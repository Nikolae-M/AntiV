# interface de linha de comando do AntiV (sem argumentos abre a interface grafica)

from __future__ import annotations

import argparse
import sys
import threading
import time
from pathlib import Path

from . import __version__
from .engine import ScanEngine, ScanOptions
from .process_monitor import scan_processes
from .quarantine import QuarantineManager
from .reporting import setup_logging


def _fmt_bytes(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.1f} {unit}" if unit != "B" else f"{int(n)} B"
        n /= 1024
    return ""


def cmd_scan(args: argparse.Namespace) -> int:
    target = Path(args.path)
    if not target.exists():
        print(f"Caminho nao encontrado: {target}", file=sys.stderr)
        return 2
    max_size = args.max_size if args.max_size is not None else (0 if args.mode == "deep" else 1024)
    options = ScanOptions(
        mode=args.mode, disk=args.disk, workers=args.workers, max_size_mb=max_size,
        auto_quarantine=args.quarantine, use_cache=not args.no_cache,
        scan_archives=not args.no_archives,
    )
    engine = ScanEngine(options)
    thread = threading.Thread(target=engine.run, args=([str(target)],), daemon=True)
    thread.start()
    last_len = 0
    try:
        while thread.is_alive():
            thread.join(0.5)
            s = engine.stats.snapshot()
            total = max(1, s["bytes_discovered"])
            pct = min(100.0, 100.0 * s["bytes_done"] / total)
            speed = s["bytes_read"] / s["elapsed"] if s["elapsed"] else 0
            line = (f"\r[{s['state']}] {pct:5.1f}% | {s['files_done']}/{s['files_discovered']} arquivos | "
                    f"{_fmt_bytes(speed)}/s | ameacas: {s['high'] + s['suspects']} | "
                    f"{s['workers']} threads ({s['disk_type']})")
            print(line.ljust(last_len), end="", file=sys.stderr, flush=True)
            last_len = len(line)
    except KeyboardInterrupt:
        print("\nCancelando... (o relatorio parcial sera salvo)", file=sys.stderr)
        engine.cancel()
        thread.join()
    print(file=sys.stderr)

    report = engine.report
    for finding in report.findings:
        print(f"[{finding.level.upper()}] {finding.name} ({finding.method}) -> {finding.display_path}")
    for path in report.save(args.report):
        print(f"Relatorio salvo em: {path}")
    print(f"Analisados: {report.files_scanned} | Cache: {report.files_cached} | "
          f"Ignorados: {report.files_skipped} | Ameacas/suspeitos: {len(report.threats)} | "
          f"Erros: {report.errors} | {report.duration_s:.1f}s")
    return 1 if report.threats else 0


def cmd_processes(args: argparse.Namespace) -> int:
    alerts = scan_processes(analyze_files=not args.no_files)
    if not alerts:
        print("Nenhum processo suspeito encontrado.")
        return 0
    for a in alerts:
        print(f"[!] PID {a.pid} {a.name} ({a.exe or 'caminho indisponivel'})")
        for reason in a.reasons:
            print(f"      - {reason}")
    return 1


def cmd_quarantine(args: argparse.Namespace) -> int:
    qm = QuarantineManager()
    if args.action == "list":
        items = qm.list_items()
        if not items:
            print("Quarentena vazia.")
        for qid, e in items.items():
            print(f"{qid} | {e['threat']} | {e['original_path']} | {e['quarantined_at']}")
        return 0
    if not args.id:
        print("Informe o ID com --id", file=sys.stderr)
        return 2
    try:
        if args.action == "restore":
            print(f"Restaurado em: {qm.restore(args.id)}")
        else:
            qm.delete(args.id)
            print("Removido definitivamente.")
    except (KeyError, OSError) as exc:
        print(f"Erro: {exc}", file=sys.stderr)
        return 2
    return 0


def cmd_monitor(args: argparse.Namespace) -> int:
    from .edr import BehaviorMonitor, MonitorOptions

    opts = MonitorOptions(
        watch_network=not args.no_network, watch_files=not args.no_files,
        watch_persistence=not args.no_persistence, use_canaries=args.canaries,
        auto_suspend_critical=args.auto_suspend, auto_quarantine_files=args.auto_quarantine,
        prefer_watchdog=not args.no_watchdog)
    if args.folder:
        opts.roots = opts.hot_roots = list(args.folder)
    monitor = BehaviorMonitor(opts)
    labels = {"critico": "CRITICO", "alto": "ALTO", "aviso": "AVISO"}

    def show(alert) -> None:
        proc = f"{alert.process} (PID {alert.pid})" if alert.pid else (alert.path or "-")
        print(f"[{labels.get(alert.level, alert.level)}] {alert.title} | {proc} | pontos {alert.score} | "
              f"{', '.join(alert.techniques) or '-'} | acao: {alert.action}", flush=True)
        for d in alert.detections[:5]:
            print(f"      +{d.points} {d.name}  {d.evidence[:100]}", flush=True)
        if alert.incident:
            print(f"      dossie: {alert.incident}", flush=True)

    monitor.subscribe(show)
    monitor.start()
    print(f"Monitor ativo (arquivos: {monitor.file_backend or 'desligado'}). Ctrl+C para parar.", flush=True)
    test_proc = None
    deadline = time.time() + args.duration if args.duration else None
    started = time.time()
    try:
        while deadline is None or time.time() < deadline:
            if args.test and test_proc is None and time.time() - started > 2:
                test_proc = monitor.simulate_test()
                print("Processo de teste inofensivo iniciado...", flush=True)
            time.sleep(0.5)
    except KeyboardInterrupt:
        print()
    finally:
        monitor.close()
        if test_proc is not None:
            test_proc.kill()
    st = monitor.stats.snapshot()
    print(f"Encerrado. Processos vistos: {st['processes_seen']} | Arquivos analisados: {st['files_scanned']} | "
          f"Alertas: {st['alerts']} | Telemetria: logs/telemetry.jsonl")
    return 1 if any(a.level in ("alto", "critico") for a in monitor.alerts) else 0


def cmd_gui(_args: argparse.Namespace) -> int:
    from .gui import main as gui_main
    gui_main()
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="antiv", description="AntiV - antivirus leve")
    p.add_argument("--version", action="version", version=f"AntiV {__version__}")
    p.add_argument("-v", "--verbose", action="store_true")
    sub = p.add_subparsers(dest="command")

    s = sub.add_parser("scan", help="varre um arquivo, pasta ou disco")
    s.add_argument("path")
    s.add_argument("--mode", choices=["fast", "full", "deep"], default="full",
                   help="fast=so extensoes de risco | full=tudo (padrao) | deep=tudo, sem limite de tamanho")
    s.add_argument("--disk", choices=["auto", "ssd", "hdd"], default="auto",
                   help="perfil de leitura (auto detecta)")
    s.add_argument("--workers", type=int, default=0, help="numero de threads (0 = automatico)")
    s.add_argument("--max-size", type=int, default=None, help="ignora arquivos maiores que X MB (0 = sem limite)")
    s.add_argument("--quarantine", action="store_true", help="isola deteccoes de certeza automaticamente")
    s.add_argument("--no-cache", action="store_true", help="reanalisa tudo, ignorando o cache")
    s.add_argument("--no-archives", action="store_true", help="nao olha dentro de ZIP/Office")
    s.add_argument("--report", choices=["txt", "json", "both"], default="both")
    s.set_defaults(func=cmd_scan)

    pr = sub.add_parser("processes", help="analisa processos em execucao")
    pr.add_argument("--no-files", action="store_true", help="nao analisa os executaveis em disco")
    pr.set_defaults(func=cmd_processes)

    q = sub.add_parser("quarantine", help="gerencia a quarentena")
    q.add_argument("action", choices=["list", "restore", "delete"])
    q.add_argument("--id")
    q.set_defaults(func=cmd_quarantine)

    m = sub.add_parser("monitor", help="monitor comportamental em tempo real (EDR leve)")
    m.add_argument("--folder", action="append", help="pasta a vigiar (pode repetir; padrao: Documentos, Downloads...)")
    m.add_argument("--duration", type=int, default=0, help="para sozinho apos N segundos")
    m.add_argument("--no-network", action="store_true")
    m.add_argument("--no-files", action="store_true", help="nao vigia arquivos/ransomware")
    m.add_argument("--no-persistence", action="store_true")
    m.add_argument("--no-watchdog", action="store_true", help="usa varredura periodica em vez do watchdog")
    m.add_argument("--canaries", action="store_true", help="cria arquivos-isca ocultos para detectar ransomware")
    m.add_argument("--auto-suspend", action="store_true", help="suspende processos de nivel critico")
    m.add_argument("--auto-quarantine", action="store_true", help="isola arquivos novos de certeza (ALTA)")
    m.add_argument("--test", action="store_true", help="dispara um processo de teste inofensivo")
    m.set_defaults(func=cmd_monitor)

    g = sub.add_parser("gui", help="abre a interface grafica")
    g.set_defaults(func=cmd_gui)
    return p


def main() -> int:
    args = build_parser().parse_args()
    if args.command is None:          # sem argumentos: interface grafica
        return cmd_gui(args)
    setup_logging(args.verbose)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        print("\nInterrompido pelo usuario.")
        return 130
