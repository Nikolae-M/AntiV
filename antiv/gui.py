# interface grafica (tkinter) do AntiV

from __future__ import annotations

import ctypes
import logging
import os
import queue
import subprocess
import sys
import threading
import time
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from . import __version__, config
from .drives import list_drives
from .edr import BehaviorMonitor, MonitorOptions, response
from .edr.files import CanaryManager
from .edr.monitor import default_hot_roots, default_roots
from .engine import ScanEngine, ScanOptions
from .process_monitor import scan_processes
from .quarantine import QuarantineManager
from .reporting import setup_logging
from .signatures import RuleSet, SignatureDB

log = logging.getLogger(__name__)

LEVEL_LABEL = {"alta": "ALTA", "suspeito": "Suspeito", "info": "Info"}
STATE_LABEL = {
    "idle": "Pronto", "preparando": "Preparando...", "varrendo": "Varrendo...",
    "pausado": "Pausado", "concluido": "Concluído", "cancelado": "Cancelado",
}


def fmt_bytes(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{int(n)} B" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return ""


def fmt_time(seconds: float) -> str:
    seconds = int(max(0, seconds))
    h, rest = divmod(seconds, 3600)
    m, s = divmod(rest, 60)
    return f"{h}:{m:02d}:{s:02d}"


def shorten(text: str, limit: int) -> str:
    return text if len(text) <= limit else "..." + text[-(limit - 1):]


def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _int(var, default: int) -> int:
    try:
        return int(var.get())
    except (tk.TclError, ValueError):
        return default


class AntiVApp(tk.Tk):
    MODES = {
        "Rápida (só arquivos de risco)": "fast",
        "Completa (recomendada)": "full",
        "Profunda (tudo, sem limite de tamanho)": "deep",
    }
    DISKS = {"Automático": "auto", "SSD / NVMe": "ssd", "HDD": "hdd"}

    def __init__(self) -> None:
        super().__init__()
        self.title(f"AntiV {__version__} (antivírus leve)")
        self.geometry("1140x780")
        self.minsize(980, 660)

        self._ui_q: queue.Queue = queue.Queue()
        self.engine: ScanEngine | None = None
        self.thread: threading.Thread | None = None
        self._run_error: str | None = None
        self._iid_finding: dict = {}
        self._findex = 0
        self._rate = 0.0
        self._fps = 0.0
        self._last: tuple | None = None
        self.last_report: Path | None = None
        self.monitor: BehaviorMonitor | None = None
        self._mon_busy = False
        self._alert_idx = 0
        self._tl_seq = 0
        self._iid_alert: dict = {}

        self._setup_style()
        self._build()
        self.protocol("WM_DELETE_WINDOW", self._on_close)
        self.after(100, self._poll_ui)
        self.after(500, self._mon_tick)
        self._refresh_quarantine()
        self._refresh_base_info()

    # util
    def _call_soon(self, fn) -> None:
        # agenda fn para rodar na thread da interface (seguro entre threads)
        self._ui_q.put(fn)

    def _poll_ui(self) -> None:
        try:
            while True:
                fn = self._ui_q.get_nowait()
                try:
                    fn()
                except Exception:
                    log.exception("Erro ao atualizar a interface")
        except queue.Empty:
            pass
        self.after(100, self._poll_ui)

    def _setup_style(self) -> None:
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure("Stat.TLabel", font=("Segoe UI", 15, "bold"))
        style.configure("StatTitle.TLabel", font=("Segoe UI", 9), foreground="#666666")
        style.configure("Big.Horizontal.TProgressbar", thickness=22)
        style.configure("Accent.TButton", font=("Segoe UI", 10, "bold"))
        style.configure("Treeview", rowheight=24)

    # layout
    def _build(self) -> None:
        notebook = ttk.Notebook(self)
        notebook.pack(fill="both", expand=True)
        self.tab_scan = ttk.Frame(notebook)
        self.tab_mon = ttk.Frame(notebook)
        self.tab_proc = ttk.Frame(notebook)
        self.tab_quar = ttk.Frame(notebook)
        self.tab_base = ttk.Frame(notebook)
        notebook.add(self.tab_scan, text="  Varredura  ")
        notebook.add(self.tab_mon, text="  Monitor em tempo real  ")
        notebook.add(self.tab_proc, text="  Processos  ")
        notebook.add(self.tab_quar, text="  Quarentena  ")
        notebook.add(self.tab_base, text="  Base de dados  ")
        self._build_scan_tab()
        self._build_mon_tab()
        self._build_proc_tab()
        self._build_quar_tab()
        self._build_base_tab()

        bar = ttk.Frame(self)
        bar.pack(fill="x")
        admin = "Administrador: sim" if is_admin() else "Administrador: não"
        ttk.Label(bar, text=f"{admin}  |  AntiV {__version__}", foreground="#666666").pack(
            side="left", padx=8, pady=3)
        if os.name == "nt" and not is_admin():
            ttk.Button(bar, text="Reabrir como Administrador", command=self._relaunch_admin).pack(
                side="right", padx=8, pady=2)

    def _build_scan_tab(self) -> None:
        tab = self.tab_scan
        tab.columnconfigure(0, weight=1)
        tab.rowconfigure(3, weight=1)

        # alvo
        box = ttk.LabelFrame(tab, text=" O que verificar ", padding=8)
        box.grid(row=0, column=0, sticky="ew", padx=8, pady=(8, 4))
        box.columnconfigure(1, weight=1)
        ttk.Label(box, text="Local:").grid(row=0, column=0)
        self.var_target = tk.StringVar()
        ttk.Entry(box, textvariable=self.var_target).grid(row=0, column=1, sticky="ew", padx=6)
        ttk.Button(box, text="Pasta...", command=self._pick_folder).grid(row=0, column=2)
        ttk.Button(box, text="Arquivo...", command=self._pick_file).grid(row=0, column=3, padx=(4, 0))
        drives = list_drives()
        self._drive_map = {label: root for root, label in drives}
        if drives:
            combo = ttk.Combobox(box, values=list(self._drive_map), state="readonly", width=22)
            combo.set("Escolher disco...")
            combo.bind("<<ComboboxSelected>>", lambda e: self.var_target.set(
                self._drive_map.get(combo.get(), "")))
            combo.grid(row=0, column=4, padx=(8, 0))

        # opcoes
        opt = ttk.LabelFrame(tab, text=" Opções ", padding=8)
        opt.grid(row=1, column=0, sticky="ew", padx=8, pady=4)
        ttk.Label(opt, text="Modo:").grid(row=0, column=0, sticky="w")
        self.var_mode = tk.StringVar(value="Completa (recomendada)")
        mode_cb = ttk.Combobox(opt, textvariable=self.var_mode, values=list(self.MODES),
                               state="readonly", width=38)
        mode_cb.grid(row=0, column=1, padx=6, sticky="w")
        mode_cb.bind("<<ComboboxSelected>>", self._on_mode_change)
        ttk.Label(opt, text="Tipo de disco:").grid(row=0, column=2, padx=(12, 0))
        self.var_disk = tk.StringVar(value="Automático")
        ttk.Combobox(opt, textvariable=self.var_disk, values=list(self.DISKS),
                     state="readonly", width=14).grid(row=0, column=3, padx=6)
        ttk.Label(opt, text="Threads (0 = auto):").grid(row=0, column=4, padx=(12, 0))
        self.var_workers = tk.IntVar(value=0)
        ttk.Spinbox(opt, from_=0, to=64, textvariable=self.var_workers, width=5).grid(row=0, column=5, padx=6)
        ttk.Label(opt, text="Máx. MB por arquivo (0 = sem limite):").grid(row=1, column=0, columnspan=2, sticky="w", pady=(6, 0))
        self.var_max = tk.IntVar(value=1024)
        ttk.Spinbox(opt, from_=0, to=100000, increment=256, textvariable=self.var_max,
                    width=8).grid(row=1, column=2, sticky="w", pady=(6, 0))

        checks = ttk.Frame(opt)
        checks.grid(row=2, column=0, columnspan=6, sticky="w", pady=(6, 0))
        self.var_quar = tk.BooleanVar(value=False)
        self.var_cache = tk.BooleanVar(value=True)
        self.var_zip = tk.BooleanVar(value=True)
        self.var_low = tk.BooleanVar(value=True)
        ttk.Checkbutton(checks, text="Isolar automaticamente detecções de certeza (ALTA)",
                        variable=self.var_quar).pack(side="left", padx=(0, 14))
        ttk.Checkbutton(checks, text="Usar cache (pula arquivos que não mudaram)",
                        variable=self.var_cache).pack(side="left", padx=(0, 14))
        ttk.Checkbutton(checks, text="Olhar dentro de ZIP/Office",
                        variable=self.var_zip).pack(side="left", padx=(0, 14))
        ttk.Checkbutton(checks, text="Prioridade baixa (PC mais fluido)",
                        variable=self.var_low).pack(side="left")

        # progresso
        prog = ttk.LabelFrame(tab, text=" Progresso ", padding=8)
        prog.grid(row=2, column=0, sticky="ew", padx=8, pady=4)
        prog.columnconfigure(0, weight=1)

        buttons = ttk.Frame(prog)
        buttons.grid(row=0, column=0, sticky="w")
        self.btn_start = ttk.Button(buttons, text="Iniciar varredura", style="Accent.TButton",
                                    command=self._start)
        self.btn_start.pack(side="left")
        self.btn_pause = ttk.Button(buttons, text="Pausar", command=self._toggle_pause, state="disabled")
        self.btn_pause.pack(side="left", padx=6)
        self.btn_cancel = ttk.Button(buttons, text="Cancelar", command=self._cancel, state="disabled")
        self.btn_cancel.pack(side="left")
        self.btn_report = ttk.Button(buttons, text="Abrir relatório", command=self._open_report, state="disabled")
        self.btn_report.pack(side="left", padx=(16, 0))
        self.sv_state = tk.StringVar(value="Pronto")
        ttk.Label(buttons, textvariable=self.sv_state, font=("Segoe UI", 10, "bold")).pack(side="left", padx=16)

        self.pb = ttk.Progressbar(prog, maximum=1000, style="Big.Horizontal.TProgressbar")
        self.pb.grid(row=1, column=0, sticky="ew", pady=(8, 2))
        self.sv_pct = tk.StringVar(value="0,0%")
        ttk.Label(prog, textvariable=self.sv_pct).grid(row=2, column=0, sticky="w")

        tiles = ttk.Frame(prog)
        tiles.grid(row=3, column=0, sticky="ew", pady=(6, 0))
        self.sv: dict = {}
        layout = [
            ("done", "Arquivos verificados"), ("read", "Dados lidos"), ("speed", "Velocidade"),
            ("fps", "Arquivos/s"), ("time", "Tempo decorrido"),
            ("eta", "Tempo restante"), ("high", "Ameaças (certeza)"), ("susp", "Suspeitos"),
            ("err", "Erros de acesso"), ("skip", "Ignorados / cache"),
        ]
        for i, (key, title) in enumerate(layout):
            row, col = divmod(i, 5)
            cell = ttk.Frame(tiles)
            cell.grid(row=row, column=col, sticky="w", padx=(0, 28), pady=4)
            tiles.columnconfigure(col, weight=1)
            self.sv[key] = tk.StringVar(value="0")
            ttk.Label(cell, textvariable=self.sv[key], style="Stat.TLabel").pack(anchor="w")
            ttk.Label(cell, text=title, style="StatTitle.TLabel").pack(anchor="w")

        self.sv_profile = tk.StringVar(value="")
        ttk.Label(prog, textvariable=self.sv_profile, foreground="#666666").grid(row=4, column=0, sticky="w")
        self.sv_current = tk.StringVar(value="")
        ttk.Label(prog, textvariable=self.sv_current, foreground="#666666").grid(row=5, column=0, sticky="w")

        # resultados
        res = ttk.LabelFrame(tab, text=" Detecções (duplo clique = detalhes) ", padding=6)
        res.grid(row=3, column=0, sticky="nsew", padx=8, pady=(4, 8))
        res.columnconfigure(0, weight=1)
        res.rowconfigure(0, weight=1)
        cols = ("nivel", "nome", "metodo", "pontos", "arquivo", "acao")
        self.tree = ttk.Treeview(res, columns=cols, show="headings", selectmode="extended")
        for col, text, width in (("nivel", "Nível", 80), ("nome", "Detecção", 230),
                                 ("metodo", "Método", 170), ("pontos", "Pontos", 60),
                                 ("arquivo", "Arquivo", 480), ("acao", "Ação", 150)):
            self.tree.heading(col, text=text)
            self.tree.column(col, width=width, anchor="w", stretch=(col == "arquivo"))
        self.tree.tag_configure("alta", background="#ffd6d6")
        self.tree.tag_configure("suspeito", background="#ffe8c2")
        self.tree.tag_configure("info", foreground="#555555")
        sb = ttk.Scrollbar(res, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=sb.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        sb.grid(row=0, column=1, sticky="ns")
        self.tree.bind("<Double-1>", lambda e: self._show_details())

        actions = ttk.Frame(res)
        actions.grid(row=1, column=0, columnspan=2, sticky="w", pady=(6, 0))
        ttk.Button(actions, text="Mover selecionados para a quarentena",
                   command=self._quarantine_selected).pack(side="left")
        ttk.Button(actions, text="Abrir local do arquivo",
                   command=self._open_location).pack(side="left", padx=6)
        ttk.Button(actions, text="Copiar caminho", command=self._copy_path).pack(side="left")
        ttk.Button(actions, text="Detalhes", command=self._show_details).pack(side="left", padx=6)


    # aba monitor em tempo real (EDR leve)
    LEVEL_MON = {"critico": "CRÍTICO", "alto": "Alto", "aviso": "Aviso"}

    def _build_mon_tab(self) -> None:
        tab = self.tab_mon
        tab.columnconfigure(0, weight=1)
        tab.rowconfigure(3, weight=1)

        top = ttk.LabelFrame(tab, text=" Proteção comportamental (EDR leve) ", padding=8)
        top.grid(row=0, column=0, sticky="ew", padx=8, pady=(8, 4))
        self.btn_mon = ttk.Button(top, text="Ativar monitor", style="Accent.TButton",
                                  command=self._toggle_monitor)
        self.btn_mon.pack(side="left")
        self.sv_mon_state = tk.StringVar(value="Desativado")
        ttk.Label(top, textvariable=self.sv_mon_state, font=("Segoe UI", 11, "bold")).pack(side="left", padx=14)
        self.sv_mon_stats = tk.StringVar(value="")
        ttk.Label(top, textvariable=self.sv_mon_stats, foreground="#666666").pack(side="left", padx=8)

        opt = ttk.LabelFrame(tab, text=" O que vigiar ", padding=8)
        opt.grid(row=1, column=0, sticky="ew", padx=8, pady=4)
        opt.columnconfigure(1, weight=1)
        self.mv = {k: tk.BooleanVar(value=v) for k, v in {
            "proc": True, "net": True, "files": True, "ransom": True, "canary": False,
            "persist": True, "scan": True, "suspend": False, "quar": False, "triage": True}.items()}
        rows = [
            [("proc", "Processos e linhas de comando"), ("net", "Rede dos processos"),
             ("persist", "Persistência (Run, tarefas, serviços)"), ("triage", "Gerar dossiê em alertas altos")],
            [("files", "Arquivos em tempo real"), ("scan", "Analisar arquivos novos (downloads/temp)"),
             ("ransom", "Detectar ransomware"), ("canary", "Usar arquivos-isca (ocultos)")],
            [("suspend", "Suspender automaticamente processos CRÍTICOS (reversível)"),
             ("quar", "Isolar automaticamente arquivos novos de certeza (ALTA)")],
        ]
        for r, items in enumerate(rows):
            line = ttk.Frame(opt)
            line.grid(row=r, column=0, columnspan=2, sticky="w")
            for key, text in items:
                ttk.Checkbutton(line, text=text, variable=self.mv[key]).pack(side="left", padx=(0, 16), pady=2)
        ttk.Label(opt, text="Pastas de documentos (ransomware):").grid(row=3, column=0, sticky="w", pady=(6, 0))
        self.var_roots = tk.StringVar(value="; ".join(default_roots()))
        ttk.Entry(opt, textvariable=self.var_roots).grid(row=3, column=1, sticky="ew", padx=6, pady=(6, 0))
        ttk.Label(opt, text="Pastas de downloads/temporárias (varredura ao baixar):").grid(row=4, column=0, sticky="w")
        self.var_hot = tk.StringVar(value="; ".join(default_hot_roots()))
        ttk.Entry(opt, textvariable=self.var_hot).grid(row=4, column=1, sticky="ew", padx=6)

        acts = ttk.Frame(tab)
        acts.grid(row=2, column=0, sticky="w", padx=8)
        for text, cmd in (("Suspender", self._mon_suspend), ("Retomar", self._mon_resume),
                          ("Encerrar", self._mon_kill), ("Encerrar + isolar executável", self._mon_contain),
                          ("Abrir dossiê", self._mon_dossier), ("Ignorar programa", self._mon_allow),
                          ("Detalhes", self._mon_details), ("Testar monitor", self._mon_test),
                          ("Remover iscas", self._mon_remove_canaries)):
            ttk.Button(acts, text=text, command=cmd).pack(side="left", padx=(0, 5), pady=4)

        pane = ttk.PanedWindow(tab, orient="vertical")
        pane.grid(row=3, column=0, sticky="nsew", padx=8, pady=(0, 8))
        box = ttk.LabelFrame(pane, text=" Alertas (duplo clique = detalhes) ", padding=4)
        box.columnconfigure(0, weight=1)
        box.rowconfigure(0, weight=1)
        self.tree_alerts = ttk.Treeview(box, columns=("hora", "nivel", "pontos", "origem", "proc", "attck", "desc", "acao"),
                                        show="headings", selectmode="browse", height=8)
        for col, text, width in (("hora", "Hora", 70), ("nivel", "Nível", 70), ("pontos", "Pts", 40),
                                 ("origem", "Origem", 90), ("proc", "Processo (PID)", 150),
                                 ("attck", "MITRE ATT&CK", 130), ("desc", "O que foi visto", 380), ("acao", "Ação", 160)):
            self.tree_alerts.heading(col, text=text)
            self.tree_alerts.column(col, width=width, anchor="w", stretch=(col == "desc"))
        self.tree_alerts.tag_configure("critico", background="#ffd0d0")
        self.tree_alerts.tag_configure("alto", background="#ffe3b8")
        self.tree_alerts.tag_configure("aviso", background="#fff6c8")
        sb = ttk.Scrollbar(box, orient="vertical", command=self.tree_alerts.yview)
        self.tree_alerts.configure(yscrollcommand=sb.set)
        self.tree_alerts.grid(row=0, column=0, sticky="nsew")
        sb.grid(row=0, column=1, sticky="ns")
        self.tree_alerts.bind("<Double-1>", lambda e: self._mon_details())
        pane.add(box, weight=3)

        tl = ttk.LabelFrame(pane, text=" Linha do tempo (telemetria) ", padding=4)
        tl.columnconfigure(0, weight=1)
        tl.rowconfigure(1, weight=1)
        flt = ttk.Frame(tl)
        flt.grid(row=0, column=0, columnspan=2, sticky="ew")
        ttk.Label(flt, text="Filtrar:").pack(side="left")
        self.var_tl_filter = tk.StringVar()
        ttk.Entry(flt, textvariable=self.var_tl_filter, width=40).pack(side="left", padx=6)
        ttk.Button(flt, text="Aplicar", command=lambda: self._render_timeline(True)).pack(side="left")
        self.tree_tl = ttk.Treeview(tl, columns=("hora", "tipo", "resumo"), show="headings", height=7)
        for col, text, width in (("hora", "Hora", 70), ("tipo", "Tipo", 110), ("resumo", "Resumo", 800)):
            self.tree_tl.heading(col, text=text)
            self.tree_tl.column(col, width=width, anchor="w", stretch=(col == "resumo"))
        sb2 = ttk.Scrollbar(tl, orient="vertical", command=self.tree_tl.yview)
        self.tree_tl.configure(yscrollcommand=sb2.set)
        self.tree_tl.grid(row=1, column=0, sticky="nsew")
        sb2.grid(row=1, column=1, sticky="ns")
        pane.add(tl, weight=2)

    @staticmethod
    def _split_paths(text: str) -> list:
        return [p.strip().strip('"') for p in text.split(";") if p.strip()]

    def _toggle_monitor(self) -> None:
        if self._mon_busy:
            return
        if self.monitor is not None and self.monitor.running:
            self._mon_busy = True
            self.sv_mon_state.set("Desativando...")
            monitor = self.monitor

            def stop() -> None:
                monitor.stop()
                self._call_soon(self._monitor_stopped)

            threading.Thread(target=stop, daemon=True).start()
            return
        if self.mv["suspend"].get() and not messagebox.askyesno(
                "Resposta automática",
                "Processos de nível CRÍTICO serão SUSPENSOS automaticamente (você pode retomá-los).\n"
                "Isso pode interromper um programa legítimo que seja confundido com ameaça.\nContinuar?"):
            return
        o = MonitorOptions(
            watch_network=self.mv["net"].get(), watch_files=self.mv["files"].get(),
            watch_ransomware=self.mv["ransom"].get(), use_canaries=self.mv["canary"].get(),
            watch_persistence=self.mv["persist"].get(), realtime_scan=self.mv["scan"].get(),
            auto_suspend_critical=self.mv["suspend"].get(), auto_quarantine_files=self.mv["quar"].get(),
            collect_triage=self.mv["triage"].get(), watch_processes=self.mv["proc"].get(),
            roots=self._split_paths(self.var_roots.get()), hot_roots=self._split_paths(self.var_hot.get()))
        self._mon_busy = True
        self.sv_mon_state.set("Iniciando...")
        self.btn_mon.config(state="disabled")
        for iid in self.tree_alerts.get_children():
            self.tree_alerts.delete(iid)
        self._iid_alert.clear()
        self._alert_idx = 0
        self._tl_seq = 0

        def start() -> None:
            try:
                monitor = BehaviorMonitor(o)
                self.monitor = monitor
                monitor.start()
                self._call_soon(self._monitor_started)
            except Exception as exc:
                log.exception("Falha ao iniciar o monitor")
                self._call_soon(lambda: self._monitor_failed(str(exc)))

        threading.Thread(target=start, daemon=True).start()

    def _monitor_started(self) -> None:
        self._mon_busy = False
        self.btn_mon.config(state="normal", text="Desativar monitor")
        self.sv_mon_state.set("Monitor ATIVO")

    def _monitor_stopped(self) -> None:
        self._mon_busy = False
        self.btn_mon.config(state="normal", text="Ativar monitor")
        self.sv_mon_state.set("Desativado")

    def _monitor_failed(self, error: str) -> None:
        self._mon_busy = False
        self.btn_mon.config(state="normal", text="Ativar monitor")
        self.sv_mon_state.set("Erro")
        messagebox.showerror("Monitor", f"Não foi possível iniciar:\n{error}")

    def _mon_tick(self) -> None:
        m = self.monitor
        if m is not None and m.running:
            st = m.stats.snapshot()
            backend = {"watchdog": "tempo real (watchdog)", "polling": "varredura periódica"}.get(m.file_backend, "desligado")
            self.sv_mon_stats.set(
                f"Processos vistos: {st['processes_seen']}  |  Eventos de arquivo: {st['file_events']}  |  "
                f"Arquivos analisados: {st['files_scanned']}  |  Alertas: {st['alerts']}  |  Arquivos: {backend}")
            alerts = m.alerts
            end = len(alerts)
            for a in alerts[self._alert_idx:end]:
                proc = f"{a.process} ({a.pid})" if a.pid else (os.path.basename(a.path) if a.path else "sem processo")
                iid = self.tree_alerts.insert("", 0, tags=(a.level,), values=(
                    time.strftime("%H:%M:%S", time.localtime(a.ts)), self.LEVEL_MON.get(a.level, a.level),
                    a.score, a.source, proc, ", ".join(a.techniques), a.description, a.action))
                self._iid_alert[iid] = a
            self._alert_idx = end
            self._render_timeline(False)
        self.after(500, self._mon_tick)

    def _render_timeline(self, reset: bool) -> None:
        m = self.monitor
        if m is None:
            return
        if reset:
            for iid in self.tree_tl.get_children():
                self.tree_tl.delete(iid)
            self._tl_seq = max(0, m.telemetry.since(0)[0] - 600)
        seq, events = m.telemetry.since(self._tl_seq)
        self._tl_seq = seq
        needle = self.var_tl_filter.get().strip().lower()
        for e in events[-200:]:
            summary = self._event_summary(e)
            if needle and needle not in summary.lower() and needle not in e["type"]:
                continue
            self.tree_tl.insert("", 0, values=(time.strftime("%H:%M:%S", time.localtime(e["ts"])), e["type"], summary))
        rows = self.tree_tl.get_children()
        for iid in rows[1000:]:
            self.tree_tl.delete(iid)

    @staticmethod
    def _event_summary(e: dict) -> str:
        t = e["type"]
        if t == "process_start":
            parent = f" (pai: {e['parent']})" if e.get("parent") else ""
            return f"{e['name']} (PID {e['pid']}){parent}: {e.get('cmdline', '')[:160]}"
        if t == "detection":
            return f"{e['process']} (PID {e['pid']}) {e['rule']} +{e['points']} {e.get('technique', '')} {e.get('evidence', '')[:120]}"
        if t == "alert":
            return f"[{e['level']}] {e['title']} (pontos {e['score']}) {', '.join(e.get('techniques', []))}"
        if t == "persistence":
            return f"{e['change']}: {e['key'][:100]} = {e['value'][:100]}"
        return str({k: v for k, v in e.items() if k not in ("seq", "ts", "type")})[:200]

    def _sel_alert(self):
        sel = self.tree_alerts.selection()
        if not sel or sel[0] not in self._iid_alert:
            messagebox.showinfo("Monitor", "Selecione um alerta na lista.")
            return None, None
        return sel[0], self._iid_alert[sel[0]]

    def _mon_act(self, label: str, fn, needs_pid: bool = True) -> None:
        iid, a = self._sel_alert()
        if a is None:
            return
        if needs_pid and not a.pid:
            messagebox.showinfo("Monitor", "Este alerta não está ligado a um processo.")
            return
        ok, msg = fn(a)
        if ok:
            a.action = label
            self.tree_alerts.set(iid, "acao", label)
        (messagebox.showinfo if ok else messagebox.showwarning)("Monitor", msg)

    def _mon_suspend(self) -> None:
        self._mon_act("suspenso manualmente", lambda a: response.suspend_process(a.pid))

    def _mon_resume(self) -> None:
        self._mon_act("retomado", lambda a: response.resume_process(a.pid))

    def _mon_kill(self) -> None:
        _iid, a = self._sel_alert()
        if a is not None and messagebox.askyesno("Encerrar", f"Encerrar '{a.process}' (PID {a.pid})?"):
            self._mon_act("encerrado", lambda x: response.terminate_process(x.pid))

    def _mon_contain(self) -> None:
        _iid, a = self._sel_alert()
        if a is not None and messagebox.askyesno(
                "Isolar", f"Encerrar '{a.process}' e mover o executável para a quarentena?\n{a.exe}"):
            self._mon_act("encerrado e isolado", lambda x: response.quarantine_executable(x.pid, x.exe, x.title))
            self._refresh_quarantine()

    def _mon_dossier(self) -> None:
        iid, a = self._sel_alert()
        if a is None:
            return
        if not a.incident and a.pid:
            try:
                a.incident = str(response.save_triage(response.collect_triage(a.pid, a.title)))
            except OSError as exc:
                messagebox.showerror("Monitor", str(exc))
                return
        if a.incident and Path(a.incident).exists():
            self._open_path(Path(a.incident))
        else:
            messagebox.showinfo("Monitor", "Sem dossiê para este alerta (o processo pode já ter encerrado).")

    def _mon_allow(self) -> None:
        _iid, a = self._sel_alert()
        if a is None:
            return
        if not a.exe:
            messagebox.showinfo("Monitor", "Este alerta não tem um programa associado.")
            return
        if messagebox.askyesno("Ignorar programa", f"Parar de alertar sobre este programa?\n{a.exe}\n\n"
                                                   "Detecções de certeza (hash/assinatura) continuam ativas."):
            self.monitor.allowlist.add(a.exe)

    def _mon_details(self) -> None:
        sel = self.tree_alerts.selection()
        if not sel or sel[0] not in self._iid_alert:
            return
        a = self._iid_alert[sel[0]]
        lines = [f"{a.title}", f"Nível: {self.LEVEL_MON.get(a.level, a.level)}   Pontos: {a.score}   Origem: {a.source}"]
        if a.pid:
            lines.append(f"Processo: {a.process} (PID {a.pid})")
        if a.exe:
            lines.append(f"Executável: {a.exe}")
        if a.path:
            lines.append(f"Arquivo: {a.path}")
        lines.append("")
        for d in a.detections:
            tech = f" [{d.technique}]" if d.technique else ""
            lines.append(f"  +{d.points}  {d.name}{tech}")
            if d.evidence:
                lines.append(f"      {d.evidence[:200]}")
        if a.incident:
            lines.append(f"\nDossiê: {a.incident}")
        messagebox.showinfo("Detalhes do alerta", "\n".join(lines))

    def _mon_test(self) -> None:
        if self.monitor is None or not self.monitor.running:
            messagebox.showinfo("Monitor", "Ative o monitor primeiro.")
            return
        try:
            self.monitor.simulate_test()
            messagebox.showinfo("Monitor", "Processo de teste inofensivo iniciado. Em poucos segundos "
                                           "deve aparecer um alerta 'Teste inofensivo do monitor'.")
        except OSError as exc:
            messagebox.showerror("Monitor", str(exc))

    def _mon_remove_canaries(self) -> None:
        n = CanaryManager.remove_registered()
        messagebox.showinfo("Monitor", f"{n} arquivo(s)-isca removido(s).")

    # aba processos
    def _build_proc_tab(self) -> None:
        tab = self.tab_proc
        tab.columnconfigure(0, weight=1)
        tab.rowconfigure(1, weight=1)
        top = ttk.Frame(tab, padding=8)
        top.grid(row=0, column=0, sticky="ew")
        self.btn_proc = ttk.Button(top, text="Analisar processos agora", command=self._scan_procs)
        self.btn_proc.pack(side="left")
        ttk.Button(top, text="Encerrar processo selecionado",
                   command=self._kill_proc).pack(side="left", padx=8)
        self.sv_proc = tk.StringVar(value="Verifica CPU/RAM, pasta de origem, imitação de processos do sistema, "
                                          "Office abrindo cmd/PowerShell e o arquivo .exe de cada processo.")
        ttk.Label(top, textvariable=self.sv_proc, foreground="#666666").pack(side="left", padx=8)
        self.tree_proc = ttk.Treeview(tab, columns=("pid", "nome", "caminho", "motivos"),
                                      show="headings", selectmode="browse")
        for col, text, width in (("pid", "PID", 70), ("nome", "Processo", 160),
                                 ("caminho", "Caminho", 360), ("motivos", "Motivos", 460)):
            self.tree_proc.heading(col, text=text)
            self.tree_proc.column(col, width=width, anchor="w")
        self.tree_proc.grid(row=1, column=0, sticky="nsew", padx=8, pady=(0, 8))

    # aba quarentena
    def _build_quar_tab(self) -> None:
        tab = self.tab_quar
        tab.columnconfigure(0, weight=1)
        tab.rowconfigure(1, weight=1)
        top = ttk.Frame(tab, padding=8)
        top.grid(row=0, column=0, sticky="ew")
        ttk.Button(top, text="Atualizar", command=self._refresh_quarantine).pack(side="left")
        ttk.Button(top, text="Restaurar selecionado", command=self._restore_quarantine).pack(side="left", padx=8)
        ttk.Button(top, text="Excluir definitivamente", command=self._delete_quarantine).pack(side="left")
        self.tree_q = ttk.Treeview(tab, columns=("id", "ameaca", "origem", "data"),
                                   show="headings", selectmode="browse")
        for col, text, width in (("id", "ID", 250), ("ameaca", "Ameaça", 200),
                                 ("origem", "Caminho original", 450), ("data", "Data", 150)):
            self.tree_q.heading(col, text=text)
            self.tree_q.column(col, width=width, anchor="w")
        self.tree_q.grid(row=1, column=0, sticky="nsew", padx=8, pady=(0, 8))

    # aba base
    def _build_base_tab(self) -> None:
        tab = self.tab_base
        pad = ttk.Frame(tab, padding=16)
        pad.pack(fill="both", expand=True)
        self.sv_base = tk.StringVar(value="Carregando...")
        ttk.Label(pad, textvariable=self.sv_base, font=("Segoe UI", 11)).pack(anchor="w")
        ttk.Label(pad, foreground="#666666", wraplength=900, justify="left", text=(
            "Métodos de detecção: hash SHA-256, padrões de bytes (regras em data/rules.json), "
            "heurísticas de executáveis (packers, seções graváveis+executáveis, entropia, imports), "
            "scripts ofuscados/PowerShell, macros e links remotos em documentos Office, "
            "dupla extensão e disfarce de extensão, autorun.inf e atalhos maliciosos, "
            "conteúdo de ZIP analisado em memória.")).pack(anchor="w", pady=(8, 16))
        row = ttk.Frame(pad)
        row.pack(anchor="w")
        ttk.Button(row, text="Importar lista de hashes (.txt/.csv)...",
                   command=self._import_hashes).pack(side="left")
        ttk.Button(row, text="Criar arquivo de teste inofensivo...",
                   command=self._create_test_file).pack(side="left", padx=8)
        ttk.Button(row, text="Limpar cache de varredura", command=self._clear_cache).pack(side="left")
        ttk.Button(row, text="Abrir pasta de relatórios",
                   command=lambda: self._open_folder(config.REPORTS_DIR)).pack(side="left", padx=8)
        self.sv_base_msg = tk.StringVar(value="")
        ttk.Label(pad, textvariable=self.sv_base_msg, foreground="#1a6b2f").pack(anchor="w", pady=10)

    # escolhas
    def _pick_folder(self) -> None:
        path = filedialog.askdirectory(title="Escolha a pasta ou disco")
        if path:
            self.var_target.set(os.path.normpath(path))

    def _pick_file(self) -> None:
        path = filedialog.askopenfilename(title="Escolha o arquivo")
        if path:
            self.var_target.set(os.path.normpath(path))

    def _on_mode_change(self, _event=None) -> None:
        mode = self.MODES.get(self.var_mode.get(), "full")
        self.var_max.set(0 if mode == "deep" else 1024)

    # varredura
    def _running(self) -> bool:
        return self.thread is not None and self.thread.is_alive()

    def _start(self) -> None:
        if self._running():
            return
        target = self.var_target.get().strip().strip('"')
        if not target or not os.path.exists(target):
            messagebox.showwarning("AntiV", "Escolha um disco, pasta ou arquivo que exista.")
            return
        options = ScanOptions(
            mode=self.MODES.get(self.var_mode.get(), "full"),
            disk=self.DISKS.get(self.var_disk.get(), "auto"),
            workers=max(0, _int(self.var_workers, 0)),
            max_size_mb=max(0, _int(self.var_max, 1024)),
            auto_quarantine=self.var_quar.get(), use_cache=self.var_cache.get(),
            scan_archives=self.var_zip.get(), low_priority=self.var_low.get(),
        )
        for iid in self.tree.get_children():
            self.tree.delete(iid)
        self._iid_finding.clear()
        self._findex = 0
        self._rate, self._fps, self._last = 0.0, 0.0, None
        self._run_error = None
        self.engine = None
        self.pb["value"] = 0
        self.sv_pct.set("0,0%")
        self.sv_state.set("Carregando base de assinaturas...")
        self.btn_start.config(state="disabled")
        self.btn_pause.config(state="normal", text="Pausar")
        self.btn_cancel.config(state="normal")
        self.btn_report.config(state="disabled")
        self.thread = threading.Thread(target=self._run_engine, args=(options, target), daemon=True)
        self.thread.start()
        self.after(200, self._tick)

    def _run_engine(self, options: ScanOptions, target: str) -> None:
        try:
            engine = ScanEngine(options)
            self.engine = engine
            engine.run([target])
        except Exception as exc:
            log.exception("Falha na varredura")
            self._run_error = str(exc)

    def _toggle_pause(self) -> None:
        if not self.engine:
            return
        if self.engine.stats.state == "pausado":
            self.engine.resume()
            self.btn_pause.config(text="Pausar")
        else:
            self.engine.pause()
            self.btn_pause.config(text="Continuar")

    def _cancel(self) -> None:
        if self.engine:
            self.engine.cancel()
            self.btn_cancel.config(state="disabled")
            self.sv_state.set("Cancelando...")

    def _tick(self) -> None:
        engine = self.engine
        if engine is not None:
            self._update_stats(engine.stats.snapshot())
            self._drain_findings(engine)
        if self._running():
            self.after(200, self._tick)
        else:
            self._finish()

    def _update_stats(self, s: dict) -> None:
        total = max(1, s["bytes_discovered"])
        frac = min(1.0, s["bytes_done"] / total)
        self.pb["value"] = frac * 1000
        estimate = "" if s["discovery_done"] else "  (estimativa, ainda descobrindo arquivos)"
        self.sv_pct.set(f"{frac * 100:.1f}%".replace(".", ",") + estimate)
        self.sv_state.set(STATE_LABEL.get(s["state"], s["state"]))

        now = time.monotonic()
        if self._last is not None and s["state"] == "varrendo":
            dt = now - self._last[0]
            if dt > 0:
                inst_bytes = (s["bytes_read"] - self._last[1]) / dt
                inst_files = (s["files_done"] - self._last[2]) / dt
                self._rate = 0.6 * self._rate + 0.4 * inst_bytes
                self._fps = 0.6 * self._fps + 0.4 * inst_files
        self._last = (now, s["bytes_read"], s["files_done"])

        self.sv["done"].set(f"{s['files_done']:,} / {s['files_discovered']:,}".replace(",", "."))
        self.sv["read"].set(fmt_bytes(s["bytes_read"]))
        self.sv["speed"].set(f"{fmt_bytes(self._rate)}/s")
        self.sv["fps"].set(f"{self._fps:.0f}")
        self.sv["time"].set(fmt_time(s["elapsed"]))
        if s["discovery_done"] and s["bytes_done"] > 0 and s["elapsed"] > 1:
            avg = s["bytes_done"] / s["elapsed"]
            self.sv["eta"].set(fmt_time((s["bytes_discovered"] - s["bytes_done"]) / avg))
        else:
            self.sv["eta"].set("calculando...")
        self.sv["high"].set(str(s["high"]))
        self.sv["susp"].set(str(s["suspects"]))
        self.sv["err"].set(str(s["errors"]))
        self.sv["skip"].set(f"{s['files_skipped']} / {s['cache_hits']}")
        disk = {"ssd": "SSD", "hdd": "HDD"}.get(s["disk_type"], "tipo de disco não identificado")
        self.sv_profile.set(f"Perfil de leitura: {disk}, {s['workers']} threads")
        current = s["current"][0] if s["current"] else ""
        self.sv_current.set(f"Verificando: {shorten(current, 120)}" if current else "")

    def _drain_findings(self, engine: ScanEngine) -> None:
        findings = engine.report.findings
        end = len(findings)
        for finding in findings[self._findex:end]:
            iid = self.tree.insert("", "end", tags=(finding.level,), values=(
                LEVEL_LABEL.get(finding.level, finding.level), finding.name, finding.method,
                finding.score, finding.display_path, finding.action))
            self._iid_finding[iid] = finding
        self._findex = end

    def _finish(self) -> None:
        engine = self.engine
        if engine is not None:
            self._update_stats(engine.stats.snapshot())
            self._drain_findings(engine)
        self.btn_start.config(state="normal")
        self.btn_pause.config(state="disabled", text="Pausar")
        self.btn_cancel.config(state="disabled")
        if self._run_error:
            self.sv_state.set("Erro")
            messagebox.showerror("AntiV", f"A varredura falhou:\n{self._run_error}")
            return
        if engine is None:
            return
        report = engine.report
        try:
            saved = report.save("both")
            self.last_report = saved[-1]
            self.btn_report.config(state="normal")
        except OSError as exc:
            log.error("Nao foi possivel salvar o relatorio: %s", exc)
        threats = len(report.threats)
        text = (f"{'Varredura cancelada' if report.cancelled else 'Varredura concluída'} "
                f"em {fmt_time(report.duration_s)}.\n\n"
                f"Arquivos analisados: {report.files_scanned:,}\n"
                f"Pulados pelo cache: {report.files_cached:,}\n"
                f"Ignorados: {report.files_skipped:,}\n"
                f"Dados lidos: {fmt_bytes(report.bytes_read)}\n"
                f"Ameaças/suspeitos: {threats}\n"
                f"Erros de acesso: {report.errors}\n\n"
                "O relatório foi salvo na pasta 'reports'.").replace(",", ".")
        (messagebox.showwarning if threats else messagebox.showinfo)("AntiV", text)

    # resultados
    def _selected_findings(self) -> list:
        return [self._iid_finding[i] for i in self.tree.selection() if i in self._iid_finding]

    def _show_details(self) -> None:
        items = self._selected_findings()
        if not items:
            return
        f = items[0]
        lines = [f"Detecção: {f.name}", f"Nível: {LEVEL_LABEL.get(f.level, f.level)}",
                 f"Método: {f.method}", f"Pontos: {f.score}", f"Arquivo: {f.display_path}"]
        if f.sha256:
            lines.append(f"SHA-256: {f.sha256}")
        if f.details:
            lines.append("")
            lines.extend(f"  {d}" for d in f.details)
        if f.level == "suspeito":
            lines.append("\nAtenção: heurísticas podem errar. Confirme antes de isolar.")
        messagebox.showinfo("Detalhes da detecção", "\n".join(lines))

    def _copy_path(self) -> None:
        items = self._selected_findings()
        if items:
            self.clipboard_clear()
            self.clipboard_append(items[0].path)

    def _open_location(self) -> None:
        items = self._selected_findings()
        if not items:
            return
        path = os.path.normpath(items[0].path)
        try:
            if os.name == "nt":
                subprocess.Popen(["explorer", "/select,", path])
            else:
                messagebox.showinfo("AntiV", path)
        except OSError as exc:
            messagebox.showerror("AntiV", f"Não foi possível abrir: {exc}")

    def _quarantine_selected(self) -> None:
        selected = [(i, self._iid_finding[i]) for i in self.tree.selection() if i in self._iid_finding]
        if not selected:
            messagebox.showinfo("AntiV", "Selecione uma ou mais detecções na lista.")
            return
        paths = {f.path for _i, f in selected}
        if not messagebox.askyesno(
                "Quarentena", f"Mover {len(paths)} arquivo(s) para a quarentena?\n\n"
                              "Se a detecção for heurística, ela pode ser um falso positivo. "
                              "Você poderá restaurar na aba Quarentena."):
            return
        qm = QuarantineManager()
        done: dict = {}
        failures: list = []
        for _iid, f in selected:
            if f.path in done or f.path in {p for p, _ in failures}:
                continue
            try:
                done[f.path] = qm.quarantine(Path(f.path), f.name, f.sha256)
            except OSError as exc:
                failures.append((f.path, str(exc)))
        for iid, f in selected:
            if f.path in done:
                f.action = f"quarentena (id {done[f.path][:8]})"
                self.tree.set(iid, "acao", f.action)
        self._refresh_quarantine()
        text = f"{len(done)} arquivo(s) isolado(s)."
        if failures:
            text += "\n\nFalhas:\n" + "\n".join(f"{p}: {e}" for p, e in failures[:5])
        messagebox.showinfo("Quarentena", text)

    def _open_report(self) -> None:
        if self.last_report and self.last_report.exists():
            self._open_path(self.last_report)

    def _open_path(self, path: Path) -> None:
        try:
            if os.name == "nt":
                os.startfile(str(path))  # type: ignore[attr-defined]
            else:
                messagebox.showinfo("AntiV", str(path))
        except OSError as exc:
            messagebox.showerror("AntiV", f"Não foi possível abrir: {exc}")

    def _open_folder(self, folder: Path) -> None:
        folder.mkdir(parents=True, exist_ok=True)
        self._open_path(folder)

    # processos
    def _scan_procs(self) -> None:
        self.btn_proc.config(state="disabled")
        self.sv_proc.set("Analisando processos...")

        def work() -> None:
            try:
                alerts, error = scan_processes(), None
            except Exception as exc:
                log.exception("Falha ao analisar processos")
                alerts, error = [], str(exc)
            self._call_soon(lambda: self._show_procs(alerts, error))

        threading.Thread(target=work, daemon=True).start()

    def _show_procs(self, alerts: list, error: str | None) -> None:
        self.btn_proc.config(state="normal")
        for iid in self.tree_proc.get_children():
            self.tree_proc.delete(iid)
        if error:
            self.sv_proc.set(f"Erro: {error}")
            return
        for a in alerts:
            self.tree_proc.insert("", "end", values=(a.pid, a.name, a.exe, "; ".join(a.reasons)))
        self.sv_proc.set(f"{len(alerts)} processo(s) com alertas." if alerts
                         else "Nenhum processo suspeito encontrado.")

    def _kill_proc(self) -> None:
        sel = self.tree_proc.selection()
        if not sel:
            messagebox.showinfo("AntiV", "Selecione um processo na lista.")
            return
        pid, name = self.tree_proc.item(sel[0], "values")[:2]
        if int(pid) == os.getpid():
            messagebox.showwarning("AntiV", "Este é o próprio AntiV.")
            return
        if not messagebox.askyesno("Encerrar processo",
                                   f"Encerrar '{name}' (PID {pid})?\nDados não salvos nele serão perdidos."):
            return
        try:
            import psutil
            psutil.Process(int(pid)).terminate()
            self.tree_proc.delete(sel[0])
        except Exception as exc:
            messagebox.showerror("AntiV", f"Não foi possível encerrar: {exc}")

    # quarentena
    def _refresh_quarantine(self) -> None:
        for iid in self.tree_q.get_children():
            self.tree_q.delete(iid)
        try:
            items = QuarantineManager().list_items()
        except OSError:
            return
        for qid, e in items.items():
            self.tree_q.insert("", "end", iid=qid, values=(
                qid, e["threat"], e["original_path"], e["quarantined_at"]))

    def _restore_quarantine(self) -> None:
        sel = self.tree_q.selection()
        if not sel:
            return
        try:
            path = QuarantineManager().restore(sel[0])
            messagebox.showinfo("Quarentena", f"Restaurado em:\n{path}")
        except (KeyError, OSError) as exc:
            messagebox.showerror("Quarentena", str(exc))
        self._refresh_quarantine()

    def _delete_quarantine(self) -> None:
        sel = self.tree_q.selection()
        if not sel or not messagebox.askyesno("Quarentena", "Excluir definitivamente este item?"):
            return
        try:
            QuarantineManager().delete(sel[0])
        except (KeyError, OSError) as exc:
            messagebox.showerror("Quarentena", str(exc))
        self._refresh_quarantine()

    # base de dados
    def _refresh_base_info(self) -> None:
        def work() -> None:
            try:
                hashes, rules = len(SignatureDB()), len(RuleSet.load().rules)
                text = f"Base atual: {hashes:,} hashes SHA-256, {rules} regras de padrões".replace(",", ".")
            except Exception as exc:
                text = f"Erro ao carregar a base: {exc}"
            self._call_soon(lambda: self.sv_base.set(text))

        threading.Thread(target=work, daemon=True).start()

    def _import_hashes(self) -> None:
        path = filedialog.askopenfilename(
            title="Lista de hashes SHA-256",
            filetypes=[("Texto/CSV", "*.txt *.csv *.tsv *.list"), ("Todos", "*.*")])
        if not path:
            return
        try:
            count = SignatureDB.import_hash_file(Path(path))
            self.sv_base_msg.set(f"{count:,} hashes importados de {os.path.basename(path)}.".replace(",", "."))
            self._refresh_base_info()
        except (ValueError, OSError) as exc:
            messagebox.showerror("Importar hashes", str(exc))

    def _create_test_file(self) -> None:
        folder = filedialog.askdirectory(title="Onde criar o arquivo de teste?")
        if not folder:
            return
        path = Path(folder) / "antiv_arquivo_de_teste.txt"
        try:
            path.write_text("Arquivo de teste inofensivo do AntiV.\n" + config.TEST_MARKER + "\n",
                            encoding="utf-8")
            self.var_target.set(os.path.normpath(folder))
            self.sv_base_msg.set(f"Criado: {path}. Volte para 'Varredura' e inicie para vê-lo ser detectado.")
        except OSError as exc:
            messagebox.showerror("AntiV", str(exc))

    def _clear_cache(self) -> None:
        if self._running():
            messagebox.showinfo("AntiV", "Aguarde a varredura terminar.")
            return
        removed = 0
        for suffix in ("", "-wal", "-shm"):
            try:
                Path(str(config.CACHE_FILE) + suffix).unlink()
                removed += 1
            except OSError:
                pass
        self.sv_base_msg.set("Cache limpo." if removed else "Não havia cache.")

    # sistema
    def _relaunch_admin(self) -> None:
        try:
            result = ctypes.windll.shell32.ShellExecuteW(
                None, "runas", sys.executable, "-m antiv", str(config.BASE_DIR), 1)
            if result > 32:
                self.destroy()
            else:
                messagebox.showwarning("AntiV", "A elevação foi cancelada ou falhou.")
        except Exception as exc:
            messagebox.showerror("AntiV", str(exc))

    def _on_close(self) -> None:
        if self._running():
            if not messagebox.askyesno("AntiV", "Há uma varredura em andamento. Cancelar e sair?"):
                return
            if self.engine:
                self.engine.cancel()
        if self.monitor is not None:
            self.monitor.close()
        self.destroy()


def main() -> None:
    setup_logging(gui=True)
    try:  # texto nitido em telas de alta resolucao
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except Exception:
        pass
    app = AntiVApp()
    app.mainloop()
