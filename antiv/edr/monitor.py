# orquestrador do monitor comportamental (EDR leve)

from __future__ import annotations

import json
import logging
import os
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

from .. import config
from ..analyzer import FileAnalyzer
from ..quarantine import QuarantineManager
from ..signatures import RuleSet, SignatureDB
from . import response
from .files import FileMonitor
from .models import LEVEL_RANK, Alert, Detection, ProcInfo, level_for_score
from .persistence import PersistenceWatcher
from .process_watch import ProcessWatcher
from .rules import BehaviorRules
from .telemetry import Telemetry

log = logging.getLogger(__name__)


def default_roots() -> list:
    home = Path.home()
    return [str(home / n) for n in ("Documents", "Documentos", "Desktop", "Pictures", "Imagens")
            if (home / n).is_dir()]


def default_hot_roots() -> list:
    home = Path.home()
    out = [str(home / n) for n in ("Downloads", "Desktop") if (home / n).is_dir()]
    temp = os.environ.get("TEMP") or os.environ.get("TMP")
    if temp and os.path.isdir(temp):
        out.append(temp)
    appdata = os.environ.get("APPDATA")
    if appdata:
        startup = Path(appdata) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup"
        if startup.is_dir():
            out.append(str(startup))
    return out


@dataclass
class MonitorOptions:
    watch_processes: bool = True
    watch_network: bool = True
    watch_files: bool = True
    watch_ransomware: bool = True
    use_canaries: bool = False
    watch_persistence: bool = True
    realtime_scan: bool = True
    auto_suspend_critical: bool = False     # suspende (reversivel) processos criticos
    auto_quarantine_files: bool = False     # isola arquivos de nivel ALTA
    collect_triage: bool = True
    roots: list = field(default_factory=default_roots)
    hot_roots: list = field(default_factory=default_hot_roots)
    canary_roots: list = field(default_factory=list)
    prefer_watchdog: bool = True
    proc_interval: float = 0.3
    net_interval: float = 2.0
    io_interval: float = 2.0
    persist_interval: float = 10.0
    poll_interval: float = 2.0
    scan_settle: float = 1.5
    telemetry_path: Optional[Path] = config.TELEMETRY_FILE


class Stats:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._v = {"processes_seen": 0, "alerts": 0, "file_events": 0, "files_scanned": 0}

    def add(self, name: str, n: int = 1) -> None:
        with self._lock:
            self._v[name] = self._v.get(name, 0) + n

    def snapshot(self) -> dict:
        with self._lock:
            return dict(self._v)


class Allowlist:
    """Programas que o usuario marcou como confiaveis (por caminho)."""

    def __init__(self, path: Path = config.ALLOWLIST_FILE) -> None:
        self.path = Path(path)
        self.paths: set = set()
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            self.paths = {p.lower() for p in data.get("paths", [])}
        except (OSError, json.JSONDecodeError):
            pass

    def is_allowed(self, exe: str) -> bool:
        return bool(exe) and exe.lower() in self.paths

    def add(self, exe: str) -> None:
        if not exe:
            return
        self.paths.add(exe.lower())
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_text(json.dumps({"paths": sorted(self.paths)}, indent=2), encoding="utf-8")
        except OSError as exc:
            log.warning("Nao foi possivel salvar a lista de confiaveis: %s", exc)


class RiskTracker:
    """Soma, por processo, os pontos de cada regra (uma vez por regra)."""

    def __init__(self, cap: int = 5000) -> None:
        self._rec: dict = {}
        self._cap = cap

    def add(self, key, dets: list) -> tuple:
        rec = self._rec.setdefault(key, {})
        new = []
        for d in dets:
            old = rec.get(d.rule_id)
            if old is None or d.points > old.points:
                if old is None:
                    new.append(d)
                rec[d.rule_id] = d
        if len(self._rec) > self._cap:
            self._rec.pop(next(iter(self._rec)))
        return self.score(key), new, sorted(rec.values(), key=lambda d: -d.points)

    def score(self, key) -> int:
        return min(100, sum(d.points for d in self._rec.get(key, {}).values()))


class BehaviorMonitor:
    def __init__(self, options: Optional[MonitorOptions] = None) -> None:
        self.opts = options or MonitorOptions()
        self.rules = BehaviorRules.load()
        self.telemetry = Telemetry(self.opts.telemetry_path)
        self.stats = Stats()
        self.allowlist = Allowlist()
        self.tracker = RiskTracker()
        self.alerts: list = []
        self.test_pids: set = set()
        self.watcher = ProcessWatcher(self)
        self.files: Optional[FileMonitor] = None
        self.persistence: Optional[PersistenceWatcher] = None
        self.file_backend = ""
        self._subs: list = []
        self._lock = threading.RLock()
        self._stop = threading.Event()
        self._threads: list = []
        self._alert_level: dict = {}
        self._dedupe: set = set()
        self._analyzer: Optional[FileAnalyzer] = None
        self._exe_cache: dict = {}
        self._next_id = 1
        self.running = False

    # ciclo
    def start(self) -> None:
        if self.running:
            return
        self._stop.clear()
        self.running = True
        self.telemetry.log("monitor", state="start")
        o = self.opts
        if o.watch_processes:
            self._spawn(self._proc_loop)
        if o.watch_files:
            self.files = FileMonitor(self)
            self.file_backend = self.files.start()
        if o.watch_persistence:
            self.persistence = PersistenceWatcher(self)
            self._spawn(lambda: self.persistence.run(self._stop, o.persist_interval))

    def _spawn(self, fn) -> None:
        t = threading.Thread(target=fn, daemon=True)
        t.start()
        self._threads.append(t)

    def stop(self) -> None:
        if not self.running:
            return
        self._stop.set()
        if self.files:
            self.files.stop()
        for t in self._threads:
            t.join(timeout=3)
        self._threads.clear()
        self.running = False
        self.telemetry.log("monitor", state="stop")

    def close(self) -> None:
        self.stop()
        self.telemetry.close()

    def _proc_loop(self) -> None:
        o = self.opts
        last_net = last_io = 0.0
        while not self._stop.is_set():
            t0 = time.monotonic()
            try:
                self.watcher.tick()
                if o.watch_network and t0 - last_net >= o.net_interval:
                    last_net = t0
                    self.watcher.net_tick()
                if t0 - last_io >= o.io_interval:
                    last_io = t0
                    self.watcher.io_tick()
            except Exception:
                log.exception("Falha no ciclo do monitor de processos")
            self._stop.wait(max(0.05, o.proc_interval - (time.monotonic() - t0)))

    # utilidades
    def subscribe(self, fn: Callable) -> None:
        self._subs.append(fn)

    def analyzer(self) -> FileAnalyzer:
        if self._analyzer is None:
            self._analyzer = FileAnalyzer(SignatureDB(), RuleSet.load(), level=2,
                                          chunk=2 * config.MB, scan_archives=True)
        return self._analyzer

    def analyze_exe(self, path: str) -> list:
        # analise estatica (hash, regras, heuristicas) com cache por arquivo
        try:
            st = os.stat(path)
        except OSError:
            return []
        if not os.path.isfile(path) or st.st_size == 0 or st.st_size > 200 * config.MB:
            return []
        sig = (path, st.st_size, st.st_mtime_ns)
        if sig not in self._exe_cache:
            try:
                self._exe_cache[sig] = self.analyzer().analyze_path(path, st.st_size).findings
            except OSError:
                self._exe_cache[sig] = []
        return self._exe_cache[sig]

    def simulate_test(self, extra_args: Optional[list] = None) -> subprocess.Popen:
        # inicia um proceso INOFENSIVO cuja linha de comando dispara o alerta de teste
        args = [sys.executable, "-c", "import time; time.sleep(6)",
                config.BEHAVIOR_TEST_TOKEN] + list(extra_args or [])
        flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        proc = subprocess.Popen(args, creationflags=flags)
        self.test_pids.add(proc.pid)
        return proc

    def top_writers(self, window: float = 8.0) -> list:
        return self.watcher.top_writers(window)

    # relatos
    def report_detections(self, proc: ProcInfo, dets: list, source: str = "processo") -> None:
        if self.allowlist.is_allowed(proc.exe) and not any(d.points >= 90 for d in dets):
            return
        with self._lock:
            score, new, allds = self.tracker.add(proc.key, dets)
            if not new:
                return
            for d in new:
                self.telemetry.log("detection", pid=proc.pid, process=proc.name, rule=d.rule_id,
                                   points=d.points, technique=d.technique, evidence=d.evidence[:200])
            level = level_for_score(score)
            if LEVEL_RANK[level] <= LEVEL_RANK[self._alert_level.get(proc.key, "")]:
                return
            self._alert_level[proc.key] = level
            alert = self._alert(level, score, source, allds[0].name, allds, pid=proc.pid,
                                process=proc.name, exe=proc.exe)
        self._finalize(alert, auto_ok=True)

    def report_direct(self, source: str, title: str, dets: list, dedupe_key: str = "",
                      path: str = "", pid: int = 0, process: str = "", exe: str = "",
                      sha256: str = "", auto_ok: bool = False) -> Optional[Alert]:
        # alerta que nao pertence a um processo (arquivo, persistencia, ransomware)
        with self._lock:
            if dedupe_key:
                if dedupe_key in self._dedupe:
                    return None
                self._dedupe.add(dedupe_key)
            score = min(100, sum(d.points for d in dets))
            level = level_for_score(score)
            if not level:
                return None
            ordered = sorted(dets, key=lambda d: -d.points)
            alert = self._alert(level, score, source, title, ordered, pid=pid, process=process,
                                exe=exe, path=path, sha256=sha256)
        self._finalize(alert, auto_ok=auto_ok)
        return alert

    def report_file_findings(self, path: str, findings: list, sha256: str = "") -> None:
        dets = []
        for f in findings:
            if f.level == "alta":
                dets.append(Detection("FILE-KNOWN", f"{f.name}", 95, "T1204.002",
                                      f.method, f.display_path))
            elif f.level == "suspeito":
                dets.append(Detection("FILE-HEUR", f"{f.name}", min(f.score, 85), "T1204.002",
                                      "; ".join(f.details[:2]), f.display_path))
        if not dets:
            return
        alert = self.report_direct("arquivo", f"Arquivo novo suspeito: {os.path.basename(path)}",
                                   dets, dedupe_key=f"file:{path}:{sha256}", path=path, sha256=sha256)
        if alert and self.opts.auto_quarantine_files and any(f.level == "alta" for f in findings):
            try:
                qid = QuarantineManager().quarantine(Path(path), dets[0].name, sha256)
                alert.action = f"arquivo isolado (id {qid[:8]})"
            except OSError as exc:
                alert.action = f"falha ao isolar: {exc}"

    def report_ransomware(self, dets: list, canary: bool = False) -> None:
        # atribui (se possivel) o 'culpado' pelo I/O e reporta o alerta
        writers = self.top_writers()
        pid, process, exe, share = 0, "", "", 0.0
        total = sum(b for _p, b in writers)
        for wpid, written in writers:
            info = self.watcher.pid_info.get(wpid)
            if info and not self.watcher.is_own(info) and not response.is_protected(wpid, info.name, info.exe)[0]:
                pid, process, exe = wpid, info.name, info.exe
                share = written / total if total else 0.0
                break
        confident = bool(pid) and (canary or share >= 0.7)
        if pid:
            for d in dets:
                d.evidence += f" | provavel responsavel: {process} (PID {pid}, {share:.0%} das gravacoes)"
        self.report_direct("ransomware", dets[0].name, dets, dedupe_key=f"ransom:{dets[0].rule_id}:{int(time.time() // 60)}",
                           pid=pid, process=process, exe=exe, auto_ok=confident)

    # interno
    def _alert(self, level, score, source, title, dets, **kw) -> Alert:
        alert = Alert(id=self._next_id, ts=time.time(), level=level, score=score,
                      source=source, title=title, detections=list(dets), **kw)
        self._next_id += 1
        return alert

    def _finalize(self, alert: Alert, auto_ok: bool) -> None:
        o = self.opts
        notes = []
        if alert.pid and o.collect_triage and LEVEL_RANK[alert.level] >= LEVEL_RANK["alto"]:
            try:
                data = response.collect_triage(alert.pid, reason=alert.title)
                data["alert_detections"] = [d.__dict__ for d in alert.detections]
                alert.incident = str(response.save_triage(data))
            except Exception:
                log.exception("Falha ao coletar o dossie")
        if alert.level == "critico" and alert.pid and o.auto_suspend_critical and auto_ok:
            ok, msg = response.suspend_process(alert.pid)
            notes.append(("suspenso automaticamente" if ok else f"suspensao negada: {msg}"))
        if notes:
            alert.action = "; ".join(notes)
        with self._lock:
            self.alerts.append(alert)
        self.stats.add("alerts")
        self.telemetry.log("alert", id=alert.id, level=alert.level, score=alert.score,
                           source=alert.source, title=alert.title, pid=alert.pid,
                           process=alert.process, techniques=alert.techniques, action=alert.action)
        for fn in list(self._subs):
            try:
                fn(alert)
            except Exception:
                log.exception("Erro em assinante de alertas")
