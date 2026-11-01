# Motor de varredura paralelo
#
# arquitetura:
#   * 1 thread "caminhante" percorre as pastas (os.scandir) e alimenta uma fila
#     limitada; ja vai contando arqivos/bytes para a barra de progresso
#   * N threads "trabalhadoras" leem e analisam os arquivos. O hashlib libera o
#     GIL em blocos grandes, entao a leitura/hash roda em paralelo de verdade
#   * Perfil de I/O: SSD usa muitas threads; HDD usa poucas threads e blocos
#     grandes (leitura sequencial, sem "chacoalhar" a cabeca do disco)
#   * Cache SQLite pula arquivos limpos que nao mudaram desde a ultima varredura

from __future__ import annotations

import logging
import os
import queue
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from . import config
from .analyzer import FileAnalyzer
from .cache import ScanCache
from .drives import detect_disk_type
from .filetypes import RISKY_EXTS, file_ext
from .quarantine import QuarantineManager
from .reporting import LEVEL_ORDER, ScanReport
from .signatures import RuleSet, SignatureDB, content_fingerprint

log = logging.getLogger(__name__)

_REPARSE_POINT = 0x400
# arquivos "somente na nuvem" (OneDrive etc.): ler dispararia o download
_CLOUD_ATTRS = 0x1000 | 0x40000 | 0x400000


@dataclass
class ScanOptions:
    mode: str = "full"            # fast | full | deep
    disk: str = "auto"            # auto | ssd | hdd
    workers: int = 0              # 0 = automatico
    max_size_mb: int = 1024       # 0 = sem limite
    auto_quarantine: bool = False  # isola automaticamente detecoes "alta"
    use_cache: bool = True
    scan_archives: bool = True
    low_priority: bool = True

    @property
    def level(self) -> int:
        return config.MODE_LEVELS.get(self.mode, 2)


class _Task:
    __slots__ = ("path", "size", "mtime_ns", "cloud")

    def __init__(self, path: str, size: int, mtime_ns: int, cloud: bool) -> None:
        self.path, self.size, self.mtime_ns, self.cloud = path, size, mtime_ns, cloud


def choose_profile(disk_type: str, workers_override: int = 0) -> tuple:
    # devolve (threads, tamanho do bloco de leitura)
    cpu = os.cpu_count() or 4
    if disk_type == "ssd":
        workers, chunk = min(16, max(4, cpu)), 1 * config.MB
    elif disk_type == "hdd":
        workers, chunk = 2, 4 * config.MB
    else:
        workers, chunk = 4, 2 * config.MB
    if workers_override > 0:
        workers = workers_override
    return workers, chunk


class ScanStats:
    """Contadores compartilhados (thread-safe) lidos pela interface."""

    _COUNTERS = (
        "files_discovered", "bytes_discovered", "files_done", "bytes_done",
        "files_scanned", "bytes_read", "files_skipped", "cache_hits", "errors",
        "high", "suspects", "infos",
    )

    def __init__(self) -> None:
        self._lock = threading.Lock()
        for name in self._COUNTERS:
            setattr(self, name, 0)
        self.state = "idle"
        self.discovery_done = False
        self.disk_type = "?"
        self.workers = 0
        self.started = 0.0
        self.finished = 0.0
        self.paused_total = 0.0
        self._pause_start = 0.0
        self.current: dict = {}

    def add(self, **kw) -> None:
        with self._lock:
            for key, value in kw.items():
                setattr(self, key, getattr(self, key) + value)

    def set(self, **kw) -> None:
        with self._lock:
            for key, value in kw.items():
                setattr(self, key, value)

    def set_state(self, state: str) -> None:
        with self._lock:
            now = time.monotonic()
            if self.state == "pausado" and state != "pausado":
                self.paused_total += now - self._pause_start
            elif state == "pausado" and self.state != "pausado":
                self._pause_start = now
            self.state = state

    def snapshot(self) -> dict:
        with self._lock:
            now = time.monotonic()
            end = self.finished or now
            paused = self.paused_total + (now - self._pause_start if self.state == "pausado" else 0)
            elapsed = max(0.0, end - self.started - paused) if self.started else 0.0
            snap = {name: getattr(self, name) for name in self._COUNTERS}
            snap.update(
                state=self.state, discovery_done=self.discovery_done,
                disk_type=self.disk_type, workers=self.workers, elapsed=elapsed,
                current=list(self.current.values()),
            )
            return snap


class ScanEngine:
    def __init__(self, options: Optional[ScanOptions] = None,
                 db: Optional[SignatureDB] = None, rules: Optional[RuleSet] = None) -> None:
        self.options = options or ScanOptions()
        self.db = db or SignatureDB()
        self.rules = rules or RuleSet.load()
        self.stats = ScanStats()
        self.report = ScanReport()
        self._cancel = threading.Event()
        self._running = threading.Event()
        self._running.set()
        self._queue: queue.Queue = queue.Queue(maxsize=4096)
        self._qm: Optional[QuarantineManager] = None
        self._q_lock = threading.Lock()
        self._skip_files: set = set()
        self._quarantine_norm = ""

    # controle
    def pause(self) -> None:
        self._running.clear()
        self.stats.set_state("pausado")

    def resume(self) -> None:
        self.stats.set_state("varrendo")
        self._running.set()

    def cancel(self) -> None:
        self._cancel.set()
        self._running.set()      # libera threads pausadas

    # execucao
    def run(self, targets: list) -> ScanReport:
        stats, opts = self.stats, self.options
        stats.set(started=time.monotonic())
        stats.set_state("preparando")
        previous_nice = self._lower_priority() if opts.low_priority else None
        cache = None
        try:
            paths = [os.path.abspath(str(t)) for t in targets]
            disk = opts.disk if opts.disk != "auto" else detect_disk_type(paths[0])
            workers, chunk = choose_profile(disk, opts.workers)
            stats.set(disk_type=disk, workers=workers)
            self.report.targets = paths
            self.report.mode, self.report.disk_type, self.report.workers = opts.mode, disk, workers

            self._quarantine_norm = os.path.normcase(os.path.abspath(str(config.QUARANTINE_DIR)))
            cache_path = str(config.CACHE_FILE)
            self._skip_files = {os.path.normcase(os.path.abspath(p))
                                for p in (cache_path, cache_path + "-wal", cache_path + "-shm")}
            if opts.use_cache:
                cache = ScanCache(config.CACHE_FILE, content_fingerprint())
            analyzer = FileAnalyzer(self.db, self.rules, opts.level, chunk, opts.scan_archives)

            stats.set_state("varrendo")
            walker = threading.Thread(target=self._walk_all, args=(paths, workers), daemon=True)
            pool = [threading.Thread(target=self._worker, args=(i, analyzer, cache), daemon=True)
                    for i in range(workers)]
            walker.start()
            for t in pool:
                t.start()
            walker.join()
            for t in pool:
                t.join()
        finally:
            if cache is not None:
                cache.close()
            if previous_nice is not None:
                self._restore_priority(previous_nice)
            stats.set(finished=time.monotonic())
            snap = stats.snapshot()
            r = self.report
            r.cancelled = self._cancel.is_set()
            r.finished_at = time.strftime("%Y-%m-%dT%H:%M:%S")
            r.duration_s = snap["elapsed"]
            r.files_discovered = snap["files_discovered"]
            r.files_scanned = snap["files_scanned"]
            r.files_cached = snap["cache_hits"]
            r.files_skipped = snap["files_skipped"]
            r.bytes_read = snap["bytes_read"]
            r.errors = snap["errors"]
            stats.set_state("cancelado" if r.cancelled else "concluido")
        return self.report

    # prioridade do processo
    @staticmethod
    def _lower_priority():
        try:
            import psutil
            proc = psutil.Process()
            old = proc.nice()
            proc.nice(psutil.BELOW_NORMAL_PRIORITY_CLASS if os.name == "nt" else 10)
            return old
        except Exception:
            return None

    @staticmethod
    def _restore_priority(old) -> None:
        try:
            import psutil
            psutil.Process().nice(old)
        except Exception:
            pass

    # descoberta de arquivos
    def _put(self, item) -> bool:
        while True:
            try:
                self._queue.put(item, timeout=0.25)
                return True
            except queue.Full:
                if self._cancel.is_set() and item is not None:
                    return False

    def _problem(self, path: str, exc: BaseException) -> None:
        self.stats.add(errors=1)
        if isinstance(exc, PermissionError):
            msg = "permissao negada (pasta protegida ou arquivo em uso; tente como Administrador)"
        else:
            msg = str(exc)
        self.report.add_problem(path, msg)

    def _walk_all(self, paths: list, workers: int) -> None:
        try:
            for root in paths:
                if self._cancel.is_set():
                    break
                self._walk(root)
        finally:
            self.stats.set(discovery_done=True)
            for _ in range(workers):
                self._put(None)

    def _walk(self, root: str) -> None:
        if os.path.isfile(root):
            try:
                st = os.stat(root)
                self.stats.add(files_discovered=1, bytes_discovered=st.st_size)
                self._put(_Task(root, st.st_size, st.st_mtime_ns, False))
            except OSError as exc:
                self._problem(root, exc)
            return
        stack = [root]
        while stack:
            directory = stack.pop()
            subdirs: list = []
            try:
                with os.scandir(directory) as entries:
                    for entry in entries:
                        if self._cancel.is_set():
                            return
                        try:
                            if entry.is_dir(follow_symlinks=False):
                                if self._skip_dir(entry):
                                    continue
                                subdirs.append(entry.path)
                            elif entry.is_file(follow_symlinks=False):
                                if os.path.normcase(entry.path) in self._skip_files:
                                    continue
                                st = entry.stat(follow_symlinks=False)
                                cloud = bool(getattr(st, "st_file_attributes", 0) & _CLOUD_ATTRS)
                                self.stats.add(files_discovered=1, bytes_discovered=st.st_size)
                                if not self._put(_Task(entry.path, st.st_size, st.st_mtime_ns, cloud)):
                                    return
                        except OSError as exc:
                            self._problem(entry.path, exc)
            except OSError as exc:
                self._problem(directory, exc)
            stack.extend(reversed(subdirs))

    def _skip_dir(self, entry: os.DirEntry) -> bool:
        if entry.name.lower() in config.EXCLUDED_DIRS:
            return True
        if os.path.normcase(entry.path) == self._quarantine_norm:
            return True
        # Junctions/pontos de reanalise: evitam laco infinito e duplicatas
        attrs = getattr(entry.stat(follow_symlinks=False), "st_file_attributes", 0)
        return bool(attrs & _REPARSE_POINT)

    # analise
    def _worker(self, wid: int, analyzer: FileAnalyzer, cache: Optional[ScanCache]) -> None:
        stats = self.stats
        while True:
            task = self._queue.get()
            if task is None:
                return
            if self._cancel.is_set():
                continue                       # esvazia a fila ao cancelar
            self._running.wait()
            if self._cancel.is_set():
                continue
            stats.current[wid] = task.path
            try:
                outcome, nread, error = self._handle(task, analyzer, cache)
            except Exception as exc:           # nunca derruba a thread
                log.exception("Erro inesperado em %s", task.path)
                outcome, nread, error = "error", 0, f"erro inesperado: {exc}"
            stats.current.pop(wid, None)
            if outcome == "scanned":
                stats.add(files_scanned=1, bytes_read=nread)
            elif outcome == "cached":
                stats.add(cache_hits=1)
            elif outcome == "skipped":
                stats.add(files_skipped=1)
            else:
                stats.add(errors=1)
                self.report.add_problem(task.path, error or "erro desconhecido")
            stats.add(files_done=1, bytes_done=task.size)

    def _handle(self, task: _Task, analyzer: FileAnalyzer, cache: Optional[ScanCache]):
        opts, level = self.options, self.options.level
        if task.cloud:
            return "skipped", 0, None
        if level == 1 and file_ext(task.path) not in RISKY_EXTS:
            return "skipped", 0, None
        if opts.max_size_mb and task.size > opts.max_size_mb * config.MB:
            return "skipped", 0, None
        if task.size == 0:
            return "scanned", 0, None
        if cache is not None and cache.is_clean(task.path, task.size, task.mtime_ns, level):
            return "cached", 0, None
        try:
            # print("lendo", task.path)
            result = analyzer.analyze_path(task.path, task.size)
        except PermissionError:
            return "error", 0, "permissao negada (arquivo em uso ou protegido; tente como Administrador)"
        except FileNotFoundError:
            return "error", 0, "arquivo removido durante a varredura"
        except OSError as exc:
            return "error", 0, f"erro de E/S: {exc}"

        findings = result.findings
        if not findings:
            if cache is not None:
                cache.mark_clean(task.path, task.size, task.mtime_ns, level)
            return "scanned", result.bytes_read, None

        top = min(findings, key=lambda f: LEVEL_ORDER.get(f.level, 9)).level
        self.stats.add(high=top == "alta", suspects=top == "suspeito", infos=top == "info")
        high = [f for f in findings if f.level == "alta"]
        if opts.auto_quarantine and high:
            action = self._quarantine(task.path, high[0].name, result.sha256)
            for f in high:
                f.action = action
        self.report.add_findings(findings)
        return "scanned", result.bytes_read, None

    def _quarantine(self, path: str, threat: str, sha256: str) -> str:
        with self._q_lock:
            try:
                if self._qm is None:
                    self._qm = QuarantineManager()
                qid = self._qm.quarantine(Path(path), threat, sha256)
                return f"quarentena (id {qid[:8]})"
            except OSError as exc:
                log.error("Quarentena falhou para %s: %s", path, exc)
                return f"falha ao isolar: {exc}"
