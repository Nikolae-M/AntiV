# monitoramento de arquivso: varredura ao baixar, ransomware e arquivos-isca

from __future__ import annotations

import ctypes
import json
import logging
import os
import queue
import random
import re
import threading
import time
import zipfile
from collections import Counter, deque
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional

from .. import config
from ..heuristics import compress_ratio
from .models import Detection

log = logging.getLogger(__name__)

IGNORE_EXTS = {".crdownload", ".part", ".partial", ".download", ".tmp", ".temp"}
COMPRESSED_EXTS = {".zip", ".7z", ".rar", ".gz", ".xz", ".bz2", ".jpg", ".jpeg", ".png",
                   ".gif", ".webp", ".mp3", ".mp4", ".mkv", ".avi", ".mov", ".pdf", ".heic",
                   ".docx", ".xlsx", ".pptx", ".odt", ".ods", ".jar", ".apk", ".msi", ".cab"}
COMMON_EXTS = COMPRESSED_EXTS | {
    ".txt", ".doc", ".xls", ".ppt", ".exe", ".dll", ".log", ".json", ".xml", ".html", ".htm",
    ".js", ".py", ".css", ".csv", ".ini", ".bak", ".cache", ".lnk", ".url", ".md", ".c", ".h",
} | IGNORE_EXTS
NOTE_RE = re.compile(r"(readme|read_me|decrypt|restore|recover|how[_ -]?to|instruction|ransom|"
                     r"!!!|_help_|your[_ -]?files)", re.IGNORECASE)
NOTE_EXTS = {".txt", ".html", ".hta", ".htm", ".rtf", ".url"}


@dataclass
class FsEvent:
    kind: str          # created | modified | deleted | moved
    path: str
    dest: str = ""
    ts: float = 0.0

    def __post_init__(self) -> None:
        if not self.ts:
            self.ts = time.time()

    @property
    def target(self) -> str:
        return self.dest if self.kind == "moved" and self.dest else self.path


def _norm(path: str) -> str:
    return os.path.normcase(os.path.abspath(path))


def _under(path: str, roots: list) -> bool:
    p = _norm(path)
    return any(p.startswith(r) for r in roots)


def _dir_roots(paths) -> list:
    return [_norm(p) + os.sep for p in paths if os.path.isdir(p)]


# backends (como observar o sistema de arquivos)
class PollingBackend:
    """Compara 'fotos' das pastas a cada N segundos. Funciona em qualquer lugar."""

    name = "polling"

    def __init__(self, roots, callback: Callable, interval: float = 2.0,
                 excluded: Callable = lambda p: False, max_entries: int = 300_000) -> None:
        self.roots, self.callback, self.interval = list(roots), callback, interval
        self.excluded, self.max_entries = excluded, max_entries
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._prev: dict = {}

    def _snapshot(self) -> dict:
        snap: dict = {}
        stack = list(self.roots)
        while stack:
            directory = stack.pop()
            try:
                with os.scandir(directory) as entries:
                    for e in entries:
                        try:
                            if e.is_dir(follow_symlinks=False):
                                if not self.excluded(e.path):
                                    stack.append(e.path)
                            elif e.is_file(follow_symlinks=False):
                                st = e.stat(follow_symlinks=False)
                                snap[e.path] = (st.st_size, st.st_mtime_ns)
                        except OSError:
                            continue
                        if len(snap) >= self.max_entries:
                            return snap
            except OSError:
                continue
        return snap

    def start(self) -> None:
        self._prev = self._snapshot()
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def _loop(self) -> None:
        while not self._stop.wait(self.interval):
            try:
                self._diff(self._snapshot())
            except Exception:
                log.exception("Falha no monitor de arquivos (polling)")

    def _diff(self, cur: dict) -> None:
        prev = self._prev
        created = [p for p in cur if p not in prev]
        deleted = {p: prev[p] for p in prev if p not in cur}
        by_sig = {v: p for p, v in deleted.items()}
        for path in created:                           # mesmo tamanho+data = renomeado
            src = by_sig.pop(cur[path], None)
            if src is not None:
                deleted.pop(src, None)
                self.callback(FsEvent("moved", src, path))
            else:
                self.callback(FsEvent("created", path))
        for path, sig in cur.items():
            if path in prev and prev[path] != sig:
                self.callback(FsEvent("modified", path))
        for path in deleted:
            self.callback(FsEvent("deleted", path))
        self._prev = cur

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=3)


class WatchdogBackend:
    """Eventos em tempo real do sistema operacional (pacote opcional 'watchdog')."""

    name = "watchdog"

    def __init__(self, roots, callback: Callable) -> None:
        from watchdog.events import FileSystemEventHandler
        from watchdog.observers import Observer

        class Handler(FileSystemEventHandler):
            def on_created(self, e):
                if not e.is_directory:
                    callback(FsEvent("created", e.src_path))

            def on_modified(self, e):
                if not e.is_directory:
                    callback(FsEvent("modified", e.src_path))

            def on_deleted(self, e):
                if not e.is_directory:
                    callback(FsEvent("deleted", e.src_path))

            def on_moved(self, e):
                if not e.is_directory:
                    callback(FsEvent("moved", e.src_path, e.dest_path))

        self._observer = Observer()
        handler = Handler()
        for root in roots:
            self._observer.schedule(handler, root, recursive=True)

    def start(self) -> None:
        self._observer.start()

    def stop(self) -> None:
        self._observer.stop()
        self._observer.join(timeout=3)


def make_backend(roots, callback, prefer_watchdog=True, interval=2.0, excluded=lambda p: False):
    if prefer_watchdog:
        try:
            return WatchdogBackend(roots, callback)
        except ImportError:
            log.info("Pacote 'watchdog' ausente: usando varredura periodica (polling).")
    return PollingBackend(roots, callback, interval, excluded)


# Ransomware
def sample_entropy(path: str) -> Optional[float]:
    # razao de compressao dos primeiros 64 KB (perto de 1.0 = cifrado/aleatorio)
    try:
        with open(path, "rb") as fh:
            data = fh.read(65536)
    except OSError:
        return None
    return compress_ratio(data) or None


class RansomwareDetector:
    """Procura o 'jeito' do ransomware: muitos arquivos reescritos/renomeados rapido."""

    def __init__(self, entropy_fn: Callable = sample_entropy, window: float = 10.0,
                 entropy_files: int = 20, ext_files: int = 15, note_dirs: int = 3,
                 cooldown: float = 60.0) -> None:
        self.entropy_fn = entropy_fn
        self.window, self.cooldown = window, cooldown
        self.th_entropy, self.th_ext, self.th_note = entropy_files, ext_files, note_dirs
        self.events: deque = deque()
        self.high: dict = {}
        self.notes: dict = {}
        self._fired: dict = {}
        self._samples: deque = deque()

    def _cool(self, name: str, now: float) -> bool:
        if now - self._fired.get(name, -1e9) < self.cooldown:
            return False
        self._fired[name] = now
        return True

    def feed(self, ev: FsEvent) -> list:
        now = ev.ts
        target = ev.target
        ext = os.path.splitext(target)[1].lower()
        self.events.append((now, ev.kind, target, ext))
        while self.events and now - self.events[0][0] > 60:
            self.events.popleft()
        out: list[Detection] = []

        if ev.kind in ("created", "modified", "moved") and ext not in COMPRESSED_EXTS:
            while self._samples and now - self._samples[0] > 1.0:
                self._samples.popleft()
            if len(self._samples) < 8:                   # limita leituras por segundo
                self._samples.append(now)
                ratio = self.entropy_fn(target)
                if ratio is not None and ratio > 0.95:
                    self.high[target] = now
        for path in [p for p, t in self.high.items() if now - t > self.window]:
            del self.high[path]
        if len(self.high) >= self.th_entropy and self._cool("ENTROPY", now):
            out.append(Detection(
                "RANSOM-MASS-ENCRYPT", "Muitos arquivos reescritos com conteudo cifrado/aleatorio",
                80, "T1486", "Comportamento tipico de ransomware",
                f"{len(self.high)} arquivos em {self.window:.0f}s"))

        recent = [e for e in self.events if now - e[0] <= self.window]
        counts = Counter(e[3] for e in recent
                         if e[1] in ("created", "moved") and e[3] and e[3] not in COMMON_EXTS)
        if counts:
            ext_top, n = counts.most_common(1)[0]
            if n >= self.th_ext and self._cool("EXT", now):
                out.append(Detection(
                    "RANSOM-MASS-RENAME", "Muitos arquivos recebendo a mesma extensao nova",
                    80, "T1486", "Ransomware renomeia arquivos com extensao propria",
                    f"{n} arquivos '{ext_top}' em {self.window:.0f}s"))

        base = os.path.basename(target)
        if ev.kind in ("created", "moved") and ext in NOTE_EXTS and NOTE_RE.search(base):
            dirs = self.notes.setdefault(base.lower(), {})
            dirs[os.path.dirname(target)] = now
            for d in [d for d, t in dirs.items() if now - t > 60]:
                del dirs[d]
            if len(dirs) >= self.th_note and self._cool("NOTE", now):
                out.append(Detection(
                    "RANSOM-NOTE", "O mesmo arquivo de 'instrucoes' surgiu em varias pastas",
                    70, "T1486", "Ransomware deixa bilhete de resgate em cada pasta", base))
        return out


# arquivos-isca (canaries)
class CanaryManager:
    """Cria arquivos-isca ocultos. Ransomware mexe neles cedo; usuarios comuns nao."""

    NAMES = ["_0_Documento_Importante.docx", "_0_Planilha_Financeira.xlsx",
             "_0_Fotos_Familia.jpg", "_0_Anotacoes.txt"]

    def __init__(self, roots, registry: Path = config.CANARY_FILE) -> None:
        self.roots = [r for r in roots if os.path.isdir(r)]
        self.registry = Path(registry)
        self.files: dict = {}          # caminho normalizado -> (caminho real, sha256)
        self.created_at = 0.0

    def _content(self, name: str) -> bytes:
        rnd = random.Random(name)
        text = "\n".join("Registro %d: %s" % (i, "".join(rnd.choices("abcdefghij ", k=60)))
                         for i in range(40)).encode()
        if name.endswith((".docx", ".xlsx")):
            import io
            buf = io.BytesIO()
            with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
                z.writestr("[Content_Types].xml", "<Types/>")
                z.writestr("data.txt", text)
            return buf.getvalue()
        if name.endswith(".jpg"):
            return b"\xff\xd8\xff\xe0" + text * 4
        return text

    def create(self) -> list:
        import hashlib
        made = []
        for root in self.roots:
            for name in self.NAMES:
                path = os.path.join(root, name)
                try:
                    if not os.path.exists(path):
                        Path(path).write_bytes(self._content(name))
                        self._hide(path)
                    self.files[_norm(path)] = (path, hashlib.sha256(Path(path).read_bytes()).hexdigest())
                    made.append(path)
                except OSError as exc:
                    log.warning("Nao foi possivel criar isca %s: %s", path, exc)
        self.created_at = time.time()
        self._save()
        return made

    @staticmethod
    def _hide(path: str) -> None:
        try:
            ctypes.windll.kernel32.SetFileAttributesW(path, 2)   # FILE_ATTRIBUTE_HIDDEN
        except Exception:
            pass

    def _save(self) -> None:
        try:
            self.registry.parent.mkdir(parents=True, exist_ok=True)
            self.registry.write_text(json.dumps([p for p, _ in self.files.values()]), encoding="utf-8")
        except OSError:
            pass

    def is_canary(self, path: str) -> bool:
        return _norm(path) in self.files

    def check(self, ev: FsEvent) -> Optional[Detection]:
        import hashlib
        if time.time() - self.created_at < 3:
            return None
        for path in (ev.path, ev.dest):
            entry = self.files.get(_norm(path)) if path else None
            if entry is None:
                continue
            real, baseline = entry
            if ev.kind in ("deleted", "moved"):
                return Detection("CANARY-HIT", "Arquivo-isca apagado/renomeado", 95, "T1486",
                                 "Programas legitimos nao mexem nestes arquivos", real)
            if ev.kind == "modified":
                try:
                    now_hash = hashlib.sha256(Path(real).read_bytes()).hexdigest()
                except OSError:
                    now_hash = ""
                if now_hash != baseline:
                    return Detection("CANARY-HIT", "Arquivo-isca foi modificado", 95, "T1486",
                                     "Programas legitimos nao mexem nestes arquivos", real)
        return None

    @staticmethod
    def remove_registered(registry: Path = config.CANARY_FILE) -> int:
        removed = 0
        try:
            paths = json.loads(Path(registry).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return 0
        for p in paths:
            try:
                os.remove(p)
                removed += 1
            except OSError:
                pass
        try:
            Path(registry).unlink()
        except OSError:
            pass
        return removed


class FileMonitor:
    """Liga backend + detector de ransomware + iscas + varredura ao baixar."""

    def __init__(self, mon) -> None:
        o = mon.opts
        self.mon = mon
        self.roots = [r for r in dict.fromkeys(list(o.roots) + list(o.hot_roots)) if os.path.isdir(r)]
        self.ransom_roots = _dir_roots(o.roots)
        self.hot_roots = _dir_roots(o.hot_roots)
        self.ransom = RansomwareDetector()
        self.canaries = CanaryManager(o.canary_roots or o.roots) if o.use_canaries else None
        self.backend = None
        self._queue: queue.Queue = queue.Queue()
        self._seen: dict = {}
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._skip = [_norm(str(p)) + os.sep for p in (
            config.QUARANTINE_DIR, config.LOGS_DIR, config.REPORTS_DIR,
            config.INCIDENTS_DIR, config.DATA_DIR)]

    def _excluded(self, path: str) -> bool:
        p = _norm(path) + os.sep
        return any(p.startswith(s) for s in self._skip)

    def start(self) -> str:
        if self.canaries:
            self.canaries.create()
        if not self.roots:
            return "sem pastas"
        self.backend = make_backend(self.roots, self.on_event, self.mon.opts.prefer_watchdog,
                                    self.mon.opts.poll_interval, self._excluded)
        self.backend.start()
        if self.mon.opts.realtime_scan:
            self._thread = threading.Thread(target=self._scan_loop, daemon=True)
            self._thread.start()
        return self.backend.name

    def stop(self) -> None:
        self._stop.set()
        if self.backend:
            self.backend.stop()
        if self._thread:
            self._thread.join(timeout=3)

    # eventos
    def on_event(self, ev: FsEvent) -> None:
        if self._excluded(ev.path) and not (ev.dest and not self._excluded(ev.dest)):
            return
        mon, o = self.mon, self.mon.opts
        mon.stats.add("file_events")
        if self.canaries:
            hit = self.canaries.check(ev)
            if hit:
                mon.report_ransomware([hit], canary=True)
        target = ev.target
        if o.watch_ransomware and _under(target, self.ransom_roots):
            dets = self.ransom.feed(ev)
            if dets:
                mon.report_ransomware(dets)
        if (o.realtime_scan and ev.kind in ("created", "modified", "moved")
                and _under(target, self.hot_roots) and not self._excluded(target)):
            self._queue.put(target)

    # varredura ao baixar
    def _scan_loop(self) -> None:
        pending: dict = {}
        settle = self.mon.opts.scan_settle
        while not self._stop.is_set():
            try:
                pending[self._queue.get(timeout=0.3)] = time.monotonic() + settle
            except queue.Empty:
                pass
            now = time.monotonic()
            for path, due in list(pending.items()):
                if due <= now:
                    del pending[path]
                    try:
                        self._scan_one(path, pending, settle)
                    except Exception:
                        log.exception("Falha ao analisar %s", path)

    def _scan_one(self, path: str, pending: dict, settle: float) -> None:
        if os.path.splitext(path)[1].lower() in IGNORE_EXTS:
            return
        try:
            st = os.stat(path)
        except OSError:
            return
        if time.time() - st.st_mtime < settle * 0.8:         # ainda sendo escrito
            pending[path] = time.monotonic() + settle
            return
        if st.st_size == 0 or st.st_size > 200 * config.MB:
            return
        sig = (st.st_size, st.st_mtime_ns)
        if self._seen.get(path) == sig:
            return
        self._seen[path] = sig
        try:
            result = self.mon.analyzer().analyze_path(path, st.st_size)
        except OSError:
            return
        self.mon.stats.add("files_scanned")
        self.mon.report_file_findings(path, result.findings, result.sha256)
