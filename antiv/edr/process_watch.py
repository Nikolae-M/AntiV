# vigia de processos: detecta novos processos e avalia o comportamento deles

from __future__ import annotations

import logging
import os
import subprocess
import time
from collections import deque

import psutil

from .. import config
from ..heuristics import in_suspicious_dir
from .models import Detection, ProcInfo
from .network import BeaconDetector, Conn, evaluate_network, is_public
from .rules import evaluate_process

log = logging.getLogger(__name__)

_KEEP_DEAD = 60.0          # segundos que lembramos de um processo ja encerrado (linhagem)
_MODULE_DELAY = 1.5        # espera antes de olhar as DLLs carregadas


def _safe(fn, default=None):
    try:
        return fn()
    except (psutil.Error, OSError, ValueError):
        return default


class ProcessWatcher:
    def __init__(self, mon) -> None:
        self.mon = mon
        self.pid_seen: dict = {}       # pid -> chave (pid, create_time)
        self.pid_info: dict = {}       # pid -> ProcInfo (inclui encerrados recentes)
        self.proc_obj: dict = {}       # pid -> psutil.Process
        self.died: dict = {}           # pid -> instante em que sumiu
        self.io_hist: dict = {}        # pid -> deque[(t, write_bytes)]
        self.beacon = BeaconDetector()
        self._pending: list = []       # [(instante, ProcInfo)] checagem de modulos
        self._first = True
        self._own = os.getpid()

    def is_own(self, info: ProcInfo) -> bool:
        # true para o proprio AntiV e seus filhos (exceto processos de teste)
        if info.pid in self.mon.test_pids or config.BEHAVIOR_TEST_TOKEN in info.cmdline:
            return False
        cur, depth = info, 0
        while cur is not None and depth < 12:
            if cur.pid == self._own:
                return True
            cur = self.pid_info.get(cur.ppid)
            depth += 1
        return False

    def _parent_of(self, info: ProcInfo):
        parent = self.pid_info.get(info.ppid)
        if parent is not None and parent.create_time <= info.create_time + 1:
            return parent
        return None

    def _build(self, pid: int):
        try:
            p = psutil.Process(pid)
            with p.oneshot():
                name = p.name().lower()
                ppid = p.ppid()
                ctime = p.create_time()
                exe = _safe(p.exe, "") or ""
                cmd = _safe(p.cmdline, []) or []
                user = _safe(p.username, "") or ""
        except (psutil.NoSuchProcess, psutil.ZombieProcess, psutil.AccessDenied):
            return None
        return ProcInfo(pid, ppid, name, exe, subprocess.list2cmdline(cmd), ctime, user), p

    def tick(self) -> None:
        # Uma passada: descobre processos novos/encerrados e avalia os novos
        pids = set(psutil.pids())
        now = time.monotonic()
        for pid in set(self.pid_seen) - pids:        # encerrados
            key = self.pid_seen.pop(pid)
            self.died[pid] = now
            self.beacon.forget(key)
            self.io_hist.pop(pid, None)
            self.proc_obj.pop(pid, None)
        for pid, when in list(self.died.items()):   # esquece os antigos
            if now - when > _KEEP_DEAD:
                self.died.pop(pid)
                self.pid_info.pop(pid, None)

        fresh = []
        for pid in sorted(pids - set(self.pid_seen)):
            built = self._build(pid)
            if built is None:
                continue
            info, proc = built
            self.pid_seen[pid] = info.key
            self.pid_info[pid] = info
            self.proc_obj[pid] = proc
            fresh.append(info)
        baseline = self._first
        self._first = False
        for info in fresh:                            # avalia depois de registrar todos (pais primeiro)
            self._evaluate_new(info, baseline)
        self._run_pending_modules()

    def _evaluate_new(self, info: ProcInfo, baseline: bool) -> None:
        mon = self.mon
        if self.is_own(info):
            return
        mon.stats.add("processes_seen")
        parent = self._parent_of(info)
        mon.telemetry.log(
            "process_start", pid=info.pid, ppid=info.ppid, name=info.name, exe=info.exe,
            cmdline=info.cmdline[:600], user=info.username,
            parent=parent.name if parent else "", baseline=baseline)

        dets = evaluate_process(info, parent, mon.rules)
        dets += self._static_detections(info)
        if parent is not None and mon.tracker.score(parent.key) >= 50:
            dets.append(Detection("PARENT-RISK", "Processo filho de processo ja suspeito", 25,
                                  "", "Cadeia de execucao originada em algo suspeito", parent.name))
        if dets:
            mon.report_detections(info, dets, "processo")
        if not baseline and info.exe:
            self._pending.append((time.monotonic() + _MODULE_DELAY, info))

    def _static_detections(self, info: ProcInfo) -> list:
        if not info.exe:
            return []
        out = []
        for f in self.mon.analyze_exe(info.exe):
            if f.level == "alta":
                out.append(Detection("STATIC-KNOWN", f"Arquivo malicioso conhecido em execucao: {f.name}",
                                     95, "T1204.002", f.method, info.exe))
            elif f.level == "suspeito":
                out.append(Detection("STATIC-HEUR", f"Executavel com caracteristicas suspeitas ({f.name})",
                                     min(45, f.score // 2), "T1027", "; ".join(f.details[:2]), info.exe))
        return out

    def _run_pending_modules(self) -> None:
        now = time.monotonic()
        due = [item for item in self._pending if item[0] <= now][:3]
        self._pending = [i for i in self._pending if i not in due]
        for _when, info in due:
            if info.pid not in self.pid_seen:
                continue
            proc = self.proc_obj.get(info.pid)
            maps = _safe(lambda: proc.memory_maps(), []) if proc else []
            exe_dir = os.path.dirname(info.exe).lower()
            odd = [m.path for m in maps or []
                   if in_suspicious_dir(m.path) and os.path.dirname(m.path).lower() != exe_dir]
            if odd:
                self.mon.report_detections(info, [Detection(
                    "DLL-FROM-TEMP", "Modulo carregado de pasta temporaria/publica", 30, "T1574.002",
                    "Possivel DLL side-loading ou injecao", odd[0])], "processo")

    def net_tick(self) -> None:
        now = time.time()
        try:
            conns = psutil.net_connections(kind='inet')
        except (psutil.Error, OSError):
            return
        by_pid: dict = {}
        for c in conns:
            if not c.pid:
                continue
            by_pid.setdefault(c.pid, []).append(Conn(
                c.status, c.laddr.ip if c.laddr else "", c.laddr.port if c.laddr else 0,
                c.raddr.ip if c.raddr else "", c.raddr.port if c.raddr else 0))
        for pid, items in by_pid.items():
            info = self.pid_info.get(pid)
            if info is None or self.is_own(info) or pid not in self.pid_seen:
                continue
            dets = evaluate_network(info, items, self.mon.rules.never_network)
            remotes = {c.raddr_ip for c in items if c.status == "ESTABLISHED" and is_public(c.raddr_ip)}
            beacon = self.beacon.update(info.key, remotes, now)
            if beacon:
                dets.append(Detection("NET-BEACON", "Conexao periodica regular (possivel beaconing de C2)",
                                      45, "T1071", "Malware costuma 'ligar para casa' em intervalos fixos", beacon))
            if dets:
                self.mon.report_detections(info, dets, "rede")
        for key in [k for k in list(self.beacon._present) if k[0] not in by_pid]:
            self.beacon.update(key, set(), now)

    def io_tick(self) -> None:
        now = time.monotonic()
        for pid, proc in list(self.proc_obj.items()):
            counters = _safe(proc.io_counters)
            if counters is None:
                continue
            self.io_hist.setdefault(pid, deque(maxlen=10)).append((now, counters.write_bytes))

    def top_writers(self, window: float = 8.0) -> list:
        # [(pid, bytes_escritos)] na janela recente, do maior para o menor
        now = time.monotonic()
        out = []
        for pid, hist in self.io_hist.items():
            recent = [(t, b) for t, b in hist if now - t <= window]
            if len(recent) >= 2 and recent[-1][1] > recent[0][1]:
                out.append((pid, recent[-1][1] - recent[0][1]))
        return sorted(out, key=lambda x: -x[1])
