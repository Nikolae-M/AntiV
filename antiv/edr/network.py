# comportamento de rede dos processos (sem driver: amostragem via psutil)

from __future__ import annotations

import ipaddress
import statistics
from collections import deque
from dataclasses import dataclass

from ..heuristics import in_suspicious_dir
from .models import Detection, ProcInfo

BAD_PORTS = {4444, 1337, 31337, 5555, 6667, 9001, 8333}
FANOUT_LIMIT = 40


@dataclass
class Conn:
    status: str
    laddr_ip: str
    laddr_port: int
    raddr_ip: str
    raddr_port: int


def is_public(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def evaluate_network(proc: ProcInfo, conns: list, never_network: frozenset) -> list:
    out: list[Detection] = []
    est = [c for c in conns if c.status == "ESTABLISHED" and is_public(c.raddr_ip)]
    if est and proc.name in never_network:
        out.append(Detection(
            "NET-UNEXPECTED", "Programa que nao usa internet esta conectado a ela", 40,
            "T1071", "Bloco de notas/calculadora nao deveriam abrir conexoes externas",
            f"{proc.name} -> {est[0].raddr_ip}:{est[0].raddr_port}"))
    if est and proc.exe and in_suspicious_dir(proc.exe):
        out.append(Detection(
            "NET-FROM-TEMP", "Programa de pasta temporaria conectado a internet", 30,
            "T1071", "", f"{est[0].raddr_ip}:{est[0].raddr_port}"))
    remotes = {c.raddr_ip for c in est}
    if len(remotes) >= FANOUT_LIMIT:
        out.append(Detection(
            "NET-FANOUT", "Conexoes com muitos destinos ao mesmo tempo", 40, "T1046",
            "Padrao de varredura de rede ou propagacao", f"{len(remotes)} destinos"))
    bad = [c for c in est if c.raddr_port in BAD_PORTS]
    if bad:
        out.append(Detection(
            "NET-BADPORT", "Conexao em porta associada a ferramentas de controle remoto", 25,
            "T1571", "", f"{bad[0].raddr_ip}:{bad[0].raddr_port}"))
    listening = [c for c in conns if c.status == "LISTEN" and c.laddr_ip in ("0.0.0.0", "::")]
    if listening and proc.exe and in_suspicious_dir(proc.exe):
        out.append(Detection(
            "NET-LISTEN-TEMP", "Programa de pasta temporaria aguardando conexoes externas", 35,
            "T1571", "", f"porta {listening[0].laddr_port}"))
    return out


class BeaconDetector:
    """Detecta conexoes que reaparecem em intervalos regulares (C2 'beaconing')."""

    def __init__(self, min_events: int = 6, max_jitter: float = 0.25,
                 min_interval: float = 4.0, max_interval: float = 900.0) -> None:
        self.min_events = min_events
        self.max_jitter = max_jitter
        self.min_interval = min_interval
        self.max_interval = max_interval
        self._present: dict = {}      # chave do processo -> destinos vistos na amostra anterior
        self._starts: dict = {}       # (chave, destino) -> instantes em que a conexao (re)apareceu

    def update(self, key, remotes: set, now: float):
        # Registra a amostra atual. Devolve descricao se houver beaconing.
        previous = self._present.get(key, set())
        found = None
        for remote in remotes:
            starts = self._starts.setdefault((key, remote), deque(maxlen=self.min_events))
            if remote not in previous:
                starts.append(now)
            if len(starts) >= self.min_events:
                gaps = [b - a for a, b in zip(starts, list(starts)[1:])]
                mean = statistics.fmean(gaps)
                if (self.min_interval <= mean <= self.max_interval
                        and statistics.pstdev(gaps) / mean <= self.max_jitter):
                    found = f"{remote} a cada ~{mean:.0f}s ({len(starts)} vezes)"
        self._present[key] = set(remotes)
        return found

    def forget(self, key) -> None:
        self._present.pop(key, None)
        for k in [k for k in self._starts if k[0] == key]:
            del self._starts[k]
