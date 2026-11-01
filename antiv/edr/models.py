# modelos de dados do monitor comportamental

from __future__ import annotations

import time
from dataclasses import asdict, dataclass, field

LEVEL_RANK = {"": 0, "aviso": 1, "alto": 2, "critico": 3}


def level_for_score(score: int) -> str:
    # Pontuacao de risco (0-100) -> nivel de alerta
    if score >= 90:
        return "critico"
    if score >= 70:
        return "alto"
    if score >= 40:
        return "aviso"
    return ""


@dataclass
class ProcInfo:
    pid: int
    ppid: int
    name: str                      # sempre minusculo
    exe: str = ""
    cmdline: str = ""
    create_time: float = 0.0
    username: str = ""

    @property
    def key(self) -> tuple:
        # identifica o processo mesmo que o PID seja reutilizado
        return (self.pid, round(self.create_time, 2))


@dataclass
class Detection:
    rule_id: str
    name: str
    points: int
    technique: str = ""            # ID MITRE ATT&CK (ex.: T1059.001)
    description: str = ""
    evidence: str = ""


@dataclass
class Alert:
    id: int
    ts: float
    level: str                     # aviso | alto | critico
    score: int
    source: str                    # processo | rede | arquivo | ransomware | persistencia
    title: str
    pid: int = 0
    process: str = ""
    exe: str = ""
    path: str = ""
    detections: list = field(default_factory=list)
    action: str = "nenhuma"
    incident: str = ""             # caminho do dossie (JSON) deste incidente
    sha256: str = ""

    @property
    def techniques(self) -> list:
        return sorted({d.technique for d in self.detections if d.technique})

    @property
    def description(self) -> str:
        return " | ".join(d.name for d in self.detections[:4])

    def to_dict(self) -> dict:
        data = asdict(self)
        data["time"] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.ts))
        return data
