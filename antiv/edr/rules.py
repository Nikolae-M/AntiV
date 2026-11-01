# regras comportamentais: linha de comando, cadeia pai->filho e disfarces

from __future__ import annotations

import json
import logging
import os
import re
from dataclasses import dataclass
from pathlib import Path

from .. import config
from ..heuristics import in_suspicious_dir
from .models import Detection, ProcInfo

log = logging.getLogger(__name__)

SYSTEM_NAMES = {"svchost.exe", "lsass.exe", "csrss.exe", "winlogon.exe",
                "services.exe", "smss.exe", "wininit.exe", "explorer.exe",
                "taskhostw.exe", "spoolsv.exe", "dwm.exe"}
SYSTEM_DIRS = ("\\windows\\system32\\", "\\windows\\syswow64\\", "\\windows\\")
# quem deve ser o processo-pai de cada processo de sistema (quando o pai existe)
EXPECTED_PARENT = {
    "svchost.exe": {"services.exe"},
    "lsass.exe": {"wininit.exe"},
    "services.exe": {"wininit.exe"},
}
MAX_CMD = 8192


@dataclass
class CmdRule:
    id: str
    name: str
    points: int
    technique: str
    description: str
    processes: frozenset
    patterns: tuple
    also: tuple
    min_matches: int
    count_char: str

    def match(self, name: str, cmd: str):
        # Devolve a evidencia (texto) se a regra casar, senao None
        if self.processes and name not in self.processes:
            return None
        if self.count_char:
            n = cmd.count(self.count_char)
            return f"{n} ocorrencias de '{self.count_char}'" if n >= self.min_matches else None
        evidence = None
        for pat in self.patterns:
            hits = list(pat.finditer(cmd))
            if len(hits) >= self.min_matches:
                evidence = hits[0].group(0)[:120]
                break
        if evidence is None:
            return None
        if self.also and not any(p.search(cmd) for p in self.also):
            return None
        return evidence


@dataclass
class LineageRule:
    id: str
    name: str
    points: int
    technique: str
    description: str
    parents: frozenset
    children: frozenset


class BehaviorRules:
    def __init__(self, cmd_rules, lineage_rules, never_network) -> None:
        self.cmd_rules = cmd_rules
        self.lineage_rules = lineage_rules
        self.never_network = never_network

    @classmethod
    def load(cls, path: Path = config.BEHAVIOR_RULES_FILE) -> "BehaviorRules":
        try:
            raw = json.loads(Path(path).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            log.error("Regras comportamentais indisponiveis (%s): %s", path, exc)
            return cls([], [], frozenset())
        flags = re.IGNORECASE
        cmd_rules = []
        for r in raw.get("cmdline_rules", []):
            try:
                cmd_rules.append(CmdRule(
                    id=r["id"], name=r["name"], points=int(r["points"]),
                    technique=r.get("technique", ""), description=r.get("description", ""),
                    processes=frozenset(p.lower() for p in r.get("processes", [])),
                    patterns=tuple(re.compile(p, flags) for p in r.get("patterns", [])),
                    also=tuple(re.compile(p, flags) for p in r.get("also", [])),
                    min_matches=int(r.get("min_matches", 1)),
                    count_char=r.get("count_char", ""),
                ))
            except (KeyError, re.error) as exc:
                log.warning("Regra ignorada (%s): %s", r.get("id", "?"), exc)
        lineage = [LineageRule(
            id=r["id"], name=r["name"], points=int(r["points"]),
            technique=r.get("technique", ""), description=r.get("description", ""),
            parents=frozenset(p.lower() for p in r["parents"]),
            children=frozenset(c.lower() for c in r["children"]),
        ) for r in raw.get("lineage_rules", [])]
        never = frozenset(n.lower() for n in raw.get("never_network", []))
        return cls(cmd_rules, lineage, never)


def _norm(path: str) -> str:
    return path.replace("/", "\\").lower()


def is_system_path(exe: str) -> bool:
    return any(d in _norm(exe) for d in SYSTEM_DIRS)


def evaluate_process(proc: ProcInfo, parent: ProcInfo | None,
                     rules: BehaviorRules) -> list:
    # Avalia UM processo (sem estado): linha de comando, linhagem e disfarces
    out: list[Detection] = []
    cmd = proc.cmdline[:MAX_CMD]
    exe_n = _norm(proc.exe)

    for rule in rules.cmd_rules:
        evidence = rule.match(proc.name, cmd)
        if evidence is not None:
            out.append(Detection(rule.id, rule.name, rule.points, rule.technique,
                                 rule.description, evidence))

    if parent is not None:
        for rule in rules.lineage_rules:
            if parent.name in rule.parents and proc.name in rule.children:
                out.append(Detection(rule.id, rule.name, rule.points, rule.technique,
                                     rule.description, f"{parent.name} -> {proc.name}"))
        expected = EXPECTED_PARENT.get(proc.name)
        if expected and parent.name not in expected:
            out.append(Detection(
                "WRONG-PARENT", "Processo de sistema com pai incomum", 55, "T1036.005",
                "Processos de sistema tem um pai especifico; outro pai indica imitacao",
                f"pai: {parent.name}"))

    if proc.name in SYSTEM_NAMES and exe_n and "\\windows\\" not in exe_n:
        out.append(Detection(
            "MASQUERADE", "Nome de processo do sistema fora da pasta do Windows", 50,
            "T1036.005", "Malware imita nomes como svchost.exe em outras pastas", proc.exe))
    if exe_n and in_suspicious_dir(exe_n):
        out.append(Detection(
            "RUN-FROM-TEMP", "Executando de pasta temporaria/publica", 20, "T1204.002",
            "Programas legitimos raramente rodam de Temp/Public", proc.exe))
    if proc.name.count(".") >= 2 and proc.name.endswith(".exe"):
        out.append(Detection("DOUBLE-EXT", "Dupla extensao no nome do processo", 30,
                             "T1036.007", "", proc.name))
    if proc.exe and not os.path.exists(proc.exe) and os.path.isdir(os.path.dirname(proc.exe)):
        out.append(Detection("EXE-DELETED", "Arquivo do executavel foi apagado com o processo ativo",
                             35, "T1070.004", "Tecnica para esconder o malware em disco", proc.exe))
    return out
