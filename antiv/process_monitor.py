# Monitor de processos: heuristicas + analise do arquivo executavel

from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass, field

import psutil

from . import config
from .analyzer import FileAnalyzer
from .signatures import RuleSet, SignatureDB

log = logging.getLogger(__name__)

CPU_LIMIT = 85.0   # % de CPU considerada anomala
MEM_LIMIT = 40.0   # % de RAM considerada anomala

SUSPICIOUS_DIRS = ("\\appdata\\local\\temp\\", "\\windows\\temp\\",
                   "\\users\\public\\", "\\$recycle.bin\\")

SYSTEM_NAMES = {"svchost.exe", "lsass.exe", "csrss.exe", "winlogon.exe",
                "services.exe", "smss.exe", "wininit.exe"}
SYSTEM_DIR = "\\windows\\system32\\"

# programas que normalmente NAO deveriam abrir interpretadores de comando
OFFICE_PARENTS = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe",
                  "acrord32.exe", "onenote.exe"}
SHELL_CHILDREN = {"cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe",
                  "mshta.exe", "rundll32.exe", "regsvr32.exe"}

MAX_EXE_SIZE = 200 * config.MB


@dataclass
class ProcessAlert:
    pid: int
    name: str
    exe: str
    reasons: list = field(default_factory=list)


def scan_processes(sample_seconds: float = 1.0, analyze_files: bool = True) -> list:
    # amostra os processos e devolve os que dispararam alguma regra
    for proc in psutil.process_iter():          # 1a leitura de CPU (descartada)
        try:
            proc.cpu_percent(None)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    time.sleep(sample_seconds)

    infos = [p.info for p in psutil.process_iter(
        ["pid", "ppid", "name", "exe", "cpu_percent", "memory_percent"])]
    names = {i["pid"]: (i.get("name") or "").lower() for i in infos}

    analyzer = (FileAnalyzer(SignatureDB(), RuleSet.load(), level=2, scan_archives=False)
                if analyze_files else None)
    exe_cache: dict = {}
    alerts: list[ProcessAlert] = []

    for info in infos:
        name = (info.get("name") or "").lower()
        exe = info.get("exe") or ""
        exe_l = exe.lower()
        reasons = []

        if (info.get("cpu_percent") or 0) > CPU_LIMIT:
            reasons.append(f"CPU alta ({info['cpu_percent']:.0f}%)")
        if (info.get("memory_percent") or 0) > MEM_LIMIT:
            reasons.append(f"memoria alta ({info['memory_percent']:.0f}%)")
        if exe_l and any(d in exe_l for d in SUSPICIOUS_DIRS):
            reasons.append("executando de pasta temporaria/publica")
        if name in SYSTEM_NAMES and exe_l and SYSTEM_DIR not in exe_l:
            reasons.append("nome de processo do sistema fora de System32 (possivel imitacao)")
        if name.count(".") >= 2 and name.endswith(".exe"):
            reasons.append("dupla extensao no nome")
        parent = names.get(info.get("ppid"), "")
        if parent in OFFICE_PARENTS and name in SHELL_CHILDREN:
            reasons.append(f"iniciado por {parent} (comportamento tipico de macro maliciosa)")

        if analyzer and exe and os.path.isfile(exe):
            if exe not in exe_cache:
                exe_cache[exe] = _analyze_exe(analyzer, exe)
            for finding in exe_cache[exe]:
                if finding.level in ("alta", "suspeito"):
                    reasons.append(f"arquivo: {finding.name} [{finding.level}, {finding.method}]")

        if reasons:
            alerts.append(ProcessAlert(info["pid"], info.get("name") or "?", exe, reasons))
    return alerts


def _analyze_exe(analyzer: FileAnalyzer, exe: str) -> list:
    try:
        size=os.path.getsize(exe)
        if size == 0 or size > MAX_EXE_SIZE:
            return []
        return analyzer.analyze_path(exe, size).findings
    except OSError:
        return []
