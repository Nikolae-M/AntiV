# vigia de persistencia: Run/RunOnce, pastas de inicializacao, tarefas e servicos

from __future__ import annotations

import json
import logging
import os
import re
import threading
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Callable, Optional

from .. import config
from ..heuristics import in_suspicious_dir
from .models import Detection

log = logging.getLogger(__name__)

_BASE = {  # tipo -> (pontos, tecnica ATT&CK)
    "run": (30, "T1547.001"), "startup": (30, "T1547.001"), "task": (30, "T1053.005"),
    "service": (35, "T1543.003"), "winlogon": (55, "T1547.004"),
    "ifeo": (60, "T1546.012"), "appinit": (60, "T1546.010"),
}
_LOLBIN = re.compile(r"(powershell|pwsh|cmd(\.exe)?\s+/c|wscript|cscript|mshta|rundll32|regsvr32)", re.I)
_RISKY_ARGS = re.compile(r"(-enc|-encodedcommand|https?://|-w(indowstyle)?\s+hidden)", re.I)
_TARGET = re.compile(r'^\s*"?([a-zA-Z]:\\[^"]+?\.(exe|dll|bat|cmd|vbs|js|ps1|scr|com|lnk))', re.I)


def extract_target(value: str) -> Optional[str]:
    match = _TARGET.match(value)
    return match.group(1) if match else None


def evaluate_persistence(key: str, value: str, analyze: Optional[Callable] = None) -> list:
    kind = key.split(":", 1)[0]
    points, technique = _BASE.get(kind, (30, ""))
    dets = [Detection(f"PERSIST-{kind.upper()}", f"Novo item de inicializacao automatica ({kind})",
                      points, technique, key.split(":", 1)[-1][:160], value[:200])]
    low = value.lower().replace("/", "\\")
    if in_suspicious_dir(low) or "\\downloads\\" in low:
        dets.append(Detection("PERSIST-TEMP", "Alvo em pasta temporaria/publica/downloads", 30,
                              technique, "", value[:200]))
    if _LOLBIN.search(value):
        dets.append(Detection("PERSIST-LOLBIN", "Inicializacao via interpretador/LOLBin", 25,
                              technique, "", value[:200]))
    if _RISKY_ARGS.search(value):
        dets.append(Detection("PERSIST-ARGS", "Argumentos suspeitos (comando codificado/URL/janela oculta)",
                              20, technique, "", value[:200]))
    target = extract_target(value)
    if target and analyze:
        for f in analyze(target):
            if f.level == "alta":
                dets.append(Detection("PERSIST-KNOWN", f"Alvo e malware conhecido: {f.name}", 60, technique, f.method, target))
            elif f.level == "suspeito":
                dets.append(Detection("PERSIST-HEUR", f"Alvo com caracteristicas suspeitas ({f.name})", 25, technique, "", target))
    return dets


def windows_snapshot(include_services: bool = True) -> dict:
    # fotografa os pontos de persistencia do Windows. Chave -> comando/alvo.
    if os.name != "nt":
        return {}
    import winreg

    out: dict = {}

    def values(hive_name, hive, path, prefix):
        try:
            with winreg.OpenKey(hive, path) as k:
                i = 0
                while True:
                    try:
                        name, val, _ = winreg.EnumValue(k, i)
                        out[f"{prefix}:{hive_name}\\{path}\\{name}"] = str(val)
                        i += 1
                    except OSError:
                        break
        except OSError:
            pass

    run_paths = [r"Software\Microsoft\Windows\CurrentVersion\Run",
                 r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
                 r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
                 r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"]
    for hname, hive in (("HKCU", winreg.HKEY_CURRENT_USER), ("HKLM", winreg.HKEY_LOCAL_MACHINE)):
        for path in run_paths:
            values(hname, hive, path, "run")
    for name in ("Shell", "Userinit"):
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon") as k:
                out[f"winlogon:{name}"] = str(winreg.QueryValueEx(k, name)[0])
        except OSError:
            pass
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                            r"Software\Microsoft\Windows NT\CurrentVersion\Windows") as k:
            dlls = str(winreg.QueryValueEx(k, "AppInit_DLLs")[0]).strip()
            if dlls:
                out["appinit:AppInit_DLLs"] = dlls
    except OSError:
        pass
    ifeo = r"Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, ifeo) as k:
            i = 0
            while True:
                try:
                    sub = winreg.EnumKey(k, i)
                    i += 1
                except OSError:
                    break
                try:
                    with winreg.OpenKey(k, sub) as sk:
                        out[f"ifeo:{sub}"] = str(winreg.QueryValueEx(sk, "Debugger")[0])
                except OSError:
                    continue
    except OSError:
        pass

    for env, rel in (("APPDATA", r"Microsoft\Windows\Start Menu\Programs\Startup"),
                     ("PROGRAMDATA", r"Microsoft\Windows\Start Menu\Programs\StartUp")):
        base = os.environ.get(env)
        folder = Path(base) / rel if base else None
        if folder and folder.is_dir():
            try:
                for f in folder.iterdir():
                    if f.is_file() and f.name.lower() != "desktop.ini":
                        out[f"startup:{f}"] = str(f)
            except OSError:
                pass

    tasks = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "Tasks"
    stack = [tasks]
    while stack:
        d = stack.pop()
        try:
            for f in d.iterdir():
                if f.is_dir():
                    stack.append(f)
                else:
                    out[f"task:{f.relative_to(tasks)}"] = _task_command(f)
        except OSError:
            continue

    if include_services:
        try:
            import psutil
            for svc in psutil.win_service_iter():
                try:
                    out[f"service:{svc.name()}"] = svc.binpath()
                except Exception:
                    continue
        except Exception:
            pass
    return out


def _task_command(path: Path) -> str:
    try:
        root = ET.fromstring(path.read_bytes())
    except (OSError, ET.ParseError):
        return ""
    parts = []
    for el in root.iter():
        tag = el.tag.rsplit("}", 1)[-1]
        if tag in ("Command", "Arguments") and el.text:
            parts.append(el.text.strip())
    return " ".join(parts)


def diff_snapshots(old: dict, new: dict) -> list:
    # [(chave, valor, 'novo'|'alterado')]
    out = []
    for key, value in new.items():
        if key not in old:
            out.append((key, value, "novo"))
        elif old[key] != value:
            out.append((key, value, "alterado"))
    return out


class PersistenceWatcher:
    def __init__(self, mon, snapshot_fn: Optional[Callable] = None,
                 baseline_path: Path = config.PERSIST_BASELINE) -> None:
        self.mon = mon
        self.snapshot_fn = snapshot_fn or windows_snapshot
        self.baseline_path = Path(baseline_path)
        self.prev: Optional[dict] = None
        self._n = 0
        try:
            self.prev = json.loads(self.baseline_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            self.prev = None

    def poll_once(self, include_services: bool = True) -> int:
        try:
            snap = self.snapshot_fn(include_services=include_services)
        except TypeError:
            snap = self.snapshot_fn()
        if not include_services and self.prev:     # mantem os servicos da foto anterior
            snap = {**{k: v for k, v in self.prev.items() if k.startswith("service:")}, **snap}
        changes = 0
        if self.prev is not None:
            for key, value, how in diff_snapshots(self.prev, snap):
                changes += 1
                self.mon.telemetry.log("persistence", key=key, value=value[:300], change=how)
                dets = evaluate_persistence(key, value, self.mon.analyze_exe)
                target = extract_target(value) or ""
                self.mon.report_direct(
                    "persistencia", f"Persistencia {how}: {key.split(':', 1)[0]}", dets,
                    dedupe_key=f"{key}={value}", path=target or key.split(":", 1)[-1])
        self.prev = snap
        try:
            self.baseline_path.parent.mkdir(parents=True, exist_ok=True)
            self.baseline_path.write_text(json.dumps(snap), encoding="utf-8")
        except OSError:
            pass
        return changes

    def run(self, stop: threading.Event, interval: float) -> None:
        while not stop.is_set():
            self._n += 1
            try:
                self.poll_once(include_services=(self._n % 6 == 1))
            except Exception:
                log.exception("Falha ao verificar persistencia")
            stop.wait(interval)
