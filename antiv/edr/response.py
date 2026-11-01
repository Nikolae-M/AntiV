# resposta a incidentes: suspender, encerrar, quarentena e dossie (triagem)

from __future__ import annotations

import hashlib
import json
import logging
import os
import time
from pathlib import Path

import psutil

from .. import config
from ..quarantine import QuarantineManager
from .rules import is_system_path

log = logging.getLogger(__name__)

# nunca suspender/encerrar estes quando estiverem na pasta do Windows
CRITICAL_NAMES = {
    "system", "registry", "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe",
    "services.exe", "lsass.exe", "svchost.exe", "explorer.exe", "dwm.exe",
    "fontdrvhost.exe", "spoolsv.exe", "msmpeng.exe", "systemd", "init",
}


def is_protected(pid: int, name: str = "", exe: str = "") -> tuple:
    # (protegido?, motivo). Evita derrubar o sistema ou o proprio AntiV.
    if pid <= 4 or pid == 1:
        return True, "processo essencial do sistema"
    if pid == os.getpid():
        return True, "o proprio AntiV"
    if name.lower() in CRITICAL_NAMES and (not exe or is_system_path(exe)):
        return True, "processo critico do Windows"
    return False, ""


def _proc(pid: int):
    try:
        return psutil.Process(pid)
    except psutil.NoSuchProcess:
        return None


def _guard(pid: int):
    p = _proc(pid)
    if p is None:
        return None, "o processo ja foi encerrado"
    try:
        name, exe = p.name(), p.exe()
    except psutil.Error:
        name, exe = "", ""
    protected, why = is_protected(pid, name, exe)
    return (None, f"protegido ({why})") if protected else (p, "")


def suspend_process(pid: int) -> tuple:
    p, msg = _guard(pid)
    if p is None:
        return False, msg
    try:
        p.suspend()
        return True, f"processo {pid} suspenso (reversivel: use 'Retomar')"
    except psutil.Error as exc:
        return False, f"nao foi possivel suspender: {exc}"


def resume_process(pid: int) -> tuple:
    p = _proc(pid)
    if p is None:
        return False, "o processo ja foi encerrado"
    try:
        p.resume()
        return True, f"processo {pid} retomado"
    except psutil.Error as exc:
        return False, f"nao foi possivel retomar: {exc}"


def terminate_process(pid: int, timeout: float = 3.0) -> tuple:
    p, msg = _guard(pid)
    if p is None:
        return False, msg
    try:
        try:
            p.resume()                 # processo suspenso nao responde a terminate no Linux
        except psutil.Error:
            pass
        p.terminate()
        try:
            p.wait(timeout)
        except psutil.TimeoutExpired:
            p.kill()
        return True, f"processo {pid} encerrado"
    except psutil.Error as exc:
        return False, f"nao foi possivel encerrar: {exc}"


def quarantine_executable(pid: int, exe: str, threat: str) -> tuple:
    # encerra o processo e isola o executavel (so se estiver fora da pasta do Windows)
    if not exe or not os.path.isfile(exe):
        return False, "executavel nao encontrado em disco"
    if is_system_path(exe):
        return False, "executavel dentro da pasta do Windows: nao sera movido"
    ok, msg = terminate_process(pid) if pid else (True, "")
    if not ok and "ja foi encerrado" not in msg:
        return False, msg
    try:
        digest = hashlib.sha256(Path(exe).read_bytes()).hexdigest()
        qid = QuarantineManager().quarantine(Path(exe), threat, digest)
        return True, f"executavel isolado (id {qid[:8]})"
    except OSError as exc:
        return False, f"falha ao isolar: {exc}"


def _safe(fn, default=None):
    try:
        return fn()
    except Exception:
        return default


def _brief(p: psutil.Process) -> dict:
    return {"pid": p.pid, "name": _safe(p.name, ""), "exe": _safe(p.exe, ""),
            "cmdline": " ".join(_safe(p.cmdline, []) or [])[:1000]}


def collect_triage(pid: int, reason: str = "") -> dict:
    # coleta um 'dossie' do processo: arvore, rede, arquivos abertos, modulos, hash
    data: dict = {"collected_at": time.strftime("%Y-%m-%d %H:%M:%S"), "pid": pid, "reason": reason}
    p = _proc(pid)
    if p is None:
        data["error"] = "processo ja encerrado"
        return data
    with p.oneshot():
        data.update(
            name=_safe(p.name, ""), exe=_safe(p.exe, ""), cwd=_safe(p.cwd, ""),
            username=_safe(p.username, ""), status=_safe(p.status, ""),
            create_time=_safe(lambda: time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(p.create_time())), ""),
            cmdline=" ".join(_safe(p.cmdline, []) or [])[:4000],
        )
    ancestors, current = [], p
    for _ in range(8):
        current = _safe(current.parent)
        if current is None:
            break
        ancestors.append(_brief(current))
    data["ancestors"] = ancestors
    data["children"] = [_brief(c) for c in (_safe(p.children, []) or [])][:30]
    net = getattr(p, "net_connections", None) or p.connections
    data["connections"] = [
        {"status": c.status, "local": f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "",
         "remote": f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else ""}
        for c in (_safe(lambda: net(kind="inet"), []) or [])][:50]
    data["open_files"] = [f.path for f in (_safe(p.open_files, []) or [])][:50]
    data["modules"] = [m.path for m in (_safe(p.memory_maps, []) or [])][:100]
    exe = data.get("exe")
    if exe and os.path.isfile(exe) and os.path.getsize(exe) <= 200 * config.MB:
        data["sha256"] = _safe(lambda: hashlib.sha256(Path(exe).read_bytes()).hexdigest(), "")
    return data


def save_triage(data: dict) -> Path:
    config.INCIDENTS_DIR.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%d_%H%M%S")
    name = "".join(c for c in str(data.get("name", "proc")) if c.isalnum() or c in "._-")[:30]
    path = config.INCIDENTS_DIR / f"{stamp}_{data.get('pid', 0)}_{name}.json"
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
    return path
