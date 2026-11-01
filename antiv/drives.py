# deteccao do tipo de disco (SSD/HDD) e listagem de unidades

from __future__ import annotations

import logging
import os
import subprocess

log = logging.getLogger(__name__)

_CREATE_NO_WINDOW = 0x08000000


def detect_disk_type(path) -> str:
    # Retorna 'ssd', 'hdd' ou 'unknown'
    try:
        return _detect_windows(str(path)) if os.name == "nt" else _detect_linux(str(path))
    except Exception as exc:  # deteccao nunca pode derrubar a varredura
        log.info("Nao foi possivel detectar o tipo de disco: %s", exc)
        return "unknown"


def _detect_windows(path: str) -> str:
    import ctypes

    drive = os.path.splitdrive(os.path.abspath(path))[0]
    if len(drive) != 2 or not drive[0].isalpha():
        return "unknown"                      # caminho de rede (UNC)
    root = drive + "\\"
    if ctypes.windll.kernel32.GetDriveTypeW(root) != 3:   # 3 = disco fixo
        return "unknown"                      # removivel/rede
    cmd = (f"(Get-Partition -DriveLetter {drive[0]} | Get-Disk | "
           "Get-PhysicalDisk | Select-Object -First 1 -ExpandProperty MediaType)")
    out = subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", cmd],
        capture_output=True, text=True, timeout=20, creationflags=_CREATE_NO_WINDOW,
    ).stdout.strip().lower()
    if "ssd" in out:
        return "ssd"
    if "hdd" in out:
        return "hdd"
    return "unknown"


def _detect_linux(path: str) -> str:
    st = os.stat(path)
    sys_path = os.path.realpath(f"/sys/dev/block/{os.major(st.st_dev)}:{os.minor(st.st_dev)}")
    for candidate in (sys_path, os.path.dirname(sys_path)):
        flag = os.path.join(candidate, "queue", "rotational")
        if os.path.exists(flag):
            with open(flag) as fh:
                return "hdd" if fh.read().strip() == "1" else "ssd"
    return "unknown"

def list_drives() -> list:
    # lista [(raiz, descricao)] das unidades do Windows
    if os.name != "nt":
        return []
    import ctypes
    import string

    kinds = {2: "Removivel", 3: "Disco local", 4: "Rede"}
    mask = ctypes.windll.kernel32.GetLogicalDrives()
    drives = []
    for i, letter in enumerate(string.ascii_uppercase):
        if mask & (1 << i):
            root = f"{letter}:\\"
            kind = ctypes.windll.kernel32.GetDriveTypeW(root)
            if kind in kinds:
                drives.append((root, f"{root}  ({kinds[kind]})"))
    return drives
