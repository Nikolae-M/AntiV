# identificacao do tipo real de um arquivo (conteudo, nao so extensao)

from __future__ import annotations

import os

# Extensoes de risco: usadas na varredura "Rapida"
RISKY_EXTS = frozenset({
    ".exe", ".dll", ".sys", ".scr", ".com", ".pif", ".cpl", ".ocx", ".drv",
    ".msi", ".msp", ".bat", ".cmd", ".ps1", ".psm1", ".vbs", ".vbe", ".js",
    ".jse", ".wsf", ".wsh", ".hta", ".sct", ".lnk", ".jar", ".inf", ".reg",
    ".docm", ".xlsm", ".pptm", ".dotm", ".xlsb", ".doc", ".xls", ".ppt",
    ".rtf", ".pdf", ".zip", ".rar", ".7z", ".cab", ".chm",
})

SCRIPT_EXTS = frozenset({
    ".bat", ".cmd", ".ps1", ".psm1", ".psd1", ".vbs", ".vbe", ".js", ".jse",
    ".wsf", ".wsh", ".hta", ".reg", ".sct",
})

# extensao final que executa codigo ao ser aberta com duplo clique
EXEC_FINAL_EXTS = frozenset({
    ".exe", ".scr", ".com", ".pif", ".bat", ".cmd", ".vbs", ".vbe", ".js",
    ".jse", ".wsf", ".hta", ".ps1", ".lnk", ".cpl",
})

# extensoes de documentos/imagens usadas para "disfarcar" executaveis
DOC_EXTS = frozenset({
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt",
    ".rtf", ".csv", ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".mp3",
    ".mp4", ".avi", ".mkv", ".wav", ".zip", ".rar", ".7z",
})

# extensoes que jamais deveriam conter um executavel Windows (PE)
NON_EXEC_EXTS = DOC_EXTS | frozenset({".log", ".ini", ".xml", ".html", ".htm", ".webp"})

_OLE_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"


def file_ext(name: str) -> str:
    return os.path.splitext(name)[1].lower()


def is_pe(head: bytes) -> bool:
    # true se o inicio do arquivo tem cabecalho DOS 'MZ' e assinatura 'PE'
    if len(head) < 0x40 or head[:2] != b"MZ":
        return False
    offset = int.from_bytes(head[0x3C:0x40], "little")
    return offset + 4 <= len(head) and head[offset:offset + 4] == b"PE\x00\x00"


def detect_kind(name: str, head: bytes) -> str:
    # Retorna: pe | zip | ole | script | lnk | inf | other
    ext = file_ext(name)
    if is_pe(head):
        return "pe"
    if head[:4] in (b"PK\x03\x04", b"PK\x05\x06"):
        return "zip"
    if head[:8] == _OLE_MAGIC:
        return "ole"
    if ext in SCRIPT_EXTS:
        return "script"
    if ext == ".lnk" or head[:4] == b"L\x00\x00\x00":
        return "lnk"
    if ext == ".inf":
        return "inf"
    return "other"
