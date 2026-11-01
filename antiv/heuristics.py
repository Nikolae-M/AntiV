# Heuristicas: pontuam caracteristicas suspeitas sem depender de assinaturas
#
# cada funcao devolve uma lista de (pontos, motivo). A soma decide se o arquivo
# e "suspeito" ou apenas uma "observacao". Heuristicas NUNCA sao certeza: podem
# gerar falsos positivos (ex.: instaladores legitimos empacotados com UPX)

from __future__ import annotations

import re
import struct
import zipfile
import zlib

from .filetypes import DOC_EXTS, EXEC_FINAL_EXTS

Reason = tuple

_SUSPECT_DIRS = (
    "\\appdata\\local\\temp\\", "\\windows\\temp\\",
    "\\users\\public\\", "\\$recycle.bin\\",
)

_TRAILING_SPACES = re.compile(r"\s{5,}\.[a-z0-9]{2,4}$")
_B64_BLOB = re.compile(rb"[A-Za-z0-9+/]{500,}={0,2}")

_PACKER_SECTIONS = {
    b"upx0", b"upx1", b"upx2", b".aspack", b".adata", b".themida", b".vmp0",
    b".vmp1", b".petite", b".nsp0", b".nsp1", b"mpress1", b"mpress2",
    b".enigma1", b".packed",
}
_STANDARD_CODE_SECTIONS = {b".text", b".code", b"text", b"code"}

_SUSPICIOUS_APIS = (
    b"VirtualAllocEx", b"WriteProcessMemory", b"CreateRemoteThread",
    b"NtUnmapViewOfSection", b"SetWindowsHookEx", b"GetAsyncKeyState",
    b"URLDownloadToFile", b"NtWriteVirtualMemory", b"QueueUserAPC",
    b"AdjustTokenPrivileges", b"CryptEncrypt", b"WinExec",
)

_EXEC_EMBEDDED = (".exe", ".scr", ".js", ".vbs", ".bat", ".ps1", ".jar", ".dll", ".hta", ".lnk")

_IMAGE_SCN_CODE = 0x00000020
_IMAGE_SCN_MEM_EXECUTE = 0x20000000
_IMAGE_SCN_MEM_WRITE = 0x80000000


def compress_ratio(data: bytes) -> float:
    # Proxy rapido de entropia: dados cifrados/empacotados nao comprimem
    if len(data) < 4096:
        return 0.0
    return len(zlib.compress(data, 1)) / len(data)


def in_suspicious_dir(path: str) -> bool:
    return any(d in path.replace("/", "\\").lower() for d in _SUSPECT_DIRS)


def name_heuristics(name: str) -> list:
    # analisa apenas o NOME do arquivo (disfarces de extensao)
    out: list = []
    if "\u202e" in name:
        out.append((80, "Nome usa o caractere RLO (U+202E) para inverter/disfarcar a extensao"))
    low = name.lower()
    parts = low.split(".")
    if len(parts) >= 3:
        last, prev = "." + parts[-1], "." + parts[-2].strip()
        if last in EXEC_FINAL_EXTS and prev in DOC_EXTS:
            out.append((60, f"Dupla extensao enganosa ('{prev}{last}')"))
    if _TRAILING_SPACES.search(low):
        out.append((60, "Muitos espacos antes da extensao (esconde a extensao real)"))
    return out


def analyze_pe(head: bytes) -> list:
    # analise estatica basica de executaveis Windows (cabecalho PE)
    out: list = []
    try:
        if len(head) < 0x40:
            return out
        pe = int.from_bytes(head[0x3C:0x40], "little")
        if pe + 24 > len(head) or head[pe:pe + 4] != b"PE\x00\x00":
            return out
        coff = pe + 4
        _machine, nsec, _ts, _sp, _ns, optsize, chars = struct.unpack_from("<HHIIIHH", head, coff)
        opt = coff + 20
        magic = struct.unpack_from("<H", head, opt)[0]
        is64 = magic == 0x20B
        entry = struct.unpack_from("<I", head, opt + 16)[0]
        dd_base = opt + (112 if is64 else 96)
        ndd = struct.unpack_from("<I", head, dd_base - 4)[0]
        imp_rva = sec_size = 0
        if ndd > 1 and dd_base + 16 <= len(head):
            imp_rva, _imp_size = struct.unpack_from("<II", head, dd_base + 8)
        if ndd > 4 and dd_base + 40 <= len(head):
            _sec_off, sec_size = struct.unpack_from("<II", head, dd_base + 32)
        is_dll = bool(chars & 0x2000)

        sections = []
        table = opt + optsize
        for i in range(min(nsec, 96)):
            off = table + 40 * i
            if off + 40 > len(head):
                break
            name, vsize, vaddr, rsize, rptr, _a, _b, _c, _d, ch = struct.unpack_from(
                "<8sIIIIIIHHI", head, off
            )
            sections.append((name.rstrip(b"\x00").lower(), vsize, vaddr, rsize, rptr, ch))

        if nsec == 0:
            out.append((20, "PE sem nenhuma secao"))

        if any(ch & _IMAGE_SCN_MEM_EXECUTE and ch & _IMAGE_SCN_MEM_WRITE
               for *_x, ch in sections):
            out.append((25, "Secao ao mesmo tempo gravavel e executavel (tipico de packers)"))

        for sname, *_rest in sections:
            if sname in _PACKER_SECTIONS:
                out.append((20, f"Secao de packer conhecido ('{sname.decode(errors='replace')}')"))
                break

        if sections and entry:
            idx = next(
                (i for i, (_n, vs, va, rs, _rp, _ch) in enumerate(sections)
                 if va <= entry < va + max(vs, rs)), None
            )
            if idx is None:
                out.append((25, "Ponto de entrada fora de qualquer secao"))
            elif (idx == len(sections) - 1 and len(sections) >= 3
                  and sections[idx][0] not in _STANDARD_CODE_SECTIONS):
                out.append((15, "Ponto de entrada na ultima secao"))

        for sname, _vs, _va, rsize, rptr, ch in sections:
            if ch & (_IMAGE_SCN_MEM_EXECUTE | _IMAGE_SCN_CODE) and rptr < len(head):
                chunk = head[rptr:rptr + min(rsize, 512 * 1024)]
                if len(chunk) >= 8192 and compress_ratio(chunk) > 0.94:
                    out.append((20, "Secao de codigo com entropia muito alta (empacotado/cifrado)"))
                    break

        if not is_dll and nsec > 0 and imp_rva == 0:
            out.append((20, "Executavel sem tabela de importacao"))

        found = [api for api in _SUSPICIOUS_APIS if api in head]
        if len(found) >= 6:
            out.append((30, f"Muitas APIs tipicas de injecao/espionagem ({len(found)})"))
        elif len(found) >= 4:
            out.append((15, f"Varias APIs tipicas de injecao/espionagem ({len(found)})"))

        if sec_size > 0:
            out.append((-15, "Possui bloco de assinatura digital (NAO verificada)"))
    except (struct.error, IndexError, ValueError):
        pass
    return out


def analyze_script(data: bytes) -> list:
    # procura ofuscacao e payloads codificados em scripts
    out: list = []
    text = data[:512 * 1024]
    if text[:2] == b"\xff\xfe":
        text = text.decode("utf-16-le", "ignore").encode("latin-1", "ignore")
    if _B64_BLOB.search(text):
        out.append((20, "Bloco Base64 muito longo embutido (possivel payload codificado)"))
    low = text.lower()
    if low.count(b"chr(") + low.count(b"chrw(") >= 40:
        out.append((20, "Uso excessivo de Chr() (ofuscacao de string)"))
    if (low.count(b"fromcharcode") >= 5 or b"eval(unescape(" in low
            or b"eval(function(p,a,c,k,e" in low):
        out.append((25, "JavaScript ofuscado (eval/fromCharCode/packer)"))
    return out


def analyze_ole(data: bytes) -> list:
    # documentos Office antigos (.doc/.xls) com macros VBA
    if "_VBA_PROJECT".encode("utf-16-le") in data or "Macros".encode("utf-16-le") in data:
        return [(30, "Documento Office (OLE) contem macros VBA")]
    return []


def analyze_ooxml(zf: zipfile.ZipFile, infos: list) -> list:
    # documentos .docx/.xlsx/.pptx/.docm: macros, executaveis e links remotos
    out: list = []
    lowered = [i.filename.lower() for i in infos]
    if any(n.endswith("vbaproject.bin") for n in lowered):
        out.append((30, "Documento Office contem macros VBA"))
    for n in lowered:
        if "/embeddings/" in n and n.endswith(_EXEC_EMBEDDED):
            out.append((50, f"Executavel/script embutido no documento ({n.rsplit('/', 1)[-1]})"))
            break
    for info in infos:
        if not info.filename.lower().endswith(".rels") or info.file_size > 256 * 1024:
            continue
        try:
            data = zf.read(info).lower()
        except (zipfile.BadZipFile, RuntimeError, NotImplementedError, zlib.error, EOFError, OSError):
            continue
        if (b'targetmode="external"' in data and b"http" in data
                and (b"attachedtemplate" in data or b"oleobject" in data or b"/frame" in data)):
            out.append((50, "Documento carrega modelo/objeto remoto (tecnica de injecao de template)"))
            break
    return out
