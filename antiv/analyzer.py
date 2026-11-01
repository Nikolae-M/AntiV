# Analisador de arquivos: le UMA vez e aplica varios metodos de deteccao
#
# Metodos:
#   1. Hash SHA-256 contra a base de assinaturas.
#   2. Regras de padroes de bytes (strings/hex), filtradas pelo tipo do arquivo.
#   3. Heuristicas: PE (packers, W+X, entropia, imports), scripts ofuscados,
#      macros Office, disfarce de extensao, dupla extensao, caractere RLO
#   4. Conteudo de arquivos ZIP/Office analisado em memoria (sem extrair).

from __future__ import annotations

import hashlib
import io
import logging
import os
import zipfile
import zlib
from dataclasses import dataclass, field

from . import config, heuristics
from .filetypes import NON_EXEC_EXTS, detect_kind, file_ext
from .reporting import Finding
from .signatures import RuleSet, ScanBuffer, SignatureDB

log = logging.getLogger(__name__)

_ZIP_ERRORS = (zipfile.BadZipFile, RuntimeError, NotImplementedError,
               zlib.error, EOFError, OSError, ValueError)

_KIND_LABEL = {"pe": "PE", "script": "Script", "ole": "Documento", "zip": "Arquivo",
               "lnk": "Atalho", "inf": "Autorun", "other": "Arquivo"}


@dataclass
class AnalysisResult:
    findings: list = field(default_factory=list)
    sha256: str = ""
    bytes_read: int = 0


class FileAnalyzer:
    def __init__(self, db: SignatureDB, rules: RuleSet, level: int = 2,
                 chunk: int = 2 * config.MB, scan_archives: bool = True) -> None:
        self.db = db
        self.rules = rules
        self.level = level
        self.chunk = chunk
        self.scan_archives = scan_archives

    def analyze_path(self, path: str, size: int) -> AnalysisResult:
        # analisa um arquivo em disco. Pode levantar OSError (tratado fora).
        name = os.path.basename(path)
        with open(path, "rb", buffering=0) as fh:
            if size <= config.FULL_READ_LIMIT:
                data = fh.read()
                sha = hashlib.sha256(data).hexdigest()
                head = data[:config.HEAD_BYTES]
                kind = detect_kind(name, head)
                findings = self._evaluate(
                    path, "", name, kind, head, b"", data, sha, [], 0, path, True)
                return AnalysisResult(findings, sha, len(data))
            head, tail, sha, nread, kind, stream_hits = self._read_large(fh, name, size)
        findings = self._evaluate(
            path, "", name, kind, head, tail, None, sha, stream_hits, 0, path, True)
        return AnalysisResult(findings, sha, nread)

    def _read_large(self, fh, name: str, size: int):
        # le em blocos: hash do arquivo todo + amosras de inicio/fim
        buf = bytearray(self.chunk)
        view = memoryview(buf)
        digest = hashlib.sha256()
        head, kind, prev = b"", "other", b""
        tail_parts: list[bytes] = []
        hits: dict = {}
        pos = 0
        first = True
        tail_start = max(0, size - config.TAIL_BYTES)
        overlap = self.rules.max_pattern_len()
        while True:
            n = fh.readinto(buf)
            if not n:
                break
            chunk = view[:n]
            digest.update(chunk)
            if first:
                head = bytes(chunk[:config.HEAD_BYTES])
                kind = detect_kind(name, head)
                first = False
            if pos + n > tail_start:
                tail_parts.append(bytes(chunk[max(0, tail_start - pos):]))
            if self.level >= 3:  # varredura profunda: regras no arquivo inteiro
                window = prev + bytes(chunk)
                for rule in self.rules.match(kind, ScanBuffer(window)):
                    hits[rule.id] = rule
                prev = window[-overlap:] if overlap else b""
            pos += n
        tail = b"".join(tail_parts)[-config.TAIL_BYTES:]
        return head, tail, digest.hexdigest(), pos, kind, list(hits.values())

    def _evaluate(self, display_path, inner, name, kind, head, tail, full, sha,
                  stream_hits, depth, source, top_level) -> list:
        findings: list[Finding] = []

        # 1) Hash
        sig = self.db.lookup(sha)
        if sig:
            findings.append(Finding(
                path=display_path, inner=inner, level="alta", name=sig,
                method="hash SHA-256", score=100, sha256=sha,
                details=["O SHA-256 do arquivo consta na base de assinaturas"]))

        # TODO: ver se compensa usar yara aqui depois
        # 2) Regras de padroes de bytes
        hits = {r.id: r for r in stream_hits}
        if full is not None:
            for rule in self.rules.match(kind, ScanBuffer(full)):
                hits[rule.id] = rule
        else:
            for part in (head, tail):
                if part:
                    for rule in self.rules.match(kind, ScanBuffer(part)):
                        hits[rule.id] = rule
        for rule in hits.values():
            findings.append(Finding(
                path=display_path, inner=inner, level=rule.severity, name=rule.name,
                method="assinatura (padrao de bytes)",
                score=100 if rule.severity == "alta" else 60, sha256=sha,
                details=[rule.description] if rule.description else []))

        # 3) Heuristicas
        reasons = list(heuristics.name_heuristics(name))
        ext = file_ext(name)
        if kind == "pe":
            if ext in NON_EXEC_EXTS:
                reasons.append((70, f"Executavel Windows (PE) disfarcado com a extensao '{ext}'"))
            reasons += heuristics.analyze_pe(head)
            if top_level and heuristics.in_suspicious_dir(display_path):
                reasons.append((10, "Executavel em pasta temporaria/publica"))
        elif kind == "script":
            reasons += heuristics.analyze_script(full if full is not None else head)
        elif kind == "ole":
            reasons += heuristics.analyze_ole(full if full is not None else head + tail)

        # 4) Dentro de arquivos ZIP / documentos Office
        if (kind == "zip" and self.scan_archives and self.level >= 2
                and depth <= config.ARCHIVE_MAX_DEPTH):
            member_findings, zip_reasons = self._scan_zip(source, display_path, depth, inner)
            findings.extend(member_findings)
            reasons += zip_reasons

        score = max(0, min(100, sum(p for p, _ in reasons)))
        level = ("suspeito" if score >= config.SUSPECT_SCORE
                 else "info" if score >= config.INFO_SCORE else "")
        if level:
            label = _KIND_LABEL.get(kind, "Arquivo")
            findings.append(Finding(
                path=display_path, inner=inner, level=level,
                name=f"Heur.{label}.{'Suspeito' if level == 'suspeito' else 'Observacao'}",
                method="heuristica", score=score, sha256=sha,
                details=[f"{p:+d}  {text}" for p, text in reasons]))
        return findings

    def _scan_zip(self, source, display_path: str, depth: int, prefix: str = ""):
        findings: list = []
        reasons: list = []
        try:
            zf = zipfile.ZipFile(source)
        except _ZIP_ERRORS:
            return findings, reasons
        with zf:
            try:
                infos = zf.infolist()
            except _ZIP_ERRORS:
                return findings, reasons
            ooxml = any(i.filename.lower() == "[content_types].xml" for i in infos)
            if ooxml:
                reasons += heuristics.analyze_ooxml(zf, infos)
                members = [i for i in infos if "/embeddings/" in i.filename.lower()]
            else:
                members = infos
            total = 0
            for info in members[:config.ARCHIVE_MAX_ENTRIES]:
                if info.is_dir() or info.flag_bits & 0x1:   # pasta ou protegido por senha
                    continue
                if info.file_size > config.ARCHIVE_MAX_MEMBER:
                    continue
                if total + info.file_size > config.ARCHIVE_MAX_TOTAL:
                    break
                if (info.file_size > 10 * config.MB
                        and info.file_size / max(1, info.compress_size) > config.ARCHIVE_MAX_RATIO):
                    continue
                try:
                    data = zf.read(info)
                except _ZIP_ERRORS:
                    continue
                total += len(data)
                member = f"{prefix} > {info.filename}" if prefix else info.filename
                findings += self._analyze_member(display_path, member, data, depth + 1)
        return findings, reasons

    def _analyze_member(self, display_path: str, inner: str, data: bytes, depth: int) -> list:
        name = inner.rsplit(" > ", 1)[-1].rsplit("/", 1)[-1]
        sha = hashlib.sha256(data).hexdigest()
        head = data[:config.HEAD_BYTES]
        kind = detect_kind(name, head)
        source = io.BytesIO(data) if kind == "zip" else None
        return self._evaluate(display_path, inner, name, kind, head, b"", data, sha,
                              [], depth, source, False)
