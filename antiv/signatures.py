# Base de assinaturas: hashes SHA-256 e regras de padroes de bytes

from __future__ import annotations

import hashlib
import json
import logging
import re
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional

from . import config

log = logging.getLogger(__name__)

_HEX64 = re.compile(r"(?<![0-9a-fA-F])[0-9a-fA-F]{64}(?![0-9a-fA-F])")


# hashes
class SignatureDB:
    """Hash SHA-256 -> nome da ameaca (signatures.json + data/hashes/*.txt)."""

    def __init__(self) -> None:
        self.signatures: dict[str, str] = {}
        self._load_json(config.SIGNATURES_FILE)
        self._load_lists(config.HASH_LISTS_DIR)
        log.info("%d assinaturas de hash carregadas.", len(self.signatures))

    def _load_json(self, path: Path) -> None:
        try:
            with open(path, "r", encoding="utf-8") as fh:
                raw = json.load(fh)
        except FileNotFoundError:
            return
        except (OSError, json.JSONDecodeError) as exc:
            log.error("Falha ao carregar %s: %s", path, exc)
            raise
        for key, value in raw.items():
            if not key.startswith("_"):
                self.signatures[key.lower()] = value

    def _load_lists(self, folder: Path) -> None:
        if not folder.is_dir():
            return
        for path in sorted(folder.glob("*.txt")):
            label = f"Lista:{path.stem}"
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                    for line in fh:
                        match = _HEX64.search(line)
                        if match:
                            self.signatures.setdefault(match.group(0).lower(), label)
            except OSError as exc:
                log.warning("Nao foi possivel ler %s: %s", path, exc)

    def lookup(self, sha256: str) -> Optional[str]:
        return self.signatures.get(sha256)

    def __len__(self) -> int:
        return len(self.signatures)

    @staticmethod
    def import_hash_file(source: Path) -> int:
        # Importa uma lista (txt/csv) com hashes SHA-256. Retorna quantos achou.
        found: list[str] = []
        with open(source, "r", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                match = _HEX64.search(line)
                if match:
                    found.append(match.group(0).lower())
        if not found:
            raise ValueError("Nenhum hash SHA-256 (64 caracteres hex) encontrado no arquivo.")
        config.HASH_LISTS_DIR.mkdir(parents=True, exist_ok=True)
        dest = config.HASH_LISTS_DIR / f"{source.stem}.txt"
        dest.write_text("\n".join(dict.fromkeys(found)) + "\n", encoding="utf-8")
        return len(set(found))


# Regras de padroes de bytes
class ScanBuffer:
    """Bytes a analisar; guarda uma copia minuscula criada sob demanda."""

    __slots__ = ("raw", "_lower")

    def __init__(self, raw: bytes) -> None:
        self.raw = raw
        self._lower: Optional[bytes] = None

    @property
    def lower(self) -> bytes:
        if self._lower is None:
            self._lower = self.raw.lower()
        return self._lower


@dataclass(frozen=True)
class Rule:
    id: str
    name: str
    severity: str                  # alta | suspeito | info
    kinds: frozenset
    nocase: bool
    any_of: tuple
    also: tuple
    description: str


def _patterns(texts: Iterable[str], hexes: Iterable[str], nocase: bool, wide: bool) -> tuple:
    out: list[bytes] = []
    for text in texts:
        if nocase:
            text = text.lower()
        out.append(text.encode("utf-8"))
        if wide:
            out.append(text.encode("utf-16-le"))
    for item in hexes:
        data = bytes.fromhex(item)
        out.append(data.lower() if nocase else data)
    return tuple(p for p in out if p)


class RuleSet:
    """Conjunto de regras indexado pelo tipo de arquivo."""

    def __init__(self, rules: Iterable[Rule]) -> None:
        self.rules = list(rules)
        self._by_kind: dict[str, list[Rule]] = {}
        self._any = [r for r in self.rules if "any" in r.kinds]
        for rule in self.rules:
            for kind in rule.kinds - {"any"}:
                self._by_kind.setdefault(kind, []).append(rule)
        self._max_len = max(
            (len(p) for r in self.rules for p in r.any_of + r.also), default=0
        )

    @classmethod
    def load(cls, path: Path = config.RULES_FILE) -> "RuleSet":
        try:
            with open(path, "r", encoding="utf-8") as fh:
                raw = json.load(fh)
        except FileNotFoundError:
            log.warning("Arquivo de regras nao encontrado: %s", path)
            return cls([])
        rules = []
        for spec in raw.get("rules", []):
            nocase = bool(spec.get("nocase", False))
            wide = bool(spec.get("wide", False))
            any_of = _patterns(spec.get("strings", []), spec.get("hex", []), nocase, wide)
            also = _patterns(spec.get("also", []), spec.get("also_hex", []), nocase, wide)
            if not any_of:
                continue
            rules.append(Rule(
                id=spec["id"], name=spec["name"], severity=spec.get("severity", "suspeito"),
                kinds=frozenset(spec.get("kinds", ["any"])), nocase=nocase,
                any_of=any_of, also=also, description=spec.get("description", ""),
            ))
        log.info("%d regras carregadas.", len(rules))
        return cls(rules)

    def max_pattern_len(self) -> int:
        return min(self._max_len, 512)

    def match(self, kind: str, buf: ScanBuffer) -> list[Rule]:
        hits = []
        for rule in self._by_kind.get(kind, []) + self._any:
            data = buf.lower if rule.nocase else buf.raw
            if any(p in data for p in rule.any_of) and (
                not rule.also or any(p in data for p in rule.also)
            ):
                hits.append(rule)
        return hits


def content_fingerprint() -> str:
    # Identifica a versao da base + analisador (para invalidar o cache)
    digest = hashlib.sha256(config.ANALYZER_VERSION.encode())
    for path in (config.SIGNATURES_FILE, config.RULES_FILE):
        try:
            digest.update(path.read_bytes())
        except OSError:
            pass
    if config.HASH_LISTS_DIR.is_dir():
        for path in sorted(config.HASH_LISTS_DIR.glob("*.txt")):
            st = path.stat()
            digest.update(f"{path.name}:{st.st_size}:{st.st_mtime_ns}".encode())
    return digest.hexdigest()[:16]
