# Logs e relatorios de varredura (.txt e .json)

from __future__ import annotations

import json
import logging
import threading
from collections import Counter
from dataclasses import asdict, dataclass, field
from datetime import datetime

from . import config

MAX_PROBLEMS = 2000
LEVEL_ORDER = {"alta": 0, "suspeito": 1, "info": 2}


def setup_logging(verbose: bool = False, gui: bool = False) -> None:
    config.LOGS_DIR.mkdir(parents=True, exist_ok=True)
    handlers: list = [logging.FileHandler(config.LOGS_DIR / "antiv.log", encoding="utf-8")]
    if not gui:  # pythonw nao tem console
        handlers.append(logging.StreamHandler())
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        handlers=handlers, force=True,
    )


@dataclass
class Finding:
    """Uma deteccao. level: alta (certeza) | suspeito (heuristica) | info."""

    path: str
    level: str
    name: str
    method: str
    inner: str = ""            # caminho dentro de um arquivo compactado
    score: int = 0
    sha256: str = ""
    details: list = field(default_factory=list)
    action: str = "nenhuma"

    @property
    def display_path(self) -> str:
        return f"{self.path}  >>  {self.inner}" if self.inner else self.path


class ScanReport:
    def __init__(self, targets: list | None = None) -> None:
        self._lock = threading.Lock()
        self.targets = targets or []
        self.mode = ""
        self.disk_type = ""
        self.workers = 0
        self.started_at = datetime.now().isoformat(timespec="seconds")
        self.finished_at = ""
        self.duration_s = 0.0
        self.cancelled = False
        self.files_discovered = 0
        self.files_scanned = 0
        self.files_cached = 0
        self.files_skipped = 0
        self.bytes_read = 0
        self.errors = 0
        self.findings: list[Finding] = []
        self.problems: list[dict] = []

    # coleta (thread-safe)
    def add_findings(self, items: list) -> None:
        with self._lock:
            self.findings.extend(items)

    def add_problem(self, path: str, message: str) -> None:
        with self._lock:
            if len(self.problems) < MAX_PROBLEMS:
                self.problems.append({"path": path, "error": message})

    # consultas
    @property
    def threats(self) -> list:
        return [f for f in self.findings if f.level in ("alta", "suspeito")]

    def to_dict(self) -> dict:
        return {
            "targets": self.targets, "mode": self.mode, "disk_type": self.disk_type,
            "workers": self.workers, "started_at": self.started_at,
            "finished_at": self.finished_at, "duration_s": round(self.duration_s, 1),
            "cancelled": self.cancelled, "files_discovered": self.files_discovered,
            "files_scanned": self.files_scanned, "files_cached": self.files_cached,
            "files_skipped": self.files_skipped, "bytes_read": self.bytes_read,
            "errors": self.errors,
            "findings": [asdict(f) for f in self.findings],
            "problems": self.problems,
        }

    def to_text(self) -> str:
        mb = self.bytes_read / (1024 * 1024)
        speed = mb / self.duration_s if self.duration_s else 0
        lines = [
            "=== RELATORIO DE VARREDURA AntiV ===",
            f"Alvo(s):             {', '.join(self.targets)}",
            f"Modo / disco:        {self.mode} / {self.disk_type} ({self.workers} threads)",
            f"Inicio:              {self.started_at}",
            f"Fim:                 {self.finished_at}"
            + ("  (INTERROMPIDA pelo usuario)" if self.cancelled else ""),
            f"Duracao:             {self.duration_s:.1f} s",
            f"Arquivos encontrados:{self.files_discovered}",
            f"Arquivos analisados: {self.files_scanned}",
            f"Pulados pelo cache:  {self.files_cached}",
            f"Ignorados:           {self.files_skipped}",
            f"Dados lidos:         {mb:.1f} MB ({speed:.1f} MB/s)",
            f"Erros de acesso:     {self.errors}",
            f"Ameacas/suspeitos:   {len(self.threats)}",
            "",
        ]
        by_method = Counter(f.method for f in self.findings)
        if by_method:
            lines.append("Deteccoes por metodo: " + ", ".join(f"{m}: {n}" for m, n in by_method.items()))
            lines.append("")
        for f in sorted(self.findings, key=lambda x: LEVEL_ORDER.get(x.level, 9)):
            lines.append(f"[{f.level.upper()}] {f.name} | {f.method} | pontos={f.score} | {f.display_path}")
            for d in f.details:
                lines.append(f"      - {d}")
            if f.action != "nenhuma":
                lines.append(f"      acao: {f.action}")
        if self.problems:
            lines.append("")
            lines.append(f"Problemas de acesso (primeiros {min(len(self.problems), 100)}):")
            for p in self.problems[:100]:
                lines.append(f"[ERRO] {p['path']} -> {p['error']}")
        return "\n".join(lines) + "\n"

    def save(self, fmt: str = "both") -> list:
        config.REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        saved = []
        if fmt in ("json", "both"):
            p = config.REPORTS_DIR / f"scan_{stamp}.json"
            p.write_text(json.dumps(self.to_dict(), indent=2, ensure_ascii=False), encoding="utf-8")
            saved.append(p)
        if fmt in ("txt", "both"):
            p = config.REPORTS_DIR / f"scan_{stamp}.txt"
            p.write_text(self.to_text(), encoding="utf-8")
            saved.append(p)
        return saved
