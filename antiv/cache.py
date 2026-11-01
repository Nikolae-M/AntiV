# cache SQLite: pula arquivos limpos que nao mudaram desde a ultima varredura

from __future__ import annotations

import logging
import sqlite3
import threading
import os
from pathlib import Path

log = logging.getLogger(__name__)


class ScanCache:
    # Guarda (caminho, tamanho, data) de arquivos limpos
    #
    # O 'fingerprint' muda quando a base de assinaturas/regras muda; entradas
    # antigas deixam de valer automaticamente, entao nada fica "esquecido"

    def __init__(self, path: Path, fingerprint: str) -> None:
        self._lock = threading.Lock()
        self._pending: list[tuple] = []
        self._fp = fingerprint
        self._conn = None
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            conn = sqlite3.connect(str(path), check_same_thread=False, timeout=30)
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=OFF")
            conn.execute(
                "CREATE TABLE IF NOT EXISTS clean ("
                "path TEXT PRIMARY KEY, size INTEGER, mtime_ns INTEGER, "
                "level INTEGER, fp TEXT)"
            )
            conn.commit()
            self._conn = conn
        except sqlite3.Error as exc:
            log.warning("Cache desativado: %s", exc)

    def is_clean(self, path: str, size: int, mtime_ns: int, level: int) -> bool:
        if self._conn is None:
            return False
        try:
            with self._lock:
                row = self._conn.execute(
                    "SELECT 1 FROM clean WHERE path=? AND size=? AND mtime_ns=? "
                    "AND level>=? AND fp=?",
                    (path, size, mtime_ns, level, self._fp),
                ).fetchone()
            return row is not None
        except sqlite3.Error:
            return False

    def mark_clean(self, path: str, size: int, mtime_ns: int, level: int) -> None:
        if self._conn is None:
            return
        with self._lock:
            self._pending.append((path, size, mtime_ns, level, self._fp))
            if len(self._pending) >= 500:
                self._flush_locked()

    def _flush_locked(self) -> None:
        if not self._pending or self._conn is None:
            return
        try:
            self._conn.executemany(
                "INSERT OR REPLACE INTO clean VALUES (?,?,?,?,?)", self._pending
            )
            self._conn.commit()
        except sqlite3.Error as exc:
            log.warning("Falha ao gravar cache: %s", exc)
        self._pending.clear()

    def close(self) -> None:
        with self._lock:
            self._flush_locked()
            if self._conn is not None:
                self._conn.close()
                self._conn = None
