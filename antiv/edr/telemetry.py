# telemetria: registra eventos (JSON Lines) e mantem um buffer para a interface

from __future__ import annotations

import json
import logging
import os
import threading
import time
from collections import deque
from pathlib import Path
from typing import Optional

from .. import config

log = logging.getLogger(__name__)


class Telemetry:
    def __init__(self, path: Optional[Path] = config.TELEMETRY_FILE, ring: int = 5000,
                 max_bytes: int = 20 * config.MB, keep: int = 3) -> None:
        self._lock = threading.Lock()
        self._ring: deque = deque(maxlen=ring)
        self._seq = 0
        self._path = Path(path) if path else None
        self._max_bytes = max_bytes
        self._keep = keep
        self._fh = None
        if self._path:
            try:
                self._path.parent.mkdir(parents=True, exist_ok=True)
                self._fh = open(self._path, "a", encoding="utf-8")
            except OSError as exc:
                log.warning("Telemetria em disco desativada: %s", exc)

    def log(self, etype: str, **fields) -> dict:
        with self._lock:
            self._seq += 1
            event = {"seq": self._seq, "ts": round(time.time(), 3), "type": etype, **fields}
            self._ring.append(event)
            if self._fh:
                try:
                    self._fh.write(json.dumps(event, ensure_ascii=False, default=str) + "\n")
                    self._fh.flush()
                    if self._fh.tell() > self._max_bytes:
                        self._rotate()
                except OSError:
                    pass
            return event

    def since(self, seq: int) -> tuple:
        # Eventos com numero maior que seq: (ultimo_seq, [eventos])
        with self._lock:
            fresh = [e for e in self._ring if e["seq"] > seq]
            return self._seq, fresh

    def _rotate(self) -> None:
        self._fh.close()
        for i in range(self._keep - 1, 0, -1):
            older = Path(f"{self._path}.{i}")
            if older.exists():
                os.replace(older, f"{self._path}.{i + 1}")
        os.replace(self._path, f"{self._path}.1")
        self._fh = open(self._path, "a", encoding="utf-8")

    def close(self) -> None:
        with self._lock:
            if self._fh:
                self._fh.close()
                self._fh = None
