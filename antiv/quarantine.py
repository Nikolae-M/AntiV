# Quarentena: move o arquivo, ofusca o conteudo e troca a extensao

from __future__ import annotations

import json
import logging
import os
import threading
import uuid
from datetime import datetime
from pathlib import Path

from . import config

log = logging.getLogger(__name__)
_LOCK = threading.Lock()


def _xor_copy(src: Path, dst: Path) -> None:
    # copia aplicando XOR (reversivel; impede a execucao acidental)
    table = bytes(b ^ config.XOR_KEY for b in range(256))
    with open(src, "rb") as fin, open(dst, "wb") as fout:
        for chunk in iter(lambda: fin.read(config.MB), b""):
            fout.write(chunk.translate(table))


class QuarantineManager:
    def __init__(self) -> None:
        config.QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)

    def _load_index(self) -> dict:
        try:
            with open(config.QUARANTINE_INDEX, "r", encoding="utf-8") as fh:
                return json.load(fh)
        except FileNotFoundError:
            return {}
        except json.JSONDecodeError:
            log.error("Indice de quarentena corrompido.")
            return {}

    def _save_index(self, index: dict) -> None:
        with open(config.QUARANTINE_INDEX, "w", encoding="utf-8") as fh:
            json.dump(index, fh, indent=2, ensure_ascii=False)

    def quarantine(self, file_path: Path, threat: str, sha256: str) -> str:
        # Isola o arquivo. Retorna o ID; levanta OSError se falhar.
        item_id = uuid.uuid4().hex
        dest = config.QUARANTINE_DIR / f"{item_id}{config.QUARANTINE_EXT}"
        _xor_copy(file_path, dest)
        try:
            os.remove(file_path)
        except OSError:
            dest.unlink(missing_ok=True)   # evita duplicata se nao der para remover
            raise
        with _LOCK:
            index = self._load_index()
            index[item_id] = {
                "original_path": str(file_path), "threat": threat, "sha256": sha256,
                "quarantined_at": datetime.now().isoformat(timespec="seconds"),
            }
            self._save_index(index)
        log.info("Arquivo %s em quarentena (%s).", file_path, item_id)
        return item_id

    def list_items(self) -> dict:
        with _LOCK:
            return self._load_index()

    def restore(self, item_id: str) -> Path:
        with _LOCK:
            index = self._load_index()
            entry = index.get(item_id)
            if entry is None:
                raise KeyError(f"ID nao encontrado: {item_id}")
            src = config.QUARANTINE_DIR / f"{item_id}{config.QUARANTINE_EXT}"
            original = Path(entry["original_path"])
            original.parent.mkdir(parents=True, exist_ok=True)
            _xor_copy(src, original)
            src.unlink(missing_ok=True)
            del index[item_id]
            self._save_index(index)
        return original

    def delete(self, item_id: str) -> None:
        # Remove definitivamente um item da quarentena
        with _LOCK:
            index = self._load_index()
            if item_id not in index:
                raise KeyError(f"ID nao encontrado: {item_id}")
            (config.QUARANTINE_DIR / f"{item_id}{config.QUARANTINE_EXT}").unlink(missing_ok=True)
            del index[item_id]
            self._save_index(index)
