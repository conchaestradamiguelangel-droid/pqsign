"""
pqsign.keys — Gestion de claves post-cuanticas con soporte de rotacion.

Guarda un historial de pares de claves en un unico fichero JSON. La clave
activa firma; todas las claves del historial (activas o no) se pueden usar
para verificar, de forma que rotar una clave no invalida firmas antiguas.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import threading
import time
from dataclasses import dataclass, field

DEFAULT_ALGORITHM = "ML-DSA-87"


@dataclass
class KeyRecord:
    key_id: str
    algorithm: str
    public_key: bytes
    private_key: bytes
    created_at: float
    active: bool = True

    def to_json(self) -> dict:
        return {
            "key_id": self.key_id,
            "algorithm": self.algorithm,
            "public_key": base64.b64encode(self.public_key).decode(),
            "private_key": base64.b64encode(self.private_key).decode(),
            "created_at": self.created_at,
            "active": self.active,
        }

    @staticmethod
    def from_json(data: dict) -> "KeyRecord":
        return KeyRecord(
            key_id=data["key_id"],
            algorithm=data["algorithm"],
            public_key=base64.b64decode(data["public_key"]),
            private_key=base64.b64decode(data["private_key"]),
            created_at=data["created_at"],
            active=data.get("active", True),
        )


def _compute_key_id(public_key: bytes) -> str:
    return hashlib.sha256(public_key).digest()[:16].hex()


class KeyManager:
    """
    Gestiona un historial de pares de claves ML-DSA-87 (u otro algoritmo PQC
    soportado por liboqs), con generacion perezosa, persistencia en disco y
    rotacion sin invalidar firmas antiguas.

    Uso basico:
        km = KeyManager("./data/pqsign.key")
        sig = km.sign(b"hola mundo")
        km.verify(b"hola mundo", sig)  # True

    Rotacion:
        km.rotate()  # genera una nueva clave activa; las antiguas siguen
                     # disponibles para verificar (marcadas active=False)
    """

    def __init__(self, key_path: str, algorithm: str = DEFAULT_ALGORITHM):
        self.key_path = key_path
        self.algorithm = algorithm
        self._lock = threading.Lock()
        self._records: dict[str, KeyRecord] = {}
        self._active_key_id: str | None = None
        self._load_or_bootstrap()

    # ------------------------------------------------------------------ #
    # Persistencia
    # ------------------------------------------------------------------ #

    def _load_or_bootstrap(self) -> None:
        if os.path.exists(self.key_path):
            with open(self.key_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            for rec in data.get("keys", []):
                record = KeyRecord.from_json(rec)
                self._records[record.key_id] = record
                if record.active:
                    self._active_key_id = record.key_id
            if self._active_key_id is None and self._records:
                # fichero corrupto/editado a mano: activa la mas reciente
                newest = max(self._records.values(), key=lambda r: r.created_at)
                newest.active = True
                self._active_key_id = newest.key_id
        if self._active_key_id is None:
            self._generate_new_active_key()
        else:
            self._save()

    def _save(self) -> None:
        os.makedirs(os.path.dirname(os.path.abspath(self.key_path)) or ".", exist_ok=True)
        payload = {"keys": [r.to_json() for r in self._records.values()]}
        tmp_path = f"{self.key_path}.tmp"
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)
        os.replace(tmp_path, self.key_path)

    # ------------------------------------------------------------------ #
    # Generacion / rotacion
    # ------------------------------------------------------------------ #

    def _generate_new_active_key(self) -> KeyRecord:
        import oqs

        with oqs.Signature(self.algorithm) as signer:
            public_key = signer.generate_keypair()
            private_key = signer.export_secret_key()

        record = KeyRecord(
            key_id=_compute_key_id(public_key),
            algorithm=self.algorithm,
            public_key=public_key,
            private_key=private_key,
            created_at=time.time(),
            active=True,
        )
        self._records[record.key_id] = record
        self._active_key_id = record.key_id
        self._save()
        return record

    def rotate(self) -> str:
        """Genera una nueva clave activa. Las claves anteriores quedan
        marcadas como inactivas pero se conservan para poder verificar
        firmas antiguas. Devuelve el key_id de la nueva clave activa."""
        with self._lock:
            for record in self._records.values():
                record.active = False
            new_record = self._generate_new_active_key()
            return new_record.key_id

    # ------------------------------------------------------------------ #
    # Acceso
    # ------------------------------------------------------------------ #

    @property
    def active_key(self) -> KeyRecord:
        return self._records[self._active_key_id]

    @property
    def key_id(self) -> str:
        return self.active_key.key_id

    @property
    def public_key_b64(self) -> str:
        return base64.b64encode(self.active_key.public_key).decode()

    def public_key_b64_for(self, key_id: str) -> str | None:
        record = self._records.get(key_id)
        return base64.b64encode(record.public_key).decode() if record else None

    def list_key_ids(self) -> list[str]:
        return list(self._records.keys())

    # ------------------------------------------------------------------ #
    # Firma / verificacion
    # ------------------------------------------------------------------ #

    def sign(self, payload: bytes) -> tuple[str, str]:
        """Firma payload con la clave activa. Devuelve (signature_b64, key_id)."""
        import oqs

        record = self.active_key
        with oqs.Signature(self.algorithm, secret_key=record.private_key) as signer:
            signature = signer.sign(payload)
        return base64.b64encode(signature).decode(), record.key_id

    def verify(self, payload: bytes, signature_b64: str, key_id: str | None = None) -> bool:
        """Verifica payload contra una firma. Si no se da key_id, prueba con
        la clave activa; si se da, usa esa clave concreta del historial
        (permite verificar firmas hechas con claves ya rotadas)."""
        import oqs

        record = self._records.get(key_id) if key_id else self.active_key
        if record is None:
            return False
        try:
            signature = base64.b64decode(signature_b64)
        except Exception:
            return False
        with oqs.Signature(self.algorithm) as verifier:
            return verifier.verify(payload, signature, record.public_key)

    def is_available(self) -> bool:
        try:
            import oqs  # noqa: F401
        except ImportError:
            return False
        return self._active_key_id is not None
