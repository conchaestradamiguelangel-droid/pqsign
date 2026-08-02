"""
pqsign.core — API de conveniencia a nivel de modulo sobre KeyManager.

Para la mayoria de casos de uso basta con:

    import pqsign
    sig, key_id = pqsign.sign(b"hola")
    pqsign.verify(b"hola", sig, key_id)

Internamente usa un KeyManager por defecto (fichero ./pqsign.key, o la ruta
indicada por la variable de entorno PQSIGN_KEY_PATH).
"""

from __future__ import annotations

import hashlib
import json
import os

from .keys import KeyManager, DEFAULT_ALGORITHM

_default_manager: KeyManager | None = None


def _get_default_manager() -> KeyManager:
    global _default_manager
    if _default_manager is None:
        key_path = os.environ.get("PQSIGN_KEY_PATH", "./pqsign.key")
        _default_manager = KeyManager(key_path)
    return _default_manager


def canonical_payload(obj) -> bytes:
    """Serializa un dict/list/str/bytes de forma determinista para firmarlo.
    Si ya es bytes o str, se usa tal cual (str se codifica en utf-8)."""
    if isinstance(obj, bytes):
        return obj
    if isinstance(obj, str):
        return obj.encode("utf-8")
    canonical = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return canonical.encode("utf-8")


def sign(payload, manager: KeyManager | None = None) -> tuple[str, str]:
    """Firma cualquier payload (bytes, str, o estructura JSON-serializable).
    Devuelve (signature_b64, key_id)."""
    km = manager or _get_default_manager()
    return km.sign(canonical_payload(payload))


def verify(payload, signature_b64: str, key_id: str | None = None, manager: KeyManager | None = None) -> bool:
    """Verifica una firma para el mismo payload usado al firmar."""
    km = manager or _get_default_manager()
    return km.verify(canonical_payload(payload), signature_b64, key_id)


def public_key_b64(manager: KeyManager | None = None) -> str:
    km = manager or _get_default_manager()
    return km.public_key_b64


def key_id(manager: KeyManager | None = None) -> str:
    km = manager or _get_default_manager()
    return km.key_id


def rotate(manager: KeyManager | None = None) -> str:
    km = manager or _get_default_manager()
    return km.rotate()


def is_available(manager: KeyManager | None = None) -> bool:
    km = manager or _get_default_manager()
    return km.is_available()


def payload_digest(payload) -> str:
    """SHA3-256 hex del payload canonico — util para incluir en logs/headers
    sin exponer el contenido completo."""
    return hashlib.sha3_256(canonical_payload(payload)).hexdigest()
