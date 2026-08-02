"""
pqsign — Firma digital post-cuantica (ML-DSA-87 / NIST FIPS 204) lista para
usar en Python, con gestion de claves y rotacion incluida, y extensiones
para FastAPI y Flask.

Uso rapido:

    import pqsign
    sig, kid = pqsign.sign({"order_id": 42, "total": 19.99})
    pqsign.verify({"order_id": 42, "total": 19.99}, sig, kid)  # True
"""

from .keys import KeyManager, KeyRecord, DEFAULT_ALGORITHM
from .core import (
    sign,
    verify,
    public_key_b64,
    key_id,
    rotate,
    is_available,
    payload_digest,
    canonical_payload,
)

__all__ = [
    "KeyManager",
    "KeyRecord",
    "DEFAULT_ALGORITHM",
    "sign",
    "verify",
    "public_key_b64",
    "key_id",
    "rotate",
    "is_available",
    "payload_digest",
    "canonical_payload",
]

__version__ = "0.1.0"
