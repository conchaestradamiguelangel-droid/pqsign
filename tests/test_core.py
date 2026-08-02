import os
import tempfile

import pytest

pqsign = pytest.importorskip("pqsign")
from pqsign.keys import KeyManager


@pytest.fixture
def km(tmp_path):
    return KeyManager(str(tmp_path / "test.key"))


def test_sign_and_verify_roundtrip(km):
    sig, kid = km.sign(b"hola mundo")
    assert km.verify(b"hola mundo", sig, kid) is True


def test_verify_fails_on_tampered_payload(km):
    sig, kid = km.sign(b"hola mundo")
    assert km.verify(b"hola mundo modificado", sig, kid) is False


def test_verify_fails_on_wrong_signature(km):
    km.sign(b"hola mundo")
    assert km.verify(b"hola mundo", "no-es-una-firma-valida==", km.key_id) is False


def test_key_persists_across_instances(tmp_path):
    path = str(tmp_path / "persist.key")
    km1 = KeyManager(path)
    original_key_id = km1.key_id

    km2 = KeyManager(path)
    assert km2.key_id == original_key_id
    assert km2.public_key_b64 == km1.public_key_b64


def test_rotate_generates_new_active_key_but_keeps_old_verifiable(km):
    sig_old, kid_old = km.sign(b"mensaje antes de rotar")

    new_kid = km.rotate()
    assert new_kid != kid_old
    assert km.key_id == new_kid

    # la firma antigua sigue siendo verificable con su key_id original
    assert km.verify(b"mensaje antes de rotar", sig_old, kid_old) is True

    # y la nueva clave activa firma con normalidad
    sig_new, kid_new = km.sign(b"mensaje despues de rotar")
    assert kid_new == new_kid
    assert km.verify(b"mensaje despues de rotar", sig_new, kid_new) is True


def test_canonical_payload_dict_is_deterministic():
    from pqsign.core import canonical_payload

    a = canonical_payload({"b": 2, "a": 1})
    b = canonical_payload({"a": 1, "b": 2})
    assert a == b


def test_module_level_sign_verify_with_dict_payload(tmp_path, monkeypatch):
    monkeypatch.setenv("PQSIGN_KEY_PATH", str(tmp_path / "module.key"))
    import importlib
    import pqsign.core as core_mod
    importlib.reload(core_mod)
    import pqsign
    importlib.reload(pqsign)

    payload = {"order_id": 42, "total": 19.99}
    sig, kid = pqsign.sign(payload)
    assert pqsign.verify(payload, sig, kid) is True
    assert pqsign.verify({"order_id": 42, "total": 19.98}, sig, kid) is False
