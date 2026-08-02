"""
pqsign.flask_ext — Decorador de Flask para exigir peticiones firmadas y
helper para firmar respuestas salientes con criptografia post-cuantica.

Uso:

    from flask import Flask, jsonify
    from pqsign.flask_ext import require_pq_signature, sign_response

    app = Flask(__name__)

    @app.route("/webhook", methods=["POST"])
    @require_pq_signature
    def webhook():
        return sign_response({"ok": True})
"""

from __future__ import annotations

import functools

from .keys import KeyManager
from .core import _get_default_manager

SIGNATURE_HEADER = "X-PQ-Signature"
KEY_ID_HEADER = "X-PQ-Key-Id"


def require_pq_signature(view_func=None, *, manager: KeyManager | None = None):
    """Decorador Flask: exige una firma PQ valida sobre el cuerpo exacto de
    la peticion entrante en las cabeceras X-PQ-Signature / X-PQ-Key-Id."""

    def decorator(fn):
        @functools.wraps(fn)
        def wrapped(*args, **kwargs):
            from flask import request, abort

            km = manager or _get_default_manager()
            signature_b64 = request.headers.get(SIGNATURE_HEADER)
            key_id = request.headers.get(KEY_ID_HEADER)
            if not signature_b64:
                abort(401, description=f"Falta cabecera {SIGNATURE_HEADER}")
            if not km.verify(request.get_data(), signature_b64, key_id):
                abort(401, description="Firma post-cuantica invalida")
            return fn(*args, **kwargs)

        return wrapped

    if view_func is not None:
        return decorator(view_func)
    return decorator


def sign_response(payload, manager: KeyManager | None = None):
    """Construye una respuesta Flask (JSON) firmada, con X-PQ-Signature /
    X-PQ-Key-Id en las cabeceras."""
    from flask import jsonify

    from .core import canonical_payload

    km = manager or _get_default_manager()
    body = canonical_payload(payload)
    signature_b64, kid = km.sign(body)

    resp = jsonify(payload)
    resp.headers[SIGNATURE_HEADER] = signature_b64
    resp.headers[KEY_ID_HEADER] = kid
    return resp
