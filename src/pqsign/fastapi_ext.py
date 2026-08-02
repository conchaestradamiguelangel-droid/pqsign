"""
pqsign.fastapi_ext — Middleware de FastAPI para firmar respuestas y verificar
peticiones firmadas con criptografia post-cuantica (ML-DSA-87 por defecto).

Uso:

    from fastapi import FastAPI
    from pqsign.fastapi_ext import PQSignMiddleware, require_pq_signature

    app = FastAPI()
    app.add_middleware(PQSignMiddleware)  # firma toda respuesta saliente

    @app.post("/webhook")
    async def webhook(payload: dict, _=Depends(require_pq_signature)):
        ...  # solo se ejecuta si la peticion viene firmada y valida
"""

from __future__ import annotations

from typing import Callable

from fastapi import Request

from .keys import KeyManager
from .core import _get_default_manager, canonical_payload

SIGNATURE_HEADER = "X-PQ-Signature"
KEY_ID_HEADER = "X-PQ-Key-Id"


class PQSignMiddleware:
    """Middleware ASGI que firma el cuerpo de cada respuesta saliente y
    añade `X-PQ-Signature` / `X-PQ-Key-Id` como cabeceras HTTP."""

    def __init__(self, app, manager: KeyManager | None = None):
        self.app = app
        self.manager = manager

    def _km(self) -> KeyManager:
        return self.manager or _get_default_manager()

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        body_chunks: list[bytes] = []
        start_message: dict | None = None

        async def send_wrapper(message):
            nonlocal start_message
            if message["type"] == "http.response.start":
                start_message = message
                return
            if message["type"] == "http.response.body":
                body_chunks.append(message.get("body", b""))
                if not message.get("more_body", False):
                    full_body = b"".join(body_chunks)
                    signature_b64, kid = self._km().sign(full_body)

                    headers = list(start_message.get("headers", []))
                    headers.append((SIGNATURE_HEADER.encode(), signature_b64.encode()))
                    headers.append((KEY_ID_HEADER.encode(), kid.encode()))
                    start_message["headers"] = headers

                    await send(start_message)
                    await send({
                        "type": "http.response.body",
                        "body": full_body,
                        "more_body": False,
                    })
                return
            await send(message)

        await self.app(scope, receive, send_wrapper)


async def _verify_request(request: Request, manager: KeyManager | None) -> bool:
    from fastapi import HTTPException

    km = manager or _get_default_manager()
    signature_b64 = request.headers.get(SIGNATURE_HEADER)
    key_id = request.headers.get(KEY_ID_HEADER)
    if not signature_b64:
        raise HTTPException(status_code=401, detail=f"Falta cabecera {SIGNATURE_HEADER}")

    body = await request.body()
    if not km.verify(body, signature_b64, key_id):
        raise HTTPException(status_code=401, detail="Firma post-cuantica invalida")
    return True


async def require_pq_signature(request: Request) -> bool:
    """Dependency de FastAPI: exige que la peticion entrante lleve una firma
    PQ valida en las cabeceras X-PQ-Signature / X-PQ-Key-Id sobre el cuerpo
    exacto de la peticion. Lanza HTTPException(401) si falta o no es valida.
    Usa el KeyManager por defecto — para uno concreto, usa
    make_signature_dependency(manager).

    Uso: @app.post("/x")
         async def handler(payload: dict, _ok: bool = Depends(require_pq_signature)):
    """
    return await _verify_request(request, manager=None)


def make_signature_dependency(manager: KeyManager) -> Callable:
    """Fabrica de dependency para usar un KeyManager concreto (en vez del
    manager por defecto) en `Depends(...)`."""

    async def _dependency(request: Request) -> bool:
        return await _verify_request(request, manager=manager)

    return _dependency
