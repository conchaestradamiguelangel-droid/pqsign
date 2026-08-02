"""
Ejemplo de uso de pqsign con FastAPI: toda respuesta saliente se firma con
ML-DSA-87 automaticamente (cabeceras X-PQ-Signature / X-PQ-Key-Id), y el
endpoint /webhook exige que la peticion entrante venga firmada.
"""

from fastapi import FastAPI, Depends

from pqsign.fastapi_ext import PQSignMiddleware, require_pq_signature

app = FastAPI()
app.add_middleware(PQSignMiddleware)


@app.get("/status")
async def status():
    return {"ok": True, "service": "pqsign-demo"}


@app.post("/webhook")
async def webhook(_ok: bool = Depends(require_pq_signature)):
    return {"received": True}
