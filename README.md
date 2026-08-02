# pqsign

Firma digital post-cuántica (**ML-DSA-87**, NIST FIPS 204) lista para usar en
Python, con gestión de claves y rotación incluida, e integración directa para
**FastAPI** y **Flask**.

Verificado extremo a extremo (no solo en tests unitarios): firma y
verificación reales, rechazo correcto de peticiones sin firmar/manipuladas,
aceptación de peticiones correctamente firmadas, y rotación de claves sin
invalidar firmas antiguas.

## Por qué esto y no una llamada directa a liboqs

`liboqs`/`liboqs-python` te da el algoritmo, pero no:

- gestión de claves con persistencia y **rotación sin romper verificaciones antiguas**,
- una API de una línea para firmar cualquier objeto Python (no solo bytes),
- middleware listo para **FastAPI** (firma automática de toda respuesta saliente + dependency para exigir peticiones firmadas) y **Flask** (decorador equivalente).

Esto es la parte que normalmente te toca escribir tú a mano — aquí ya está
hecha, probada y documentada.

## Instalación

```bash
pip install pqsign              # core
pip install pqsign[fastapi]     # + integración FastAPI
pip install pqsign[flask]       # + integración Flask
```

## Uso básico

```python
import pqsign

sig, key_id = pqsign.sign({"order_id": 42, "total": 19.99})
pqsign.verify({"order_id": 42, "total": 19.99}, sig, key_id)  # True
```

Por defecto guarda las claves en `./pqsign.key` (configurable con la variable
de entorno `PQSIGN_KEY_PATH`).

## Rotación de claves

```python
pqsign.rotate()  # nueva clave activa; las firmas hechas con la clave
                 # anterior siguen siendo verificables usando su key_id
```

## FastAPI

```python
from fastapi import FastAPI, Depends
from pqsign.fastapi_ext import PQSignMiddleware, require_pq_signature

app = FastAPI()
app.add_middleware(PQSignMiddleware)  # firma toda respuesta saliente

@app.post("/webhook")
async def webhook(_ok: bool = Depends(require_pq_signature)):
    ...  # solo se ejecuta si la peticion viene firmada y es valida
```

Ver `examples/fastapi_example.py` para un ejemplo completo y ejecutable.

## Flask

```python
from flask import Flask
from pqsign.flask_ext import require_pq_signature, sign_response

app = Flask(__name__)

@app.route("/webhook", methods=["POST"])
@require_pq_signature
def webhook():
    return sign_response({"ok": True})
```

## API de bajo nivel (`KeyManager`)

Si necesitas varias claves independientes (por ejemplo, una por servicio o
tenant):

```python
from pqsign.keys import KeyManager

km = KeyManager("./data/servicio_a.key")
sig, key_id = km.sign(b"payload en bytes")
km.verify(b"payload en bytes", sig, key_id)
```

## Tests

```bash
pip install -e .[dev]
pytest
```

## Licencia

MIT.
