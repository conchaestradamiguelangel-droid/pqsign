"""
Ejemplo de uso de pqsign con Flask: exige firma post-cuantica en /webhook y
devuelve una respuesta firmada.
"""

from flask import Flask

from pqsign.flask_ext import require_pq_signature, sign_response

app = Flask(__name__)


@app.route("/status")
def status():
    return sign_response({"ok": True, "service": "pqsign-demo"})


@app.route("/webhook", methods=["POST"])
@require_pq_signature
def webhook():
    return sign_response({"received": True})


if __name__ == "__main__":
    app.run(port=8900)
