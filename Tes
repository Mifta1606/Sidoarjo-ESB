import os
import hashlib
import hmac
import time
import requests
from flask import Flask, request, jsonify

app = Flask(__name__)

SIGNING_SECRET = os.environ.get("SIGNING_SECRET", "")
APP_ID = os.environ.get("APP_ID", "")
APP_SECRET = os.environ.get("APP_SECRET", "")

_token = {"value": None, "exp": 0}


def verifikasi_signature(body: bytes, signature: str) -> bool:
    # SeaTalk: signature = sha256(body + signing_secret) dalam hex
    expected = hashlib.sha256(body + SIGNING_SECRET.encode()).hexdigest()
    return hmac.compare_digest(expected, signature or "")


def get_token():
    if _token["value"] and time.time() < _token["exp"] - 60:
        return _token["value"]
    r = requests.post(
        "https://openapi.seatalk.io/auth/app_access_token",
        json={"app_id": APP_ID, "app_secret": APP_SECRET},
        timeout=10,
    )
    data = r.json()
    _token["value"] = data["app_access_token"]
    _token["exp"] = data.get("expire", time.time() + 7000)
    return _token["value"]


def balas_ke_user(employee_code, teks):
    requests.post(
        "https://openapi.seatalk.io/messaging/v2/single_chat",
        headers={"Authorization": f"Bearer {get_token()}"},
        json={
            "employee_code": employee_code,
            "message": {"tag": "text", "text": {"content": teks}},
        },
        timeout=10,
    )


@app.route("/")
def home():
    return "Bot aktif"


@app.route("/callback", methods=["POST"])
def callback():
    body = request.get_data()
    signature = request.headers.get("Signature", "")

    if not verifikasi_signature(body, signature):
        return "invalid signature", 403

    data = request.get_json(silent=True) or {}
    event_type = data.get("event_type")

    # Verifikasi URL saat pertama kali didaftarkan
    if event_type == "event_verification":
        return jsonify({"seatalk_challenge": data["event"]["seatalk_challenge"]})

    # Pesan dari user ke bot
    if event_type == "message_from_bot_subscriber":
        event = data.get("event", {})
        kode = event.get("employee_code")
        teks = event.get("message", {}).get("text", {}).get("content", "")
        if kode:
            balas_ke_user(kode, f"Pesan diterima: {teks}")

    return jsonify({"ok": True})
