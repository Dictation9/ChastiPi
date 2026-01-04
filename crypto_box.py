import json
import base64
import hashlib
from cryptography.fernet import Fernet, InvalidToken


def derive_key(pin: str, salt: bytes) -> bytes:
    dk = pin.encode("utf-8") + salt
    for _ in range(200_000):
        dk = hashlib.sha256(dk).digest()
    return base64.urlsafe_b64encode(dk)


def hash_pin(pin: str, salt: bytes) -> str:
    return hashlib.sha256(pin.encode("utf-8") + salt).hexdigest()


def encrypt_data(key: bytes, data: dict) -> bytes:
    f = Fernet(key)
    return f.encrypt(json.dumps(data).encode("utf-8"))


def decrypt_data(key: bytes, blob: bytes) -> dict:
    f = Fernet(key)
    raw = f.decrypt(blob)
    return json.loads(raw.decode("utf-8"))


# re-export for convenience in app_ui
CryptoInvalidToken = InvalidToken
