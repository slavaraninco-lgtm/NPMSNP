"""
Database password encryption and decryption utility for MSNP Server.
Ensures passwords in database.db are always stored encrypted (AES/Fernet),
never in plaintext.
"""
import base64
import hashlib
import hmac
import os
import secrets
from typing import Optional

try:
    from cryptography.fernet import Fernet, InvalidToken
    _HAS_CRYPTOGRAPHY = True
except ImportError:
    Fernet = None
    InvalidToken = Exception
    _HAS_CRYPTOGRAPHY = False

ENCRYPTION_PREFIX = "enc:v1:"
DEFAULT_FALLBACK_KEY = "msnp_server_default_master_salt_key_2026"


def _get_fernet_instance(secret_key: str) -> "Fernet":
    """Derives a deterministic 32-byte urlsafe base64 key from secret_key for Fernet."""
    key_bytes = hashlib.sha256(secret_key.encode("utf-8")).digest()
    url_key = base64.urlsafe_b64encode(key_bytes)
    return Fernet(url_key)


def _fallback_encrypt(plaintext: str, secret_key: str) -> str:
    """
    Pure-Python authenticated keystream encryption fallback (AES-CTR-like stream + HMAC-SHA256).
    Used if cryptography package is unavailable.
    """
    pt_bytes = plaintext.encode("utf-8")
    salt = secrets.token_bytes(16)
    # Derive encryption and MAC keys using SHA-256
    enc_key = hashlib.sha256(salt + secret_key.encode("utf-8") + b":enc").digest()
    mac_key = hashlib.sha256(salt + secret_key.encode("utf-8") + b":mac").digest()

    # Generate keystream blocks
    keystream = bytearray()
    counter = 0
    while len(keystream) < len(pt_bytes):
        keystream.extend(hashlib.sha256(enc_key + counter.to_bytes(4, "big")).digest())
        counter += 1

    ciphertext = bytes(p ^ k for p, k in zip(pt_bytes, keystream))
    tag = hmac.new(mac_key, salt + ciphertext, hashlib.sha256).digest()[:16]
    payload = salt + tag + ciphertext
    return base64.urlsafe_b64encode(payload).decode("ascii")


def _fallback_decrypt(token: str, secret_key: str) -> Optional[str]:
    """Decrypts a payload encrypted by _fallback_encrypt."""
    try:
        payload = base64.urlsafe_b64decode(token.encode("ascii"))
        if len(payload) < 32:
            return None
        salt = payload[:16]
        tag = payload[16:32]
        ciphertext = payload[32:]

        mac_key = hashlib.sha256(salt + secret_key.encode("utf-8") + b":mac").digest()
        expected_tag = hmac.new(mac_key, salt + ciphertext, hashlib.sha256).digest()[:16]
        if not hmac.compare_digest(tag, expected_tag):
            return None

        enc_key = hashlib.sha256(salt + secret_key.encode("utf-8") + b":enc").digest()
        keystream = bytearray()
        counter = 0
        while len(keystream) < len(ciphertext):
            keystream.extend(hashlib.sha256(enc_key + counter.to_bytes(4, "big")).digest())
            counter += 1

        pt_bytes = bytes(c ^ k for c, k in zip(ciphertext, keystream))
        return pt_bytes.decode("utf-8", errors="replace")
    except Exception:
        return None


def is_encrypted(value: Optional[str]) -> bool:
    """Checks if the stored string is an encrypted token."""
    if not value:
        return False
    return value.startswith(ENCRYPTION_PREFIX)


def encrypt_password(plaintext: str, secret_key: Optional[str] = None) -> str:
    """
    Encrypts a plaintext password into an encrypted ciphertext string.
    Returns: enc:v1:<token>
    If already encrypted, returns as-is.
    """
    if not plaintext:
        return ""
    if is_encrypted(plaintext):
        return plaintext

    key = secret_key or DEFAULT_FALLBACK_KEY
    if _HAS_CRYPTOGRAPHY and Fernet is not None:
        try:
            f = _get_fernet_instance(key)
            token = f.encrypt(plaintext.encode("utf-8")).decode("ascii")
            return f"{ENCRYPTION_PREFIX}{token}"
        except Exception:
            pass

    # Fallback encryption
    token = _fallback_encrypt(plaintext, key)
    return f"{ENCRYPTION_PREFIX}{token}"


def decrypt_password(ciphertext: str, secret_key: Optional[str] = None) -> str:
    """
    Decrypts an encrypted password string.
    If the string is legacy plaintext (does not start with enc:v1:), returns it as-is.
    """
    if not ciphertext:
        return ""
    if not is_encrypted(ciphertext):
        return ciphertext

    token = ciphertext[len(ENCRYPTION_PREFIX):].strip()
    key = secret_key or DEFAULT_FALLBACK_KEY

    if _HAS_CRYPTOGRAPHY and Fernet is not None:
        try:
            f = _get_fernet_instance(key)
            decrypted = f.decrypt(token.encode("ascii")).decode("utf-8")
            return decrypted
        except (InvalidToken, Exception):
            pass

    # Try fallback decrypt
    fallback_res = _fallback_decrypt(token, key)
    if fallback_res is not None:
        return fallback_res

    # If decryption fails (e.g. wrong key), return raw ciphertext to prevent data loss
    return ciphertext
