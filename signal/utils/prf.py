import hmac
import hashlib


def prf(dkey: bytes, data: bytes, outlen=2) -> bytes:
    """Keyed PRF truncated to outlen bytes (16-bit covert)"""
    return hmac.new(dkey, data, hashlib.sha256).digest()[:outlen]
