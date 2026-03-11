import hmac
import hashlib

def prf(dkey: bytes, ctr: int) -> bytes:
    """Compute Pseudo-random bit string"""
    
    ctr_bytes = ctr.to_bytes(4, "big")

    # Compute HMAC-SHA256(dkey, ctr) to act as a PRF.
    mac = hmac.new(dkey, ctr_bytes, hashlib.sha256)

    # HMAC-SHA256 outputs 32 bytes, but AES-GCM expects a 96-bit (12 byte) IV.
    # We therefore truncate the output to the first 12 bytes so it can be used
    # as the IV mask in the anamorphic construction. Truncation of a PRF output
    # preserves pseudorandomness for shorter lengths, so the resulting 96-bit
    # value remains suitable for use as a nonce mask.
    return mac.digest()[:12] 
