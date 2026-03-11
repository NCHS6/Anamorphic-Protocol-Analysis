def xor_bytes(a: bytes, b: bytes) -> bytes:
    """Compute xor of two byte strings"""
    
    return bytes(x ^ y for x, y in zip(a, b))