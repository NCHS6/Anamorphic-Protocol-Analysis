def xor_bytes(a: bytes, b: bytes) -> bytes:
    """Compute xor of two byte strings"""
    
    return (int.from_bytes(a, "big") ^ int.from_bytes(b, "big")).to_bytes(len(a), "big")