from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes



def kdf_root(rk, dh_out):
    """Root KDF for asymmetric ratchet"""

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=64,
        salt=rk,
        info=b"root_ratchet"
    )
    material = hkdf.derive(dh_out)
    return material[:32], material[32:]  # new root key, initial chain key

def kdf_chain(ck):
    """Symmetric ratchet: derive message key and next chain key"""
    
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=64,
        salt=None,
        info=b"chain_ratchet"
    )
    material = hkdf.derive(ck)
    mk = material[:32]
    ck_next = material[32:]
    return mk, ck_next