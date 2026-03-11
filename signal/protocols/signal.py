import os
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from ..utils.kdf import kdf_chain, kdf_root

class SignalProtocol:

    def __init__(self, rk, ck_send, ck_recv, sk_ratchet, pk_ratchet_peer):
        self.rk = rk
        self.ck_send = ck_send
        self.ck_recv = ck_recv
        self.sk_ratchet = sk_ratchet
        self.pk_ratchet_peer = pk_ratchet_peer

# ---------- Gen / Handshake ----------

def Gen():
    """Generate initial state for two parties (Alice/Bob)"""
    skA = x25519.X25519PrivateKey.generate()
    skB = x25519.X25519PrivateKey.generate()

    pkA = skA.public_key()
    pkB = skB.public_key()

    # Simulate X3DH exchange
    dh = skA.exchange(pkB)
    rk, ck_send = kdf_root(b'\x00'*32, dh)
    _, ck_recv = kdf_root(b'\x00'*32, dh)  # symmetric for demo

    stA = SignalProtocol(rk, ck_send, ck_recv, skA, pkB)
    stB = SignalProtocol(rk, ck_recv, ck_send, skB, pkA)

    return stA, stB

# ---------- Send / Recv ----------

def Send(st, m):
    """Send a message using symmetric ratchet"""
    mk, st.ck_send = kdf_chain(st.ck_send)
    aes = AESGCM(mk)
    iv = os.urandom(12)
    ciphertext = aes.encrypt(iv, m, None)
    header = {"pk_ratchet": st.sk_ratchet.public_key()}  # minimal header
    return header, iv, ciphertext

def Recv(st, header, iv, ciphertext):
    """Receive a message using symmetric ratchet"""
    pk_peer = header["pk_ratchet"]

    # Check if asymmetric ratchet needed
    if pk_peer.public_bytes() != st.pk_ratchet_peer.public_bytes():
        dh = st.sk_ratchet.exchange(pk_peer)
        st.rk, st.ck_recv = kdf_root(st.rk, dh)
        st.pk_ratchet_peer = pk_peer

    mk, st.ck_recv = kdf_chain(st.ck_recv)
    aes = AESGCM(mk)
    plaintext = aes.decrypt(iv, ciphertext, None)
    return plaintext