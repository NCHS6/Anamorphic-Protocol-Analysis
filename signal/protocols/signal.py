import os
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization
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

    def Send(self, m, asymmetric = False):
        """Send a message using asymmetric or symmetric ratchet"""

        if asymmetric:
            sk = x25519.X25519PrivateKey.generate()
            pk = sk.public_key()
            # DH with peer to update root and reset chain
            dh = sk.exchange(self.pk_ratchet_peer)
            self.rk, self.ck_send = kdf_root(self.rk, dh)
            self.sk_ratchet = sk
        else:
            pk = self.sk_ratchet.public_key()

        mk, self.ck_send = kdf_chain(self.ck_send)
        aes = AESGCM(mk)
        iv = os.urandom(12)
        ciphertext = aes.encrypt(iv, m, None)

        header = {"pk_ratchet": pk}

        return header, iv, ciphertext

    def Recv(self, header, iv, ciphertext):
        """Receive a message using symmetric ratchet"""
        pk_peer = header["pk_ratchet"]

        pk_peer_bytes = pk_peer.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        pk_st_bytes = self.pk_ratchet_peer.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )

        # Check if asymmetric ratchet needed
        if pk_peer_bytes != pk_st_bytes:
            dh = self.sk_ratchet.exchange(pk_peer)
            self.rk, self.ck_recv = kdf_root(self.rk, dh)
            self.pk_ratchet_peer = pk_peer

        mk, self.ck_recv = kdf_chain(self.ck_recv)
        aes = AESGCM(mk)
        plaintext = aes.decrypt(iv, ciphertext, None)
        return plaintext