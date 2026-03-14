import os
from .signal import SignalProtocol
from ..utils.prf import prf
from ..utils.kdf import kdf_chain, kdf_root
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization


class CovertKeyspaceProtocol(SignalProtocol):
    """SignalState with anamorphic covert 16-bit channel"""

    def __init__(self, rk, ck_send, ck_recv, sk_ratchet, pk_ratchet_peer, dkey: bytes, covert_bits: int):
        super().__init__(rk, ck_send, ck_recv, sk_ratchet, pk_ratchet_peer)
        self.dkey = dkey
        self.covert_bits = covert_bits

        self.outlen = (covert_bits + 7) // 8
        self.mask = (1 << covert_bits) - 1

    def aSend(self, m: bytes, m_c_value: int):
        """
        Send a normal message m and embed 16-bit covert m_c
        Returns header, iv, ciphertext
        """

        m_c_value &= self.mask

        while True:
            sk = x25519.X25519PrivateKey.generate()
            pk = sk.public_key()

            pk_bytes = pk.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )

            prf_out = int.from_bytes(prf(self.dkey, pk_bytes, self.outlen), "big")

            if (prf_out & self.mask) == m_c_value:
                break

        dh = sk.exchange(self.pk_ratchet_peer)
        self.rk, self.ck_send = kdf_root(self.rk, dh)
        self.sk_ratchet = sk  
        
        mk, self.ck_send = kdf_chain(self.ck_send)
        aes = AESGCM(mk)
        iv = os.urandom(12)
        ciphertext = aes.encrypt(iv, m, None)

        header = {"pk_ratchet": pk}

        return header, iv, ciphertext

    def aRecv(self, header: dict, iv: bytes, ciphertext: bytes):
        """
        Receive message, extract covert 16-bit message
        Returns plaintext, covert
        """
        pk_peer = header["pk_ratchet"]

        pk_peer_bytes = pk_peer.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        pk_st_bytes = self.pk_ratchet_peer.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )

        prf_bytes = prf(self.dkey, pk_peer_bytes, self.outlen)
        prf_int = int.from_bytes(prf_bytes, "big")

        covert_value = prf_int & self.mask

        if pk_peer_bytes != pk_st_bytes:
            dh = self.sk_ratchet.exchange(pk_peer)
            self.rk, self.ck_recv = kdf_root(self.rk, dh)
            self.pk_ratchet_peer = pk_peer

        mk, self.ck_recv = kdf_chain(self.ck_recv)
        aes = AESGCM(mk)
        plaintext = aes.decrypt(iv, ciphertext, None)

        return plaintext, covert_value