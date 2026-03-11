import os
from .aes_gcm import AESGCMProtocol
from ..utils.prf import prf 
from ..utils.xor import xor_bytes 

class CovertIVProtocol(AESGCMProtocol):

    def __init__(self, dkey: bytes, ctr: int):
        super().__init__()

        self.dkey = dkey
        self.senderCtr = ctr
        self.receiverCtr = ctr

    def aEnc(self, m: bytes, m_c: bytes):
        """Encrypt with covert IV"""

        mask = prf(self.dkey, self.senderCtr)
        
        iv = xor_bytes(mask, m_c)

        ciphertext = self.aes.encrypt(iv, m, None)

        self.senderCtr = (self.senderCtr + 1) % (2**32)
        
        return iv, ciphertext
    
    def aDec(self, iv: bytes, ciphertext: bytes):
        """Decrypt overt and covert messages"""

        plaintext = self.aes.decrypt(iv, ciphertext, None)

        mask = prf(self.dkey, self.receiverCtr)

        m_c = xor_bytes(mask, iv)

        self.receiverCtr = (self.receiverCtr + 1) % (2**32)

        return plaintext, m_c
    

