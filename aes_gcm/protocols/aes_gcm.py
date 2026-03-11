import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class AESGCMProtocol:

    def __init__(self):
        self.k = None

    def Gen(self):
        """Generate AES-256 session key"""
        
        self.k = os.urandom(32)
        self.aes = AESGCM(self.k)

    def Enc(self, m: bytes):
        """Encrypt with random IV"""
        
        iv = os.urandom(12)

        # The third argument is AAD (additional authenticated data); we pass None
        # because this construction does not authenticate any external metadata.
        ciphertext = self.aes.encrypt(iv, m, None)

        # AES-GCM returns ciphertext || tag (the final 16 bytes are the auth tag).
        # We therefore return (IV, ciphertext) which corresponds to (IV, C || T).
        return iv, ciphertext 
    
    def Dec(self, iv: bytes, ciphertext: bytes):
        """Decrypt ciphertext"""
        
        plaintext = self.aes.decrypt(iv, ciphertext, None)

        return plaintext
