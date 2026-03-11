import os


def run_standard_aes_demo(protocol):
    protocol.Gen()

    print("AES-GCM:")

    message = b"Hello Bob"
    print("overt message:", message)
    
    iv, c = protocol.Enc(message)
    print("IV:", iv)

    m = protocol.Dec(iv, c)

    print("Overt recovered:", m == message)


def run_anamorphic_aes_demo(protocol):
    protocol.Gen()

    print("covert-IV extension:")

    message = b"Hello Bob"
    print("overt message:", message)
    
    covert = b"TOP_SECRET!!"
    print("covert message:", covert)

    iv, c = protocol.aEnc(message, covert)
    print("IV:", iv)

    m, recovered = protocol.aDec(iv, c)

    print("Overt recovered:", m == message)
    print("Covert recovered:", covert == recovered)
