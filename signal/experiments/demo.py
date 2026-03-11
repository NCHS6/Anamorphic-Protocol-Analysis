import os
from ..protocols.signal import SignalProtocol
from ..protocols.covert_keyspace_extension import CovertKeyspaceProtocol
from cryptography.hazmat.primitives import serialization

def run_standard_signal_demo():
    # Initialize Signal states
    stA, stB = SignalProtocol.Gen()

    print("Signal Protocol (standard):")

    message = b"Hello Bob"
    print("Overt message:", message)

    header, iv, ct = stA.Send(message, True)

    pk_bytes = header["pk_ratchet"].public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    print("Public Ratchet Key:", pk_bytes.hex())

    m = stB.Recv(header, iv, ct)
    print("Overt recovered:", m == message)


def run_anamorphic_signal_demo():
    # Shared secret for covert channel
    dkey = os.urandom(32)

    # Initialize Signal states
    stA, stB = SignalProtocol.Gen()

    # Wrap with Covert-Keyspace extension
    anaA = CovertKeyspaceProtocol(stA.rk, stA.ck_send, stA.ck_recv, stA.sk_ratchet, stA.pk_ratchet_peer, dkey)
    anaB = CovertKeyspaceProtocol(stB.rk, stB.ck_send, stB.ck_recv, stB.sk_ratchet, stB.pk_ratchet_peer, dkey)

    print("Covert-Keyspace extension (anamorphic):")

    message = b"Hello Bob"
    print("Overt message:", message)

    covert = b"\xAB\xCD"  # 16-bit covert
    print("Covert message:", covert.hex())

    header, iv, ct = anaA.aSend(message, covert)
    
    pk_bytes = header["pk_ratchet"].public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    print("Public Ratchet Key:", pk_bytes.hex())


    m, recovered = anaB.aRecv(header, iv, ct)
    print("Overt recovered:", m == message)
    print("Covert recovered:", covert == recovered)