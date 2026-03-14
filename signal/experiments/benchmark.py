import time
import os
import random


def signal_encryption_benchmark_pair(stA, stB, anaA, anaB, iterations, msg_len, covert_bits):
    """
    Benchmark encryption for SignalProtocol vs Anamorphic protocol
    with variable covert bit length.
    """

    messages = [os.urandom(msg_len) for _ in range(iterations)]

    # generate covert integers with chosen bit length
    covert_values = [random.getrandbits(covert_bits) for _ in range(iterations)]

    # --- Standard Signal ---
    total_time = 0.0
    for msg in messages:
        start = time.perf_counter()
        header, iv, ct = stA.Send(msg)
        end = time.perf_counter()

        total_time += (end - start)

        plaintext = stB.Recv(header, iv, ct)
        if plaintext != msg:
            raise ValueError("Standard Signal decryption failed!")

    avg_enc_standard = total_time / iterations

    # --- Anamorphic Signal ---
    total_time = 0.0
    for msg, covert in zip(messages, covert_values):

        start = time.perf_counter()
        header, iv, ct = anaA.aSend(msg, covert)
        end = time.perf_counter()

        total_time += (end - start)

        plaintext, recovered = anaB.aRecv(header, iv, ct)

        if plaintext != msg or recovered != covert:
            raise ValueError("Anamorphic Signal decryption failed!")

    avg_enc_anamorphic = total_time / iterations

    return {
        "standard_enc": avg_enc_standard,
        "anamorphic_enc": avg_enc_anamorphic
    }


def signal_decryption_benchmark_pair(stA, stB, anaA, anaB, iterations, msg_len, covert_bits):
    """
    Benchmark decryption with variable covert bit length.
    Pre-encrypts messages for fair timing.
    """

    messages = [os.urandom(msg_len) for _ in range(iterations)]
    covert_values = [random.getrandbits(covert_bits) for _ in range(iterations)]

    # --- Pre-encrypt standard messages ---
    standard_encrypted = []
    for msg in messages:
        header, iv, ct = stA.Send(msg)
        standard_encrypted.append((header, iv, ct))

    total_time = 0.0
    for msg, (header, iv, ct) in zip(messages, standard_encrypted):

        start = time.perf_counter()
        plaintext = stB.Recv(header, iv, ct)
        end = time.perf_counter()

        total_time += (end - start)

        if plaintext != msg:
            raise ValueError("Standard Signal decryption failed!")

    avg_dec_standard = total_time / iterations

    # --- Pre-encrypt anamorphic messages ---
    anamorphic_encrypted = []
    for msg, covert in zip(messages, covert_values):
        header, iv, ct = anaA.aSend(msg, covert)
        anamorphic_encrypted.append((header, iv, ct))

    # Benchmark anamorphic decryption
    total_time = 0.0
    for msg, covert, (header, iv, ct) in zip(messages, covert_values, anamorphic_encrypted):

        start = time.perf_counter()
        plaintext, recovered = anaB.aRecv(header, iv, ct)
        end = time.perf_counter()

        total_time += (end - start)

        if plaintext != msg or recovered != covert:
            raise ValueError("Anamorphic Signal decryption failed!")

    avg_dec_anamorphic = total_time / iterations

    return {
        "standard_dec": avg_dec_standard,
        "anamorphic_dec": avg_dec_anamorphic
    }