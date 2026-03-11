import time
import os

def signal_encryption_benchmark_pair(stA, stB, anaA, anaB, iterations, msg_len):
    """
    Benchmark encryption for SignalProtocol vs CovertKeyspaceProtocol
    using proper sender/receiver pairs.
    """
    messages = [os.urandom(msg_len) for _ in range(iterations)]
    covert_messages = [os.urandom(2) for _ in range(iterations)]

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
    for msg, covert in zip(messages, covert_messages):
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


def signal_decryption_benchmark_pair(stA, stB, anaA, anaB, iterations, msg_len):
    """
    Benchmark decryption for SignalProtocol vs CovertKeyspaceProtocol
    using proper sender/receiver pairs.
    
    Pre-encrypts all messages to ensure fair timing.
    """
    messages = [os.urandom(msg_len) for _ in range(iterations)]
    covert_messages = [os.urandom(2) for _ in range(iterations)]

    # --- Pre-encrypt all messages for standard Signal ---
    standard_encrypted = []
    for msg in messages:
        header, iv, ct = stA.Send(msg)
        standard_encrypted.append((header, iv, ct))

    # Benchmark standard decryption
    total_time = 0.0
    for msg, (header, iv, ct) in zip(messages, standard_encrypted):
        start = time.perf_counter()
        plaintext = stB.Recv(header, iv, ct)
        end = time.perf_counter()
        total_time += (end - start)

        if plaintext != msg:
            raise ValueError("Standard Signal decryption failed!")

    avg_dec_standard = total_time / iterations

    # --- Pre-encrypt all messages for anamorphic CovertKeyspace ---
    anamorphic_encrypted = []
    for msg, covert in zip(messages, covert_messages):
        header, iv, ct = anaA.aSend(msg, covert)
        anamorphic_encrypted.append((header, iv, ct))

    # Benchmark anamorphic decryption
    total_time = 0.0
    for msg, covert, (header, iv, ct) in zip(messages, covert_messages, anamorphic_encrypted):
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