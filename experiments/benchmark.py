import time
import os

def encryption_benchmark(standard_protocol, anamorphic_protocol, iterations, msg_len):

    messages = [os.urandom(msg_len) for _ in range(iterations)]
    covert_messages = [os.urandom(12) for _ in range(iterations)]
    
    # --- Standard AES-GCM ---
    standard_protocol.Gen()

    total_time = 0.0
    for msg in messages:

        start = time.perf_counter()
        iv, c = standard_protocol.Enc(msg)
        end = time.perf_counter()

        total_time += (end - start)

        m_dec = standard_protocol.Dec(iv, c)
        if m_dec != msg:
            raise ValueError("Decryption failed in standard AES-GCM!")

    avg_enc_time_standard = total_time / iterations

    # --- Anamoprhic Covert-IV ---
    anamorphic_protocol.Gen()

    total_time = 0.0
    for msg, covert in zip(messages, covert_messages):

        start = time.perf_counter()
        iv, c = anamorphic_protocol.aEnc(msg, covert)
        end = time.perf_counter()

        total_time += (end - start)

        m_dec, m_c_dec = anamorphic_protocol.aDec(iv, c)
        if m_dec != msg or m_c_dec != covert:
            raise ValueError("Decryption failed in anamorphic covert-IV!")

    avg_enc_time_anamorphic = total_time / iterations

    return {
        "standard_enc": avg_enc_time_standard,
        "anamorphic_enc": avg_enc_time_anamorphic
    }

def decryption_benchmark(standard_protocol, anamorphic_protocol, iterations, msg_len):
    """Benchmark decryption time for standard and anamorphic AES-GCM."""

    messages = [os.urandom(msg_len) for _ in range(iterations)]
    covert_messages = [os.urandom(12) for _ in range(iterations)]

    # --- Pre-encrypt all messages for standard AES-GCM ---
    standard_protocol.Gen()
    standard_encrypted = []
    for msg in messages:
        iv, c = standard_protocol.Enc(msg)
        standard_encrypted.append((iv, c))

    # Benchmark decryption for standard AES-GCM
    total_time = 0.0
    for msg, (iv, c) in zip(messages, standard_encrypted):
        start = time.perf_counter()
        m_dec = standard_protocol.Dec(iv, c)
        end = time.perf_counter()

        total_time += (end - start)

        if m_dec != msg:
            raise ValueError("Decryption failed in standard AES-GCM!")

    avg_dec_time_standard = total_time / iterations

    # --- Pre-encrypt all messages for anamorphic covert-IV ---
    anamorphic_protocol.Gen()
    anamorphic_encrypted = []
    for msg, covert in zip(messages, covert_messages):
        iv, c = anamorphic_protocol.aEnc(msg, covert)
        anamorphic_encrypted.append((iv, c))

    # Benchmark decryption for anamorphic covert-IV
    total_time = 0.0
    for msg, covert, (iv, c) in zip(messages, covert_messages, anamorphic_encrypted):
        start = time.perf_counter()
        m_dec, m_c_dec = anamorphic_protocol.aDec(iv, c)
        end = time.perf_counter()

        total_time += (end - start)

        if m_dec != msg or m_c_dec != covert:
            raise ValueError("Decryption failed in anamorphic covert-IV!")

    avg_dec_time_anamorphic = total_time / iterations

    return {
        "standard_dec": avg_dec_time_standard,
        "anamorphic_dec": avg_dec_time_anamorphic
    }