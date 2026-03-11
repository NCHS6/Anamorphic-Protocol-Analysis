import os
import random
from aes_gcm.protocols.aes_gcm import AESGCMProtocol
from aes_gcm.protocols.covert_iv_extension import CovertIVProtocol

from aes_gcm.experiments.demo import run_standard_aes_demo, run_anamorphic_aes_demo
from aes_gcm.experiments.benchmark import encryption_benchmark, decryption_benchmark

from signal.experiments.demo import run_standard_signal_demo, run_anamorphic_signal_demo

from signal.protocols.signal import SignalProtocol
from signal.protocols.covert_keyspace_extension import CovertKeyspaceProtocol
from signal.experiments.demo import run_standard_signal_demo, run_anamorphic_signal_demo
from signal.experiments.benchmark import signal_encryption_benchmark_pair, signal_decryption_benchmark_pair

from plots import plot_overhead


aes = AESGCMProtocol()

dkey = os.urandom(32)
ctr = random.randint(0, 2**32 - 1)
covert = CovertIVProtocol(dkey, ctr)

print("=== Standard AES-GCM Demo ===")
run_standard_aes_demo(aes)

print("\n=== Anamorphic Covert-IV Demo ===")
run_anamorphic_aes_demo(covert)


# --- Benchmark parameters ---
iterations = 100000 
msg_lengths = [64, 256, 1024, 4096, 8192]  # bytes

standard_enc_times = []
anamorphic_enc_times = []
standard_dec_times = []
anamorphic_dec_times = []

for msg_len in msg_lengths:
    print(f"Benchmarking messages of length {msg_len} bytes...")

    # Encryption benchmark
    enc_results = encryption_benchmark(aes, covert, iterations, msg_len)
    standard_enc_times.append(enc_results['standard_enc'])
    anamorphic_enc_times.append(enc_results['anamorphic_enc'])

    # Decryption benchmark
    dec_results = decryption_benchmark(aes, covert, iterations, msg_len)
    standard_dec_times.append(dec_results['standard_dec'])
    anamorphic_dec_times.append(dec_results['anamorphic_dec'])


plot_overhead(
    msg_lengths,
    standard_enc_times,
    anamorphic_enc_times,
    "Encryption: Standard vs Anamorphic",
    iterations
)

plot_overhead(
    msg_lengths,
    standard_dec_times,
    anamorphic_dec_times,
    "Decryption: Standard vs Anamorphic",
    iterations
)

print("=== Standard Signal Demo ===")
run_standard_signal_demo()

print("\n=== Anamorphic Covert-Keyspace Demo ===")
run_anamorphic_signal_demo()

# --- Signal benchmark setup ---
signal_msg_lengths = [64]  # keep smaller for Signal (ratchet cost is high)
signal_iterations = 5  # smaller to reduce runtime

standard_enc_times = []
anamorphic_enc_times = []
standard_dec_times = []
anamorphic_dec_times = []


for msg_len in signal_msg_lengths:
    print(f"Benchmarking Signal messages of length {msg_len} bytes...")

    # Initialize Signal states for this iteration
    stA, stB = SignalProtocol.Gen()
    dkey = os.urandom(32)
    anaA = CovertKeyspaceProtocol(stA.rk, stA.ck_send, stA.ck_recv, stA.sk_ratchet, stA.pk_ratchet_peer, dkey)
    anaB = CovertKeyspaceProtocol(stB.rk, stB.ck_send, stB.ck_recv, stB.sk_ratchet, stB.pk_ratchet_peer, dkey)

    # Encryption benchmark
    enc_results = signal_encryption_benchmark_pair(stA, stB, anaA, anaB, signal_iterations, msg_len)
    standard_enc_times.append(enc_results['standard_enc'])
    anamorphic_enc_times.append(enc_results['anamorphic_enc'])

    # Decryption benchmark
    dec_results = signal_decryption_benchmark_pair(stA, stB, anaA, anaB, signal_iterations, msg_len)
    standard_dec_times.append(dec_results['standard_dec'])
    anamorphic_dec_times.append(dec_results['anamorphic_dec'])


plot_overhead(
    signal_msg_lengths,
    standard_enc_times,
    anamorphic_enc_times,
    "Encryption: Standard vs Anamorphic",
    signal_iterations
)

plot_overhead(
    signal_msg_lengths,
    standard_dec_times,
    anamorphic_dec_times,
    "Decryption: Standard vs Anamorphic",
    signal_iterations
)