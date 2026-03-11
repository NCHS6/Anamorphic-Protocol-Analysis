import os
import random
import numpy as np
import matplotlib.pyplot as plt
import matplotlib.pyplot as plt
from aes_gcm.protocols.aes_gcm import AESGCMProtocol
from aes_gcm.protocols.covert_iv_extension import CovertIVProtocol

from aes_gcm.experiments.demo import run_standard_demo, run_anamorphic_demo
from aes_gcm.experiments.benchmark import encryption_benchmark, decryption_benchmark


aes = AESGCMProtocol()

dkey = os.urandom(32)
ctr = random.randint(0, 2**32 - 1)
covert = CovertIVProtocol(dkey, ctr)

print("=== Standard AES-GCM Demo ===")
run_standard_demo(aes)

print("\n=== Anamorphic Covert-IV Demo ===")
run_anamorphic_demo(covert)




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

def plot_overhead(msg_lengths, standard, anamorphic, title, iterations):

    standard = np.array(standard)
    anamorphic = np.array(anamorphic)

    overhead = anamorphic - standard

    scale = 1e5
    standard_s = standard * scale
    overhead_s = overhead * scale

    x = np.arange(len(msg_lengths))
    width = 0.75

    cmap = plt.get_cmap("YlGnBu")
    base_colour = cmap(0.7)
    overhead_colour = cmap(0.35)

    fig, ax = plt.subplots(figsize=(5,5))


    ax.bar(
        x,
        standard_s,
        width,
        label="Standard AES-GCM",
        color=base_colour,
        edgecolor="black",
        linewidth=0.5
    )

    ax.bar(
        x,
        overhead_s,
        width,
        bottom=standard_s,
        label="Anamorphic Covert-IV",
        color=overhead_colour,
        edgecolor="black",
        linewidth=0.5
    )

    for i in range(len(msg_lengths)):

        y_bottom = standard_s[i]
        y_top = standard_s[i] + overhead_s[i]
        y_mid = (y_bottom + y_top) / 2

        raw = overhead[i]
        pct = (raw / standard[i]) * 100

        label = f"+{pct:.2f}%"

        ax.text(
            x[i],
            y_mid,
            label,
            ha="center",
            va="center",
            fontsize=7,
            color="black"
        )


    ax.set_xlabel("Message Length (bytes)")
    ax.set_ylabel(f"Average Time over {iterations} Iterations (seconds × 10$^{-5}$)")
    ax.set_title(title)

    ax.set_xticks(x)
    ax.set_xticklabels(msg_lengths)

    ax.grid(axis="y", linestyle="--", alpha=0.5)

    ax.legend(fontsize=9)

    plt.tight_layout()
    plt.savefig(title[:10] + ".png")
    plt.show()


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
