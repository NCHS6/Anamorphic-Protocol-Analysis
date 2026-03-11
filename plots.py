import numpy as np
import matplotlib
matplotlib.use("TkAgg")
import matplotlib.pyplot as plt

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