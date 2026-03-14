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
    plt.savefig(title[:18] + ".png", dpi = 600)
    plt.show()


def plot_overhead_log(cov_msg_lengths, standard, anamorphic, title, iterations, log=True):

    standard = np.array(standard)
    anamorphic = np.array(anamorphic)
    print(standard)
    

    overhead = anamorphic - standard

    print(overhead)

    if log != True:
        scale = 1e5
        standard = standard * scale
        overhead = overhead * scale

    x = np.arange(len(cov_msg_lengths))
    width = 0.75

    cmap = plt.get_cmap("YlGnBu")
    base_colour = cmap(0.7)
    overhead_colour = cmap(0.35)

    fig, ax = plt.subplots(figsize=(5,5))

    ax.bar(
        x,
        standard,
        width,
        label="Standard Signal",
        color=base_colour,
        edgecolor="black",
        linewidth=0.5
    )

    ax.bar(
        x,
        overhead,
        width,
        bottom=standard,
        label="Anamorphic Covert-keyspace",
        color=overhead_colour,
        edgecolor="black",
        linewidth=0.5
    )

    for i in range(len(cov_msg_lengths)):

        y_bottom = standard[i]
        y_top = standard[i] + overhead[i]
        y_mid = (y_bottom + y_top) / 2

        raw = overhead[i]
        pct = (raw / standard[i]) * 100

        label = f"+{pct:.2e}%"

        ax.text(
            x[i],
            y_mid,
            label,
            ha="center",
            va="center",
            fontsize=7,
            color="black"
        )

    ax.set_xlabel("Covert Message Length (Bits)")
    if log:
        ax.set_ylabel(f"Average Time over {iterations} Iterations (log(seconds))")
    else:
        ax.set_ylabel(f"Average Time over {iterations} Iterations (seconds × 10$^{-5}$)")


    ax.set_title(title)

    ax.set_xticks(x)
    ax.set_xticklabels(cov_msg_lengths)

    if log:
        ax.set_yscale("symlog", linthresh=1e-4)

        
    ax.grid(axis="y", linestyle="--", alpha=0.5, which="both")

    ax.legend(fontsize=9)

    plt.tight_layout()
    plt.savefig(title[:17] + "_log.png", dpi = 600)
    plt.show()