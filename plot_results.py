import csv
import os

import matplotlib
matplotlib.use("Agg")                  # draw to files, no window needed
import matplotlib.pyplot as plt

BLUE, ORANGE, GREEN = "#2a6fdb", "#e8833a", "#2e9d5b"


def load(path):
    with open(path) as f:
        return list(csv.DictReader(f))


def column(rows, key):
    return [float(r[key]) for r in rows]


def finish(ax, title, xlabel, ylabel, filename, log_y=False):
    if log_y:
        ax.set_yscale("log")
    ax.set_title(title, fontweight="bold", loc="left")
    ax.set_xlabel(xlabel)
    ax.set_ylabel(ylabel)
    ax.grid(True, alpha=0.3)
    ax.legend(frameon=False)
    ax.figure.tight_layout()
    ax.figure.savefig(os.path.join("results", filename), dpi=160)
    print("saved results/" + filename)


def main():
    s = load("results/summary.csv")
    n = column(s, "devices")

    # Graph 1: number of devices vs batch-registration time
    fig, ax = plt.subplots(figsize=(7, 4.2))
    ax.errorbar(n, column(s, "batch_processing_ms_mean"), yerr=column(s, "batch_processing_ms_std"),
                marker="o", color=BLUE, capsize=3, label="sort + build tree + root")
    ax.errorbar(n, column(s, "finalize_epoch_ms_mean"), yerr=column(s, "finalize_epoch_ms_std"),
                marker="s", color=ORANGE, capsize=3, label="full epoch close (+ anchor + proof packages)")
    finish(ax, "Batch registration time vs number of devices", "Number of devices", "Time (ms)",
           "graph1_batch_time.png")

    # Graph 2: number of devices vs verification latency
    fig, ax = plt.subplots(figsize=(7, 4.2))
    ax.errorbar(n, column(s, "verification_latency_ms_mean"), yerr=column(s, "verification_latency_ms_std"),
                marker="o", color=BLUE, capsize=3, label="Merkle membership verification")
    ax.errorbar(n, column(s, "token_validation_ms_mean"), yerr=column(s, "token_validation_ms_std"),
                marker="^", color=GREEN, capsize=3, label="temporary-token validation")
    ax.errorbar(n, column(s, "resource_access_latency_ms_mean"), yerr=column(s, "resource_access_latency_ms_std"),
                marker="s", color=ORANGE, capsize=3, label="end-to-end resource access")
    finish(ax, "Verification latency vs number of devices", "Number of devices",
           "Latency per request (ms, log scale)", "graph2_verification_latency.png", log_y=True)

    # Graph 3: number of devices vs throughput
    fig, ax = plt.subplots(figsize=(7, 4.2))
    ax.plot(n, column(s, "registration_throughput_per_s_mean"), marker="o", color=BLUE, label="registrations / s")
    ax.plot(n, column(s, "verification_throughput_per_s_mean"), marker="s", color=ORANGE, label="verifications / s")
    ax.plot(n, column(s, "access_throughput_per_s_mean"), marker="^", color=GREEN, label="access decisions / s")
    finish(ax, "Throughput vs number of devices", "Number of devices",
           "Requests per second (log scale)", "graph3_throughput.png", log_y=True)

    # Graph 4: batch vs individual registration
    if os.path.exists("results/batch_vs_individual.csv"):
        b = load("results/batch_vs_individual.csv")
        bn = column(b, "devices")
        fig, (a1, a2) = plt.subplots(1, 2, figsize=(11, 4.2))
        a1.plot(bn, column(b, "individual_time_ms"), marker="o", color=ORANGE, label="individual (rebuild per device)")
        a1.plot(bn, column(b, "batch_time_ms"), marker="s", color=BLUE, label="batch (one build per epoch)")
        a1.set_yscale("log")
        a1.set_title("Fog processing time", fontweight="bold", loc="left")
        a1.set_xlabel("Number of devices"); a1.set_ylabel("Total time (ms, log scale)")
        a1.grid(True, alpha=0.3); a1.legend(frameon=False)
        a2.plot(bn, column(b, "individual_root_updates"), marker="o", color=ORANGE, label="individual: root anchors")
        a2.plot(bn, column(b, "batch_root_updates"), marker="s", color=BLUE, label="batch: root anchors")
        a2.plot(bn, column(b, "individual_stale_proofs"), marker="x", ls="--", color="gray", label="individual: stale proofs")
        a2.set_yscale("log")
        a2.set_title("Registry updates and stale proofs", fontweight="bold", loc="left")
        a2.set_xlabel("Number of devices"); a2.set_ylabel("Count (log scale)")
        a2.grid(True, alpha=0.3); a2.legend(frameon=False)
        fig.tight_layout()
        fig.savefig("results/graph4_batch_vs_individual.png", dpi=160)
        print("saved results/graph4_batch_vs_individual.png")


if __name__ == "__main__":
    main()