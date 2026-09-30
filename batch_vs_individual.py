import csv
import os
import statistics
import sys
import time

from crypto_utils import generate_keypair, public_key_hex, make_did, compute_leaf, sign_json
from merkle import build_levels, get_proof, verify_proof
from registry import RootRegistry

DEVICE_COUNTS = [5, 10, 25, 50, 100, 250]
RUNS = 5


def make_leaves(n):
    leaves = []
    for _ in range(n):
        pk = public_key_hex(generate_keypair())
        leaves.append(compute_leaf(make_did("factory-A", pk), pk))
    return leaves


def anchor(registry, fog_sk, epoch_id, root, count):
    record = {"epoch_id": epoch_id, "root": root, "leaf_count": count, "fog_id": "fog-A1"}
    registry.anchor(record, sign_json(fog_sk, record))


def individual(leaves, fog_sk, fog_pk):
    """Rebuild the tree, anchor a new root and refresh EVERY proof after each new device."""
    registry = RootRegistry()
    registry.register_signer("fog-A1", fog_pk)
    issued = {}                  # leaf -> the proof that device currently holds
    stale = 0
    start = time.perf_counter()
    for i in range(len(leaves)):
        current = leaves[:i + 1]
        levels = build_levels(current)                     # rebuild after every arrival
        root = levels[-1][0]
        anchor(registry, fog_sk, i + 1, root, len(current))
        for leaf in current:
            if leaf in issued and not verify_proof(leaf, issued[leaf], root):
                stale += 1                                 # that device's old proof no longer works
            issued[leaf] = get_proof(levels, leaf)         # so it must get a new one
    return {"time_ms": (time.perf_counter() - start) * 1000,
            "root_updates": len(registry.blocks), "stale_proofs": stale}


def batch(leaves, fog_sk, fog_pk):
    """Collect everything, build the tree ONCE, anchor ONE root, one proof per device."""
    registry = RootRegistry()
    registry.register_signer("fog-A1", fog_pk)
    start = time.perf_counter()
    levels = build_levels(leaves)
    anchor(registry, fog_sk, 1, levels[-1][0], len(leaves))
    for leaf in leaves:
        get_proof(levels, leaf)
    return {"time_ms": (time.perf_counter() - start) * 1000,
            "root_updates": len(registry.blocks), "stale_proofs": 0}


def main():
    counts = [int(x) for x in sys.argv[1:]] or DEVICE_COUNTS
    fog_sk = generate_keypair()
    fog_pk = public_key_hex(fog_sk)
    rows = []
    print(f"{'N':>5} | {'individual ms':>13} {'roots':>6} {'stale':>7} | {'batch ms':>9} {'roots':>6} | speed-up")
    for n in counts:
        ind, bat = [], []
        for _ in range(RUNS):
            leaves = make_leaves(n)
            ind.append(individual(leaves, fog_sk, fog_pk))
            bat.append(batch(leaves, fog_sk, fog_pk))
        row = {"devices": n,
               "individual_time_ms": statistics.mean(x["time_ms"] for x in ind),
               "individual_root_updates": ind[0]["root_updates"],
               "individual_stale_proofs": ind[0]["stale_proofs"],
               "batch_time_ms": statistics.mean(x["time_ms"] for x in bat),
               "batch_root_updates": bat[0]["root_updates"]}
        row["speedup"] = row["individual_time_ms"] / row["batch_time_ms"]
        rows.append(row)
        print(f"{n:>5} | {row['individual_time_ms']:>13.2f} {row['individual_root_updates']:>6} "
              f"{row['individual_stale_proofs']:>7} | {row['batch_time_ms']:>9.2f} "
              f"{row['batch_root_updates']:>6} | {row['speedup']:.1f}x")
    os.makedirs("results", exist_ok=True)
    with open("results/batch_vs_individual.csv", "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    print("\nSaved results/batch_vs_individual.csv")


if __name__ == "__main__":
    main()