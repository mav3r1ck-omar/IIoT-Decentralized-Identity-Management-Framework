import csv
import os
import statistics
import sys
import time

import config
from device import Device
from fog_node import FogNode
from merkle import build_levels, get_proof

DEVICE_COUNTS = [5, 10, 25, 50, 100, 250, 500]
RUNS = 5

# every device type, and one operation it is allowed to do
TYPES = [("temperature-sensor", "telemetry/temperature", "WRITE"),
         ("pressure-sensor", "telemetry/pressure", "WRITE"),
         ("smart-meter", "telemetry/energy", "WRITE"),
         ("camera", "stream/video", "WRITE"),
         ("valve-controller", "telemetry/valve", "WRITE"),
         ("motor-controller", "telemetry/motor", "WRITE"),
         ("plc", "telemetry/line", "READ")]


def ms(seconds):
    return seconds * 1000


def one_run(n, run):
    """Measure every required metric for ONE run with n devices."""
    fog = FogNode()
    devices = []
    for i in range(n):
        dev_type, res, op = TYPES[i % len(TYPES)]
        d = Device(f"dev-{run}-{i}", dev_type, fog, verbose=False)
        d.resource, d.operation = res, op
        devices.append(d)

    # 1. registration latency (PSK + public key + PoP + DID/metadata) and throughput
    reg_times = []
    start_all = time.perf_counter()
    for d in devices:
        t = time.perf_counter()
        d.register()
        reg_times.append(time.perf_counter() - t)
    reg_total = time.perf_counter() - start_all

    # 2. batch processing: sort leaves + build tree + compute root
    leaves = [r["leaf"] for r in fog.batch.pending.values()]
    t = time.perf_counter()
    levels = build_levels(leaves)
    root = levels[-1][0]
    batch_time = time.perf_counter() - t

    # 3. proof-generation latency (per device)
    t = time.perf_counter()
    for leaf in leaves:
        get_proof(levels, leaf)
    proof_avg = (time.perf_counter() - t) / n

    # the real epoch close (tree + anchor + signed packages), so devices get proofs
    t = time.perf_counter()
    fog.finalize_epoch()
    finalize_time = time.perf_counter() - t
    for d in devices:
        d.package = fog.get_proof_package(d.did)

    # 4. verification latency: leaf + proof path + trusted root
    ver_times = []
    start_all = time.perf_counter()
    for d in devices:
        t = time.perf_counter()
        ok, _ = fog.verifier.verify_membership(d.did, d.pk, d.package["epoch_id"], d.package["proof"])
        ver_times.append(time.perf_counter() - t)
        assert ok
    ver_total = time.perf_counter() - start_all

    # 5. resource-access latency: nonce + signed request + full ALLOW/DENY decision
    acc_times = []
    start_all = time.perf_counter()
    for d in devices:
        t = time.perf_counter()
        result = d.access(d.resource, d.operation)
        acc_times.append(time.perf_counter() - t)
        assert result["decision"] == "ALLOW", result
    acc_total = time.perf_counter() - start_all

    # 6. temporary-token validation: signature + expiry + revocation + nonce
    late = Device(f"late-{run}", "temperature-sensor", fog, verbose=False)
    late.register(want_token=True)
    tok_times = []
    for _ in range(max(20, n)):
        nonce = fog.get_challenge(late.did)
        t = time.perf_counter()
        v = fog.tokens.validate(late.token)
        ok, _ = fog.nonces.consume(nonce, v["payload"]["did"])
        tok_times.append(time.perf_counter() - t)
        assert v["ok"] and ok

    return {
        "devices": n, "run": run,
        "registration_latency_ms": ms(statistics.mean(reg_times)),
        "registration_throughput_per_s": n / reg_total,
        "batch_processing_ms": ms(batch_time),
        "proof_generation_ms": ms(proof_avg),
        "finalize_epoch_ms": ms(finalize_time),
        "verification_latency_ms": ms(statistics.mean(ver_times)),
        "verification_throughput_per_s": n / ver_total,
        "token_validation_ms": ms(statistics.mean(tok_times)),
        "resource_access_latency_ms": ms(statistics.mean(acc_times)),
        "access_throughput_per_s": n / acc_total,
        "proof_length": len(devices[0].package["proof"]),
    }


def main():
    counts = [int(x) for x in sys.argv[1:]] or DEVICE_COUNTS
    rows = []
    print(f"{'N':>5} {'batch ms':>10} {'verify ms':>10} {'access ms':>10} {'reg/s':>8} {'verify/s':>10}")
    for n in counts:
        runs = [one_run(n, r) for r in range(RUNS)]
        rows += runs
        avg = lambda key: statistics.mean(x[key] for x in runs)
        print(f"{n:>5} {avg('batch_processing_ms'):>10.3f} {avg('verification_latency_ms'):>10.4f} "
              f"{avg('resource_access_latency_ms'):>10.3f} {avg('registration_throughput_per_s'):>8.0f} "
              f"{avg('verification_throughput_per_s'):>10.0f}")

    os.makedirs("results", exist_ok=True)
    # every single run (raw data)
    with open("results/raw_measurements.csv", "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    # averages and standard deviations per device count
    metrics = [k for k in rows[0] if k not in ("devices", "run")]
    with open("results/summary.csv", "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["devices"] + [f"{m}_mean" for m in metrics] + [f"{m}_std" for m in metrics])
        for n in counts:
            group = [r for r in rows if r["devices"] == n]
            means = [statistics.mean(g[m] for g in group) for m in metrics]
            stds = [statistics.stdev(g[m] for g in group) if len(group) > 1 else 0 for m in metrics]
            writer.writerow([n] + [round(v, 6) for v in means] + [round(v, 6) for v in stds])
    print("\nSaved results/raw_measurements.csv and results/summary.csv")


if __name__ == "__main__":
    main()