"""
Live demonstration - follows the 10 steps of Section 7 of the assignment.
Devices talk to the fog over HTTPS (TLS). Lines tagged [FOG] show what the
fog node checked and decided; [DEVICE] lines show the device side.

    python3 demo.py           # run straight through
    python3 demo.py --step    # pause after each step (use this in the live demo)
"""
import json
import sys

import config
import attacks
from crypto_utils import b64url_decode, compute_leaf, generate_keypair, public_key_hex
from device import Device
from fog_client import FogClient
from fog_node import FogNode
from merkle import hash_pair
from server import start_in_background

PAUSE = "--step" in sys.argv
PORT = config.FOG_PORT + 2          # own port, so it never clashes with a running server.py


def step(number, title):
    if PAUSE and number > 1:
        input("\n   [press Enter for the next step] ")
    print("\n" + "=" * 78 + f"\n  STEP {number}: {title}\n" + "=" * 78)


def fog_log(msg):
    print(f"  [FOG] {msg}")


def short(h, n=16):
    return h[:n] + "..." if isinstance(h, str) and len(h) > n else h


def show_decision(result):
    """Print a fog decision with every check it performed."""
    marks = "  ".join(f"{k}={'OK' if v else 'FAIL'}" for k, v in result["checks"].items())
    fog_log(f"{result['decision']}: {result['reason']}")
    fog_log(f"checks: {marks}")
    if result.get("detected_by"):
        fog_log(f"rejected by: {result['detected_by']}")


def main():
    node = FogNode()
    server = start_in_background(node, PORT)
    fog = FogClient(f"https://{config.FOG_HOST}:{PORT}", admin_key=config.ADMIN_API_KEY)
    fog_log(f"fog node '{node.fog_id}' listening on https://{config.FOG_HOST}:{PORT} (TLS 1.2+)")
    fog_log(f"fog signing key: {short(node.pk_hex, 24)}")

    try:
        # ----------------------------------------------------------------------------- 1
        step(1, "Device connects over TLS and completes initial (PSK) authentication")
        temp = Device("temp-01", "temperature-sensor", fog)
        temp.register()
        fog_log("temp-01: PSK HMAC valid, timestamp fresh, message not replayed -> session opened")
        rogue = Device("rogue-99", "plc", fog, psk=b"guessed-psk", verbose=False)
        try:
            rogue.register()
        except ValueError as e:
            fog_log(f"rogue-99 REJECTED before any identity step: {e}")

        # ----------------------------------------------------------------------------- 2
        step(2, "DID / key generation and proof-of-possession")
        print(f"  [DEVICE temp-01] DID        = {temp.did}")
        print(f"  [DEVICE temp-01] public key = {short(temp.pk, 40)}  (private key never leaves the device)")
        fog_log("sent a fresh 256-bit challenge; temp-01 signed it; signature verified with its public key")
        insider = Device("insider-01", "plc", fog, verbose=False)
        insider.pk = temp.pk                       # claims temp-01's public key
        try:
            insider.register()
        except ValueError as e:
            fog_log(f"insider-01 claimed temp-01's public key -> REJECTED: {e}")

        # ----------------------------------------------------------------------------- 3
        step(3, "Multiple devices collected into one registration batch")
        devices = {"temp-01": temp}
        for name, dev_type in [("press-01", "pressure-sensor"), ("cam-01", "camera"),
                               ("valve-01", "valve-controller"), ("motor-01", "motor-controller"),
                               ("plc-01", "plc")]:
            devices[name] = Device(name, dev_type, fog)
            devices[name].register()
        fog_log(f"epoch {node.batch.current_epoch} is OPEN: {len(node.batch.pending)} leaves pending")
        fog_log(f"blocks on the ledger so far: {len(node.registry.blocks)}  (no tree is built per device)")

        # ----------------------------------------------------------------------------- 4
        step(4, "Registration window closes: sort leaves, build tree, compute and anchor the root")
        summary = fog.finalize_epoch()
        levels = node.batch.trees[summary["epoch_id"]]
        fog_log(f"sorted {summary['leaf_count']} leaves, built a tree with {len(levels) - 1} levels above the leaves")
        fog_log(f"epoch {summary['epoch_id']} ROOT = {summary['root']}")
        block = node.registry.blocks[-1]
        fog_log(f"anchored in block #{block['index']}: prev_hash={short(block['prev_hash'])} "
                f"block_hash={short(block['block_hash'])}")
        fog_log(f"anchor record: {block['record']}")
        fog_log(f"ledger integrity check (verify_chain): {node.registry.verify_chain()}")
        for d in devices.values():
            d.fetch_proof()

        # ----------------------------------------------------------------------------- 5
        step(5, "Inclusion-proof generation and verification")
        pkg = temp.package
        leaf = compute_leaf(temp.did, temp.pk)
        fog_log(f"temp-01 proof package: epoch {pkg['epoch_id']}, {len(pkg['proof'])} sibling hashes, "
                f"signed by the fog")
        fog_log(f"verifier recomputes the leaf itself: H(DID|PK) = {short(leaf, 24)}")
        current = leaf
        for i, s in enumerate(pkg["proof"]):
            current = hash_pair(s["hash"], current) if s["side"] == "L" else hash_pair(current, s["hash"])
            fog_log(f"  level {i}: sibling {short(s['hash'])} on the {s['side']} -> {short(current, 24)}")
        trusted = node.registry.get_root(pkg["epoch_id"])
        fog_log(f"reconstructed root {short(current, 24)} == trusted root {short(trusted, 24)} "
                f"-> {'VALID' if current == trusted else 'INVALID'}")

        cam = devices["cam-01"]
        fake_pk = public_key_hex(generate_keypair())
        fake_leaf = compute_leaf(cam.did, fake_pk)
        current = fake_leaf
        for s in cam.package["proof"]:
            current = hash_pair(s["hash"], current) if s["side"] == "L" else hash_pair(current, s["hash"])
        fog_log("tamper test: cam-01's public key changed AFTER the batch closed")
        fog_log(f"  recomputed root {short(current, 24)} != anchored root {short(trusted, 24)} -> tampering detected")

        # ----------------------------------------------------------------------------- 6
        step(6, "Temporary token for a device that joins while epoch 2 is open")
        late = Device("valve-02", "valve-controller", fog)
        late.register(want_token=True)
        payload = json.loads(b64url_decode(late.token))["payload"]
        fog_log(f"token issued: id={payload['token_id']} role={payload['device_type']} "
                f"expires in {payload['expires_at'] - payload['issued_at']:.0f}s")
        fog_log(f"token scope (provisional only): {payload['scope']}")
        fog_log(f"valve-02 has a proof package yet? {fog.get_proof_package(late.did) is not None}")
        late.access("telemetry/valve", "WRITE", "token")
        show_decision(late.send(late.build_request("telemetry/valve", "WRITE", "token")))
        late.access("actuator/valve", "OPEN", "token")
        show_decision(late.send(late.build_request("actuator/valve", "OPEN", "token")))

        # ----------------------------------------------------------------------------- 7
        step(7, "Successful and denied resource-access decisions (identity != authorization)")
        for dev, res, op in [(temp, "telemetry/temperature", "WRITE"),
                             (temp, "production-line", "STOP"),
                             (devices["motor-01"], "production-line", "STOP"),
                             (devices["valve-01"], "actuator/valve", "OPEN")]:
            show_decision(dev.access(res, op))
        fog_log("temp-01 STOP: identity checks all OK, only the policy failed -> DENY")

        # ----------------------------------------------------------------------------- 8
        step(8, "Revocation: blocked immediately, then left out of the next epoch")
        show_decision(cam.access("stream/video", "WRITE"))
        fog.revoke_device(cam.did, "camera firmware compromised")
        fog_log("operator REVOKED cam-01")
        show_decision(cam.access("stream/video", "WRITE"))
        fog_log("old proof still verifies (history), but current authorization is withdrawn")
        s2 = fog.finalize_epoch()
        fog_log(f"epoch {s2['epoch_id']} ROOT = {short(s2['root'], 24)}  leaves={s2['leaf_count']}  "
                f"excluded (revoked) = {len(s2['excluded_revoked'])}")
        fog_log(f"epoch 1 root still on the ledger (audit history): {short(node.registry.get_root(1), 24)}")
        late.fetch_proof()
        fog_log("valve-02 now holds a permanent epoch-2 proof, so actuator control is allowed:")
        show_decision(late.access("actuator/valve", "OPEN"))

        # ----------------------------------------------------------------------------- 9
        step(9, "Attack demonstrations (fresh fog, over TLS)")
        a_fog, a_devices, a_late = attacks.setup(use_https=True)
        for attack in (attacks.attack_replay, attacks.attack_tamper, attacks.attack_stolen_token,
                       attacks.attack_expired_revoked, attacks.attack_bonus):
            attack(a_fog, a_devices, a_late)
        attacks.banner("ATTACK SUMMARY")
        for name, decision, by, held in attacks.RESULTS:
            print(f"  [{'HELD' if held else 'FAIL'}] {name[:52]:<52} {decision:<5} {by or '-'}")
        print(f"\n  {sum(h for *_, h in attacks.RESULTS)}/{len(attacks.RESULTS)} defences held")
        if attacks.SERVER:
            attacks.SERVER.shutdown()

        # ----------------------------------------------------------------------------- 10
        step(10, "Performance / scalability results")
        try:
            import csv
            with open("results/summary.csv") as f:
                rows = list(csv.DictReader(f))
            print(f"  {'devices':>7} {'batch ms':>9} {'verify ms':>10} {'token ms':>9} "
                  f"{'access ms':>10} {'reg/s':>7} {'verify/s':>9}")
            for r in rows:
                print(f"  {r['devices']:>7} {float(r['batch_processing_ms_mean']):>9.3f} "
                      f"{float(r['verification_latency_ms_mean']):>10.4f} "
                      f"{float(r['token_validation_ms_mean']):>9.4f} "
                      f"{float(r['resource_access_latency_ms_mean']):>10.3f} "
                      f"{float(r['registration_throughput_per_s_mean']):>7.0f} "
                      f"{float(r['verification_throughput_per_s_mean']):>9.0f}")
            with open("results/batch_vs_individual.csv") as f:
                rows = list(csv.DictReader(f))
            print(f"\n  {'devices':>7} {'individual ms':>14} {'root anchors':>13} {'stale proofs':>13} "
                  f"{'batch ms':>9} {'speed-up':>9}")
            for r in rows:
                print(f"  {r['devices']:>7} {float(r['individual_time_ms']):>14.2f} "
                      f"{r['individual_root_updates']:>13} {r['individual_stale_proofs']:>13} "
                      f"{float(r['batch_time_ms']):>9.2f} {float(r['speedup']):>8.1f}x")
            print("\n  Graphs: results/graph1_batch_time.png, graph2_verification_latency.png,")
            print("          graph3_throughput.png, graph4_batch_vs_individual.png")
        except FileNotFoundError:
            print("  No results yet. Run: python3 benchmark.py && python3 batch_vs_individual.py "
                  "&& python3 plot_results.py")
    finally:
        server.shutdown()


if __name__ == "__main__":
    main()