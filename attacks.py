import copy
import json
import sys
import time

import config
from crypto_utils import generate_keypair, public_key_hex, sign, b64url_decode, b64url_encode, canonical_json
from protocol import access_message
from fog_node import FogNode
from device import Device
from fog_client import FogClient
from server import start_in_background

RESULTS = []
NODE = None          # the real FogNode (needed only for the ledger-tampering bonus)
SERVER = None        # the HTTPS server, when running with --https


def banner(title):
    print("\n" + "=" * 78 + f"\n  {title}\n" + "=" * 78)


def report(name, expected, result, expect_deny=True):
    """Print one attack attempt in the format the assignment asks for."""
    held = (result["decision"] == "DENY") if expect_deny else (result["decision"] == "ALLOW")
    failed = [k for k, v in result.get("checks", {}).items() if v is False]
    print(f"\n  ATTACK      : {name}")
    print(f"  expected    : {expected}")
    print(f"  decision    : {result['decision']}  ->  {result['reason']}")
    print(f"  detected by : {result.get('detected_by') or '-'}")
    if failed:
        print(f"  failed check: {failed}")
    print(f"  RESULT      : {'DEFENCE HELD' if held else '*** DEFENCE FAILED ***'}")
    RESULTS.append((name, result["decision"], result.get("detected_by"), held))


def setup(use_https=False):
    global NODE, SERVER
    banner("SETUP: 5 devices registered in epoch 1, one late device with a token"
           + ("  [over HTTPS]" if use_https else ""))
    NODE = FogNode()
    if use_https:
        port = config.FOG_PORT + 1
        SERVER = start_in_background(NODE, port)
        fog = FogClient(f"https://{config.FOG_HOST}:{port}", admin_key=config.ADMIN_API_KEY)
    else:
        fog = NODE
    devices = {n: Device(n, t, fog) for n, t in [("temp-01", "temperature-sensor"),
                                                 ("motor-01", "motor-controller"),
                                                 ("cam-01", "camera"),
                                                 ("press-01", "pressure-sensor"),
                                                 ("plc-01", "plc")]}
    for d in devices.values():
        d.register()
    summary = fog.finalize_epoch()
    print(f"  [FOG] epoch {summary['epoch_id']} closed: {summary['leaf_count']} leaves, root {summary['root'][:20]}...")
    for d in devices.values():
        d.fetch_proof()
    late = Device("valve-02", "valve-controller", fog)
    late.register(want_token=True)
    return fog, devices, late


# ---------------------------------------------------------------- ATTACK 1
def attack_replay(fog, devices, late):
    banner("ATTACK 1: Replay of an exact request")
    temp = devices["temp-01"]
    temp.access("telemetry/temperature", "WRITE")                 # legitimate, attacker records it
    captured = copy.deepcopy(temp.last_request)
    report("Replay a captured proof-mode request", "DENY - nonce already used", fog.access(captured))

    late.access("telemetry/valve", "WRITE", "token")
    captured = copy.deepcopy(late.last_request)
    report("Replay a captured token-mode request", "DENY - nonce already used (token still valid)",
           fog.access(captured))


# ---------------------------------------------------------------- ATTACK 2
def attack_tamper(fog, devices, late):
    banner("ATTACK 2: Tampered identity / proof")
    temp = devices["temp-01"]
    attacker_sk = generate_keypair()
    attacker_pk = public_key_hex(attacker_sk)

    def signed(did, pk, sk, epoch, proof):
        """Build a proof request with whatever (possibly fake) values the attacker chooses."""
        nonce = fog.get_challenge(did)
        msg = access_message("proof", did, nonce, "telemetry/temperature", "WRITE", epoch_id=epoch)
        return {"mode": "proof", "did": did, "public_key": pk, "epoch_id": epoch, "proof": proof,
                "nonce": nonce, "resource": "telemetry/temperature", "operation": "WRITE",
                "signature": sign(sk, msg)}

    pkg = temp.package
    fake_did = temp.did[:-1] + ("1" if temp.did[-1] == "0" else "0")
    report("Modified DID with the victim's proof", "DENY - leaf changes, root mismatch",
           fog.access(signed(fake_did, temp.pk, temp.sk, pkg["epoch_id"], pkg["proof"])))
    report("Victim DID + attacker public key", "DENY - H(DID|PK') not in the tree",
           fog.access(signed(temp.did, attacker_pk, attacker_sk, pkg["epoch_id"], pkg["proof"])))
    bad_proof = copy.deepcopy(pkg["proof"])
    bad_proof[0]["hash"] = "00" * 32
    report("One sibling hash changed", "DENY - reconstructed root != trusted root",
           fog.access(signed(temp.did, temp.pk, temp.sk, pkg["epoch_id"], bad_proof)))
    report("Proof for an epoch that was never anchored", "DENY - no trusted root",
           fog.access(signed(temp.did, temp.pk, temp.sk, 99, pkg["proof"])))

    obj = json.loads(b64url_decode(late.token))
    obj["payload"]["scope"].append("OPEN:actuator/valve")        # try to widen the token
    real_token = late.token
    late.token = b64url_encode(canonical_json(obj))
    result = late.send(late.build_request("actuator/valve", "OPEN", "token"))
    late.token = real_token
    report("Token payload edited (scope widened)", "DENY - fog signature on token breaks", result)


# ---------------------------------------------------------------- ATTACK 3
def attack_stolen_token(fog, devices, late):
    banner("ATTACK 3: Stolen valid temporary token used from another device")
    thief = Device("thief", "valve-controller", fog, verbose=False)
    thief.did, thief.token = late.did, late.token                  # copied DID + token, own key
    report("Stolen token, request signed with the thief's key",
           "DENY - signature does not match the key inside the token",
           thief.send(thief.build_request("telemetry/valve", "WRITE", "token")))
    report("Legitimate owner uses the same token (control case)", "ALLOW - owner holds the key",
           late.access("telemetry/valve", "WRITE", "token"), expect_deny=False)


# ---------------------------------------------------------------- ATTACK 4
def attack_expired_revoked(fog, devices, late):
    banner("ATTACK 4: Expired token, revoked token, revoked device")
    meter = Device("meter-99", "smart-meter", fog)
    meter.register(want_token=True, token_ttl=2)
    meter.access("telemetry/energy", "WRITE", "token")
    print("  ...waiting 3 s for the token to expire")
    time.sleep(3)
    report("Token used after expiry", "DENY - TOKEN_EXPIRED",
           meter.send(meter.build_request("telemetry/energy", "WRITE", "token")))

    late.access("telemetry/valve", "WRITE", "token")
    fog.revoke_token(late.token_id, "suspicious traffic")
    print(f"  [FOG] operator revoked token {late.token_id}")
    report("Token used after explicit revocation", "DENY - TOKEN_REVOKED",
           late.send(late.build_request("telemetry/valve", "WRITE", "token")))

    cam = devices["cam-01"]
    cam.access("stream/video", "WRITE")
    fog.revoke_device(cam.did, "camera firmware compromised")
    print("  [FOG] operator revoked device cam-01")
    report("Revoked device presents its old (still valid) proof",
           "DENY - merkle_proof_valid=True but not_revoked=False",
           cam.send(cam.build_request("stream/video", "WRITE")))


# ---------------------------------------------------------------- BONUS
def attack_bonus(fog, devices, late):
    banner("BONUS: wrong PSK, copied public key at enrollment, ledger tampering")

    def as_result(func):
        """Onboarding raises ValueError on rejection - turn that into a DENY result."""
        try:
            func()
            return {"decision": "ALLOW", "reason": "accepted"}
        except ValueError as e:
            return {"decision": "DENY", "reason": str(e)}

    rogue = Device("rogue-01", "plc", fog, psk=b"guessed-psk", verbose=False)
    r = as_result(rogue.register)
    r["detected_by"] = "onboarding - PSK bootstrap check"
    report("Unknown device with a wrong PSK", "DENY at bootstrap", r)

    insider = Device("insider-01", "plc", fog, verbose=False)
    insider.pk = devices["temp-01"].pk                            # claims temp-01's public key
    r = as_result(insider.register)                               # but signs with its own key
    r["detected_by"] = "onboarding - proof-of-possession"
    report("Enroll with a copied public key", "DENY - cannot sign the challenge", r)

    block = NODE.registry.blocks[0]
    saved = block["record"]["root"]
    block["record"]["root"] = "f" * 64                            # someone edits the ledger
    ok = NODE.registry.verify_chain()
    block["record"]["root"] = saved                               # put it back
    report("Edit an anchored root in the ledger", "DETECTED - chain check fails",
           {"decision": "DENY" if not ok else "ALLOW", "reason": "verify_chain() returned " + str(ok),
            "detected_by": "root registry - hash chain"})


def main():
    fog, devices, late = setup(use_https="--https" in sys.argv)
    for attack in (attack_replay, attack_tamper, attack_stolen_token, attack_expired_revoked, attack_bonus):
        attack(fog, devices, late)
    banner("SUMMARY")
    for name, decision, by, held in RESULTS:
        print(f"  [{'HELD' if held else 'FAIL'}] {name[:52]:<52} {decision:<5} {by or '-'}")
    print(f"\n  {sum(h for *_, h in RESULTS)}/{len(RESULTS)} defences held")
    if SERVER:
        SERVER.shutdown()

if __name__ == "__main__":
    main()