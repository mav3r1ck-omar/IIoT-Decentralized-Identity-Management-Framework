from crypto_utils import compute_leaf, verify
from merkle import verify_proof
from protocol import access_message


def decision(allow, reason, checks, mode, did, detected_by=None):
    """The standard answer for every request."""
    return {"decision": "ALLOW" if allow else "DENY", "reason": reason, "checks": checks,
            "mode": mode, "did": did, "detected_by": detected_by}


class Verifier:
    def __init__(self, registry, tokens, nonces, policy, revocations, batch):
        self.registry = registry
        self.tokens = tokens
        self.nonces = nonces
        self.policy = policy
        self.revocations = revocations
        self.batch = batch                    # to look up active devices and their role

    # ------------------------------------------------------------ identity only
    def verify_membership(self, did, pk_hex, epoch_id, proof):
        root = self.registry.get_root(epoch_id)          # trusted root from the ledger
        if root is None:
            return False, "UNKNOWN_EPOCH"
        leaf = compute_leaf(did, pk_hex)                 # NEVER trust a leaf sent by the device
        if not verify_proof(leaf, proof, root):
            return False, "MERKLE_PROOF_INVALID: reconstructed root != trusted root"
        return True, "MEMBERSHIP_OK"

    # ------------------------------------------------------------ Phase 3: proof mode
    def access_with_proof(self, req):
        checks = {}
        try:
            did, pk, epoch_id, proof = req["did"], req["public_key"], req["epoch_id"], req["proof"]
            nonce, sig, resource, op = req["nonce"], req["signature"], req["resource"], req["operation"]
        except (KeyError, TypeError):
            return decision(False, "MALFORMED_REQUEST", checks, "proof", None)

        # 1. freshness - stops replay
        ok, why = self.nonces.consume(nonce, did)
        checks["nonce_fresh"] = ok
        if not ok:
            return decision(False, why, checks, "proof", did, "nonce/request validator")

        # 2. membership - stops tampered DID / PK / proof / epoch
        ok, why = self.verify_membership(did, pk, epoch_id, proof)
        checks["merkle_proof_valid"] = ok
        if not ok:
            return decision(False, why, checks, "proof", did, "Merkle proof verification")

        # 3. proof-of-possession - the live requester holds the private key
        msg = access_message("proof", did, nonce, resource, op, epoch_id=epoch_id)
        checks["proof_of_possession"] = verify(pk, msg, sig)
        if not checks["proof_of_possession"]:
            return decision(False, "POP_FAILED: requester does not hold the private key",
                            checks, "proof", did, "proof-of-possession check")

        # 4. revocation - current authorization, even if the proof is historically valid
        checks["not_revoked"] = not self.revocations.is_revoked(did)
        if not checks["not_revoked"]:
            return decision(False, f"DEVICE_REVOKED ({self.revocations.reason(did)}): proof is "
                            f"historically valid but current authorization is withdrawn",
                            checks, "proof", did, "revocation checker")

        # 5. device status
        record = self.batch.active.get(did)
        checks["device_active"] = record is not None
        if record is None:
            return decision(False, "DEVICE_NOT_ACTIVE", checks, "proof", did, "device status check")

        # 6. authorization - identity is fine, but is THIS operation allowed?
        allowed, why = self.policy.evaluate(record["metadata"]["type"], resource, op, provisional=False)
        checks["policy"] = allowed
        return decision(allowed, why, checks, "proof", did, None if allowed else "access-control policy")

    # ------------------------------------------------------------ Phase 2: token mode
    def access_with_token(self, req):
        checks = {}
        try:
            token, nonce, sig = req["token"], req["nonce"], req["signature"]
            resource, op = req["resource"], req["operation"]
        except (KeyError, TypeError):
            return decision(False, "MALFORMED_REQUEST", checks, "token", None)

        # 1. token: signature, expiry, token revocation
        v = self.tokens.validate(token)
        checks["token_valid"] = v["ok"]
        payload = v["payload"] or {}
        did = payload.get("did")
        if not v["ok"]:
            return decision(False, v["reason"], checks, "token", did, "token validity/revocation checker")

        # 2. is the whole DEVICE revoked?
        checks["not_revoked"] = not self.revocations.is_revoked(did)
        if not checks["not_revoked"]:
            return decision(False, f"DEVICE_REVOKED ({self.revocations.reason(did)})", checks,
                            "token", did, "revocation checker")

        # 3. freshness
        ok, why = self.nonces.consume(nonce, did)
        checks["nonce_fresh"] = ok
        if not ok:
            return decision(False, why, checks, "token", did, "nonce/request validator")

        # 4. proof-of-possession with the key INSIDE the token - stops stolen tokens
        msg = access_message("token", did, nonce, resource, op, token=token)
        checks["proof_of_possession"] = verify(payload["public_key"], msg, sig)
        if not checks["proof_of_possession"]:
            return decision(False, "POP_FAILED: token used without the matching private key (stolen token)",
                            checks, "token", did, "proof-of-possession check")

        # 5. token scope + provisional policy
        checks["in_token_scope"] = f"{op}:{resource}" in payload["scope"]
        allowed, why = self.policy.evaluate(payload["device_type"], resource, op, provisional=True)
        if allowed and not checks["in_token_scope"]:
            allowed, why = False, "SCOPE_DENY: operation not in token scope"
        checks["policy"] = allowed
        return decision(allowed, why, checks, "token", did, None if allowed else "access-control policy")