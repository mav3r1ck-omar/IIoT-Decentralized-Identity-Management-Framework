import config
from crypto_utils import generate_keypair, public_key_hex
from registry import RootRegistry
from onboarding import OnboardingService
from batch_manager import EpochBatchManager
from token_service import TokenService
from nonce_store import NonceStore
from policy import AccessPolicy
from revocation import RevocationList
from verifier import Verifier


class FogNode:
    """One object that owns every fog service. The rest of the project talks only to this."""

    def __init__(self, fog_id="fog-A1", zone_id=config.ZONE_ID, registry=None):
        self.fog_id = fog_id
        self.sk = generate_keypair()                 # the fog's own identity key
        self.pk_hex = public_key_hex(self.sk)
        self.registry = registry or RootRegistry()
        self.registry.register_signer(fog_id, self.pk_hex)
        self.onboarding = OnboardingService(zone_id)
        self.batch = EpochBatchManager(fog_id, self.sk, self.registry)
        self.tokens = TokenService(fog_id, self.sk, self.pk_hex)
        self.nonces = NonceStore()
        self.policy = AccessPolicy()
        self.revocations = RevocationList()
        self.verifier = Verifier(self.registry, self.tokens, self.nonces, self.policy,
                                 self.revocations, self.batch)

    # ---- Phase 1 + 2 ----
    def complete_registration(self, record, want_token=False, token_ttl=None):
        """After onboarding: queue the device for the batch, optionally bridge it with a token."""
        if self.revocations.is_revoked(record["did"]):
            raise ValueError("device is revoked")
        epoch = self.batch.add_to_batch(record)
        result = {"did": record["did"], "epoch_id": epoch, "status": "PENDING"}
        if want_token:
            scope = self.policy.provisional_scope(record["metadata"]["type"])
            result["token"] = self.tokens.issue(record, scope, token_ttl)
        return result

    def finalize_epoch(self):
        return self.batch.finalize_epoch(self.revocations.dids())    # revoked devices left out

    def get_proof_package(self, did):
        return self.batch.get_package(did)

    # ---- Phase 2 + 3 ----
    def get_challenge(self, did):
        return self.nonces.issue(did)

    def access(self, request):
        if request.get("mode") == "proof":
            return self.verifier.access_with_proof(request)
        if request.get("mode") == "token":
            return self.verifier.access_with_token(request)
        raise ValueError("mode must be 'proof' or 'token'")

    # ---- revocation ----
    def revoke_device(self, did, reason):
        self.revocations.revoke_device(did, reason)       # layer 1: blocked immediately
        return self.tokens.revoke_all_for(did, reason)    # its tokens die too

    def revoke_token(self, token_id, reason):
        return self.tokens.revoke(token_id, reason)

        # ---- device-facing API for onboarding (each maps to one HTTPS route in Lesson 11) ----
    def register_start(self, device_name, timestamp, mac):
        return self.onboarding.start(device_name, timestamp, mac)

    def register_pubkey(self, session_id, pk_hex):
        return self.onboarding.submit_public_key(session_id, pk_hex)

    def register_pop(self, session_id, signature):
        return self.onboarding.verify_pop(session_id, signature)

    def register_submit(self, session_id, did, metadata, want_token=False, token_ttl=None):
        record = self.onboarding.submit_identity(session_id, did, metadata)
        result = self.complete_registration(record, want_token, token_ttl)
        result["leaf"] = record["leaf"]
        return result