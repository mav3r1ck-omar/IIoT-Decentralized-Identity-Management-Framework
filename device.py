import time

import config
from crypto_utils import generate_keypair, public_key_hex, make_did, sign
from protocol import psk_auth_mac, pop_message, access_message
from token_service import TokenService


class Device:
    """A simulated IIoT device. Its private key never leaves this object."""

    def __init__(self, name, dev_type, fog, psk=None, verbose=True):
        self.name = name
        self.type = dev_type
        self.fog = fog                                   # who we talk to (FogNode now, HTTPS client later)
        self.psk = psk if psk is not None else config.provision_psk(name)   # flashed at the factory
        self.sk = generate_keypair()
        self.pk = public_key_hex(self.sk)
        self.did = make_did(config.ZONE_ID, self.pk)
        self.metadata = {"type": dev_type, "zone": config.ZONE_ID, "vendor": "Acme",
                         "model": "X1", "firmware": "1.0"}
        self.token = None
        self.package = None
        self.last_request = None                         # attack scripts "capture" this
        self.verbose = verbose

    def log(self, msg):
        if self.verbose:
            print(f"  [DEVICE {self.name}] {msg}")

    # ------------------------------------------------------------ Phase 1 (+ optional Phase 2 token)
    def register(self, want_token=False, token_ttl=None):
        ts = int(time.time())
        sid = self.fog.register_start(self.name, ts, psk_auth_mac(self.name, self.psk, ts))
        self.log("PSK bootstrap accepted")
        challenge = self.fog.register_pubkey(sid, self.pk)
        self.fog.register_pop(sid, sign(self.sk, pop_message(sid, challenge, self.pk)))
        self.log("proof-of-possession verified by fog")
        result = self.fog.register_submit(sid, self.did, self.metadata, want_token, token_ttl)
        self.token = result.get("token")
        self.log(f"queued for epoch {result['epoch_id']}  leaf={result['leaf'][:16]}..."
                 + ("  + temporary token" if self.token else ""))
        return result

    def fetch_proof(self):
        self.package = self.fog.get_proof_package(self.did)
        if self.package:
            self.log(f"proof package for epoch {self.package['epoch_id']} "
                     f"({len(self.package['proof'])} sibling hashes)")
        return self.package

    @property
    def token_id(self):
        """Read the token's id (used when an operator revokes a single token)."""
        return TokenService.decode(self.token)[0]["token_id"] if self.token else None

    # ------------------------------------------------------------ Phase 2/3 requests
    def build_request(self, resource, operation, mode="proof"):
        nonce = self.fog.get_challenge(self.did)             # fresh nonce for EVERY request
        if mode == "proof":
            epoch = self.package["epoch_id"]
            msg = access_message("proof", self.did, nonce, resource, operation, epoch_id=epoch)
            req = {"mode": "proof", "did": self.did, "public_key": self.pk, "epoch_id": epoch,
                   "proof": self.package["proof"], "nonce": nonce,
                   "resource": resource, "operation": operation}
        else:
            msg = access_message("token", self.did, nonce, resource, operation, token=self.token)
            req = {"mode": "token", "token": self.token, "nonce": nonce,
                   "resource": resource, "operation": operation}
        req["signature"] = sign(self.sk, msg)                # proves the private key is here, now
        return req

    def send(self, request):
        self.last_request = request
        return self.fog.access(request)

    def access(self, resource, operation, mode="proof"):
        result = self.send(self.build_request(resource, operation, mode))
        self.log(f"{operation} {resource} [{mode}] -> {result['decision']}: {result['reason']}")
        return result