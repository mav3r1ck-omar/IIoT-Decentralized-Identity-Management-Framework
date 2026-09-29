import json
import time

import config
from crypto_utils import (b64url_encode, b64url_decode, canonical_json, random_hex,
                          sign_json, verify_json)


class TokenService:
    """Issues and checks short-lived, fog-signed tokens for devices waiting for a proof."""

    def __init__(self, fog_id, fog_sk, fog_pk_hex, clock=time.time):
        self.fog_id = fog_id
        self.fog_sk = fog_sk              # signs tokens
        self.fog_pk_hex = fog_pk_hex      # checks tokens
        self.clock = clock                # real clock normally, fake clock in tests
        self.issued = {}                  # token_id -> did
        self.revoked = {}                 # token_id -> reason

    # ------------------------------------------------------------ issue
    def issue(self, record, scope, ttl_s=None):
        ttl = min(ttl_s or config.TOKEN_TTL_S, config.TOKEN_MAX_TTL_S)   # never longer than the max
        now = self.clock()
        payload = {
            "token_id": random_hex(12),
            "did": record["did"],
            "public_key": record["public_key"],        # binds the token to ONE key
            "device_type": record["metadata"]["type"],
            "scope": sorted(scope),                    # limited, provisional permissions
            "mode": "provisional",
            "issued_at": now,
            "expires_at": now + ttl,
            "fog_id": self.fog_id,
        }
        signature = sign_json(self.fog_sk, payload)
        token = b64url_encode(canonical_json({"payload": payload, "sig": signature}))
        self.issued[payload["token_id"]] = record["did"]
        return token

    # ------------------------------------------------------------ read
    @staticmethod
    def decode(token):
        obj = json.loads(b64url_decode(token))
        return obj["payload"], obj["sig"]

    # ------------------------------------------------------------ check
    def validate(self, token):
        """Order: format -> fog signature -> expiry -> revocation. Never crashes."""
        try:
            payload, sig = self.decode(token)
        except (ValueError, TypeError, KeyError):
            return {"ok": False, "reason": "TOKEN_MALFORMED", "payload": None}

        if not verify_json(self.fog_pk_hex, payload, sig):
            return {"ok": False, "reason": "TOKEN_SIGNATURE_INVALID", "payload": payload}
        if self.clock() > payload["expires_at"]:
            return {"ok": False, "reason": "TOKEN_EXPIRED", "payload": payload}
        if payload["token_id"] in self.revoked:
            return {"ok": False, "reason": "TOKEN_REVOKED", "payload": payload}
        return {"ok": True, "reason": "TOKEN_VALID", "payload": payload}

    # ------------------------------------------------------------ revoke
    def revoke(self, token_id, reason="revoked by operator"):
        if token_id not in self.issued:
            return False
        self.revoked[token_id] = reason
        return True

    def revoke_all_for(self, did, reason="device revoked"):
        ids = [tid for tid, owner in self.issued.items() if owner == did]
        for tid in ids:
            self.revoked[tid] = reason
        return ids