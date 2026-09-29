import time

import config
from crypto_utils import random_hex


class NonceStore:
    """Fresh, fog-issued, single-use numbers. A replayed request carries a USED nonce."""

    def __init__(self, ttl_s=config.NONCE_TTL_S, clock=time.time):
        self.ttl = ttl_s
        self.clock = clock
        self.pending = {}      # nonce -> (did it was issued to, expiry time)
        self.used = set()      # nonces that have already been consumed

    def issue(self, did):
        nonce = random_hex(16)
        self.pending[nonce] = (did, self.clock() + self.ttl)
        return nonce

    def consume(self, nonce, did):
        """Returns (ok, reason). A nonce can succeed at most ONCE."""
        if nonce in self.used:
            return False, "NONCE_REUSED"               # replay attack
        entry = self.pending.pop(nonce, None)          # remove it: it can't be used again
        if entry is None:
            return False, "NONCE_UNKNOWN"              # the fog never issued it
        self.used.add(nonce)
        owner, expires = entry
        if self.clock() > expires:
            return False, "NONCE_EXPIRED"
        if owner != did:
            return False, "NONCE_WRONG_DEVICE"         # issued to someone else
        return True, "NONCE_FRESH"