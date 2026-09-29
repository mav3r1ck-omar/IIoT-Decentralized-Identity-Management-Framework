import time


class RevocationList:
    """Revocation layer 1: blocks a device IMMEDIATELY at the fog.
    (Layer 2 - leaving it out of the next root - is done by finalize_epoch.)"""

    def __init__(self, clock=time.time):
        self.clock = clock
        self.revoked = {}          # did -> {"reason", "revoked_at"}

    def revoke_device(self, did, reason):
        self.revoked[did] = {"reason": reason, "revoked_at": self.clock()}

    def is_revoked(self, did):
        return did in self.revoked

    def reason(self, did):
        entry = self.revoked.get(did)
        return entry["reason"] if entry else None

    def dids(self):
        return set(self.revoked)   # handed to finalize_epoch as revoked_dids