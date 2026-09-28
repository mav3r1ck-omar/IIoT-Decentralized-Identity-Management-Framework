import hmac
import time

import config
from crypto_utils import random_hex, verify, make_did, compute_leaf, is_valid_public_key
from protocol import psk_auth_mac, pop_message


class OnboardingService:
    """Fog-side onboarding: PSK -> public key -> challenge -> PoP -> DID + metadata."""

    def __init__(self, zone_id):
        self.zone_id = zone_id
        self.sessions = {}          # session_id -> dict with the session's progress
        self.used_macs = set()      # bootstrap messages already seen (replay protection)

    # ------------------------------------------------------------ helper
    def _get_session(self, session_id, expected_state):
        """Return the session only if it exists AND is at the expected step."""
        s = self.sessions.get(session_id)
        if s is None:
            raise ValueError("unknown session")
        if s["state"] != expected_state:
            raise ValueError(f"wrong step: session is {s['state']}, expected {expected_state}")
        return s

    # ------------------------------------------------------------ step 1-2: PSK
    def start(self, device_name, timestamp, mac):
        # 1. message must be recent (stops very old recorded messages)
        if abs(time.time() - timestamp) > config.PSK_TIME_WINDOW_S:
            raise ValueError("bootstrap timestamp outside allowed window")

        # 2. recompute the MAC the real device would send, compare safely
        expected = psk_auth_mac(device_name, config.provision_psk(device_name), timestamp)
        if not hmac.compare_digest(mac, expected):
            raise ValueError("PSK authentication failed")

        # 3. each bootstrap message may be used only once
        if mac in self.used_macs:
            raise ValueError("bootstrap message replayed")
        self.used_macs.add(mac)

        # 4. open a new session
        session_id = random_hex(16)
        self.sessions[session_id] = {
            "device_name": device_name,
            "state": "AUTHENTICATED",
            "created": time.time(),
        }
        return session_id

    # ------------------------------------------------------------ step 4-5a: public key
    def submit_public_key(self, session_id, pk_hex):
        s = self._get_session(session_id, "AUTHENTICATED")
        if not is_valid_public_key(pk_hex):
            raise ValueError("invalid public key")

        s["public_key"] = pk_hex
        s["challenge"] = random_hex(32)                               # fresh, unpredictable
        s["challenge_expires"] = time.time() + config.CHALLENGE_TTL_S
        s["state"] = "CHALLENGED"
        return s["challenge"]

    # ------------------------------------------------------------ step 5b: proof-of-possession
    def verify_pop(self, session_id, signature):
        s = self._get_session(session_id, "CHALLENGED")

        if time.time() > s["challenge_expires"]:
            s["state"] = "FAILED"
            raise ValueError("challenge expired")

        msg = pop_message(session_id, s["challenge"], s["public_key"])
        s["challenge"] = None                                         # single use

        if not verify(s["public_key"], msg, signature):
            s["state"] = "FAILED"
            raise ValueError("proof-of-possession failed")

        s["state"] = "POP_VERIFIED"
        return True

    # ------------------------------------------------------------ step 6: DID + metadata
    def submit_identity(self, session_id, did, metadata):
        s = self._get_session(session_id, "POP_VERIFIED")

        # the DID must belong to the key that was just proven
        if did != make_did(self.zone_id, s["public_key"]):
            raise ValueError("DID is not bound to the proven public key")

        # metadata validation
        for field in config.REQUIRED_METADATA:
            if not metadata.get(field):
                raise ValueError(f"metadata missing field: {field}")
        if metadata["type"] not in config.ALLOWED_DEVICE_TYPES:
            raise ValueError(f"device type '{metadata['type']}' not allowed")
        if metadata["zone"] != self.zone_id:
            raise ValueError(f"device belongs to zone '{metadata['zone']}', not '{self.zone_id}'")

        # step 7: the device leaf
        record = {
            "did": did,
            "public_key": s["public_key"],
            "device_name": s["device_name"],
            "metadata": metadata,
            "leaf": compute_leaf(did, s["public_key"]),
        }
        del self.sessions[session_id]          # onboarding finished
        return record