import requests

import config


class FogClient:
    """Talks to the fog over HTTPS. Has the SAME methods as FogNode,
    so Device works with either one without any change."""

    def __init__(self, base_url=f"https://{config.FOG_HOST}:{config.FOG_PORT}", admin_key=None):
        self.base_url = base_url
        self.admin_key = admin_key
        self.http = requests.Session()
        self.http.trust_env = False            # ignore proxy settings for this local connection

    def _post(self, path, payload=None, admin=False):
        headers = {"X-Admin-Key": self.admin_key} if admin else {}
        r = self.http.post(self.base_url + path, json=payload or {}, headers=headers,
                           verify=config.CA_CERT,          # only trust a server signed by OUR CA
                           timeout=10)
        data = r.json()
        if r.status_code >= 400:
            raise ValueError(data.get("error", f"HTTP {r.status_code}"))
        return data

    # ---- onboarding ----
    def register_start(self, device_name, timestamp, mac):
        return self._post("/register/start", {"device_name": device_name, "timestamp": timestamp,
                                              "mac": mac})["session_id"]

    def register_pubkey(self, session_id, pk_hex):
        return self._post("/register/pubkey", {"session_id": session_id, "public_key": pk_hex})["challenge"]

    def register_pop(self, session_id, signature):
        return self._post("/register/pop", {"session_id": session_id, "signature": signature})["ok"]

    def register_submit(self, session_id, did, metadata, want_token=False, token_ttl=None):
        return self._post("/register/submit", {"session_id": session_id, "did": did, "metadata": metadata,
                                               "want_token": want_token, "token_ttl": token_ttl})

    def get_proof_package(self, did):
        return self._post("/proof", {"did": did})["package"]

    # ---- access ----
    def get_challenge(self, did):
        return self._post("/access/challenge", {"did": did})["nonce"]

    def access(self, request):
        return self._post("/access/request", request)

    # ---- operator ----
    def finalize_epoch(self):
        return self._post("/admin/finalize", admin=True)

    def revoke_device(self, did, reason):
        return self._post("/admin/revoke-device", {"did": did, "reason": reason}, admin=True)

    def revoke_token(self, token_id, reason):
        return self._post("/admin/revoke-token", {"token_id": token_id, "reason": reason}, admin=True)["ok"]

    def chain(self):
        return self.http.get(self.base_url + "/registry/chain", verify=config.CA_CERT, timeout=10).json()