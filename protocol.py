from crypto_utils import hmac_sha256_hex, canonical_json, sha256_hex


def psk_auth_mac(device_name, psk, timestamp):
    """What the device sends instead of its PSK: HMAC(PSK, "name|timestamp")."""
    return hmac_sha256_hex(psk, f"{device_name}|{timestamp}".encode())


def pop_message(session_id, challenge, pk_hex):
    """The exact bytes the device signs to prove it owns its private key (onboarding)."""
    return b"IIOT-POP|" + canonical_json({"session_id": session_id,
                                          "challenge": challenge,
                                          "public_key": pk_hex})


def token_hash(token):
    return sha256_hex(token.encode())


def access_message(mode, did, nonce, resource, operation, epoch_id=None, token=None):
    """What a device signs for EVERY resource request.
    Binding nonce + resource + operation (+ epoch or H(token)) means a captured
    signature can't be reused for a different request, resource or token."""
    body = {"mode": mode, "did": did, "nonce": nonce,
            "resource": resource, "operation": operation}
    if mode == "proof":
        body["epoch_id"] = epoch_id          # Phase 3: proof-based request
    else:
        body["token_hash"] = token_hash(token)   # Phase 2: token-based request
    return b"IIOT-ACCESS|" + canonical_json(body)