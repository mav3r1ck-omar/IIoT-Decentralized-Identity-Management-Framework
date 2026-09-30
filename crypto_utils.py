import hashlib
import json
import secrets
import hmac
import base64
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.exceptions import InvalidSignature

def sha256_hex(data:bytes)->str:
    return hashlib.sha256(data).hexdigest()

def generate_keypair():
    return ec.generate_private_key(ec.SECP256R1())

def public_key_hex(sk)->str:
    pk=sk.public_key()
    return pk.public_bytes(serialization.Encoding.X962,serialization.PublicFormat.UncompressedPoint).hex()

def sign(sk,data:bytes)->str:
    return sk.sign(data,ec.ECDSA(hashes.SHA256())).hex()

def verify(pk_hex:str,data:bytes,sig_hex:str)->bool:
    try:
        pk=ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(),bytes.fromhex(pk_hex))
        sig=bytes.fromhex(sig_hex)
        pk.verify(sig,data,ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature,ValueError,TypeError):
        return False

def compute_leaf(did:str,pk_hex:str)->str:
    leaf_str=did+"|"+pk_hex
    leaf_str_bytes=leaf_str.encode()
    return sha256_hex(leaf_str_bytes)

def make_did(zone_id:str,pk_hex:str)->str:
    return f"did:iiot:{zone_id}:{sha256_hex(bytes.fromhex(pk_hex))[:20]}"

def canonical_json(obj)->bytes:
    return json.dumps(obj,sort_keys=True,separators=(",",":")).encode()

def random_hex(n_bytes:int=16)->str:
    return secrets.token_hex(n_bytes)

def sign_json(sk,obj)->str:
    return sign(sk,canonical_json(obj))

def verify_json(pk_hex:str,obj,sig_hex:str)->bool:
    return verify(pk_hex,canonical_json(obj),sig_hex)

def hmac_sha256_hex(key: bytes, msg: bytes) -> str:
    """Keyed hash: only someone who knows `key` can produce this value."""
    return hmac.new(key, msg, hashlib.sha256).hexdigest()

def is_valid_public_key(pk_hex: str) -> bool:
    """True if pk_hex is a real point on the P-256 curve."""
    try:
        ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), bytes.fromhex(pk_hex))
        return True
    except (ValueError, TypeError):      # bad hex, wrong length, or not on the curve
        return False

def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def b64url_decode(text: str) -> bytes:
    padding = "=" * (-len(text) % 4)          # put back the '=' padding we removed
    return base64.urlsafe_b64decode(text + padding)