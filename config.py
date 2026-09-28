import hmac
import hashlib

ZONE_ID = "factory-A"
MASTER_SECRET = b"zone-A-master-secret-change-me"
PSK_TIME_WINDOW_S = 60   
CHALLENGE_TTL_S = 30   
ALLOWED_DEVICE_TYPES = {"temperature-sensor", "pressure-sensor", "smart-meter", "camera",
                        "valve-controller", "motor-controller", "plc"}
REQUIRED_METADATA = ["type", "zone", "vendor", "model", "firmware"]

def provision_psk(device_name):
    """Simulates the factory: the secret PSK programmed into each device."""
    return hmac.new(MASTER_SECRET, device_name.encode(), hashlib.sha256).digest()

TOKEN_TTL_S = 300             # default temporary-token lifetime (seconds)
TOKEN_MAX_TTL_S = 900         # a device may ask for shorter, never longer
NONCE_TTL_S = 30              # how long a request nonce stays valid

FOG_HOST = "127.0.0.1"
FOG_PORT = 8443
CA_CERT = "certs/ca.pem"          # devices trust this
FOG_CERT = "certs/fog.pem"        # the fog's TLS certificate
FOG_KEY = "certs/fog-key.pem"     # the fog's TLS private key (never share)
ADMIN_API_KEY = "admin-demo-key"  # operator actions: finalize epoch, revoke