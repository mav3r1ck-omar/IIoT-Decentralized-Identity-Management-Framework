import config
from device import Device
from fog_client import FogClient

fog = FogClient(admin_key=config.ADMIN_API_KEY)          # operator + devices, over HTTPS

print("--- Phase 1: onboarding over TLS ---")
devices = [Device("temp-01", "temperature-sensor", fog), Device("motor-01", "motor-controller", fog),
           Device("cam-01", "camera", fog), Device("plc-01", "plc", fog)]
for d in devices:
    d.register()
summary = fog.finalize_epoch()
print(f"[OPERATOR] epoch {summary['epoch_id']} closed, root {summary['root'][:24]}...")
for d in devices:
    d.fetch_proof()

print("\n--- Phase 3: requests over TLS ---")
temp, motor = devices[0], devices[1]
temp.access("telemetry/temperature", "WRITE")
temp.access("production-line", "STOP")
motor.access("production-line", "STOP")

print("\n--- Phase 2: late device with a token ---")
valve = Device("valve-02", "valve-controller", fog)
valve.register(want_token=True)
valve.access("telemetry/valve", "WRITE", "token")
valve.access("actuator/valve", "OPEN", "token")

print("\n--- Wrong PSK over TLS ---")
try:
    Device("rogue-01", "plc", fog, psk=b"guess").register()
except ValueError as e:
    print(f"  rogue-01 rejected by the fog: {e}")

chain = fog.chain()
print(f"\nLedger: {len(chain['blocks'])} block(s), chain valid = {chain['valid']}")