
# Single-Zone IIoT Decentralized Identity Management Framework

Assignment 1: one IIoT zone (`factory-A`), one fog node, and several simulated devices.
The code covers the whole identity lifecycle:

**device → fog → batch → Merkle root → anchored root → proof → token → verification → resource → revocation**

It also demonstrates attacks and evaluates performance.

---

## 1. Setup

Requires Python 3.10 or newer.

```bash
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python3 gen_certs.py               # creates certs/: zone CA + fog TLS certificate
```

If you upgrade Python or get a certificate error, delete the old certificates and regenerate them:
`rm -rf certs && python3 gen_certs.py`.

## 2. Exact commands

| What                                                      | Command                                                          |
| --------------------------------------------------------- | ---------------------------------------------------------------- |
| **Live demo**: the 10 required steps, over HTTPS    | `python3 demo.py`                                              |
| Live demo with a pause after each step                    | `python3 demo.py --step`                                       |
| Fog server only (terminal 1)                              | `python3 server.py`                                            |
| Devices against the running server (terminal 2)           | `python3 run_devices.py`                                       |
| **Attacks**, in-process                             | `python3 attacks.py`                                           |
| **Attacks** over HTTPS                              | `python3 attacks.py --https`                                   |
| **Performance benchmark** (5 runs per device count) | `python3 benchmark.py` or `python3 benchmark.py 5 10 50 100` |
| **Batch vs individual**                             | `python3 batch_vs_individual.py`                               |
| **Graphs** (from the CSV files)                     | `python3 plot_results.py`                                      |

Results are written to `results/`:

- `summary.csv`, `raw_measurements.csv`, `batch_vs_individual.csv`
- `graph1_batch_time.png`
- `graph2_verification_latency.png`
- `graph3_throughput.png`
- `graph4_batch_vs_individual.png`

## 3. Files

| File                                                              | Role                                                                                   |
| ----------------------------------------------------------------- | -------------------------------------------------------------------------------------- |
| `config.py`                                                     | Every parameter: zone, TTLs, device types, host/port, admin key                        |
| `crypto_utils.py`                                               | ECDSA P-256 keys and signatures, SHA-256, canonical JSON, DID and leaf`H(DID‖PK)`   |
| `protocol.py`                                                   | Exact bytes that are signed for proof-of-possession and for access requests            |
| `merkle.py`                                                     | Sorted binary Merkle tree, inclusion proofs, proof verification                        |
| `registry.py`                                                   | Hash-chained local ledger that stores the fog-signed root of each epoch                |
| `onboarding.py`                                                 | PSK-HMAC bootstrap → public key → PoP challenge → DID and metadata checks           |
| `batch_manager.py`                                              | Epoch batches: finalize = sort → tree → root → anchor → proof packages             |
| `token_service.py`                                              | Temporary tokens: issue, validate (signature, expiry, revocation)                      |
| `nonce_store.py`                                                | Single-use nonces issued by the fog (replay protection)                                |
| `revocation.py`                                                 | Device revocation list                                                                 |
| `policy.py`                                                     | Role-based access policy with provisional (token) restrictions                         |
| `verifier.py`                                                   | Phase 3 pipeline: every check recorded, then ALLOW or DENY                             |
| `fog_node.py`                                                   | Fog node that combines all the services                                                |
| `server.py`                                                     | Flask HTTPS server (TLS 1.2+) exposing the fog node                                    |
| `fog_client.py`                                                 | HTTPS client with the same methods as`FogNode`                                       |
| `device.py`                                                     | Simulated IIoT device: keys, DID, PoP, proof package, signed requests                  |
| `run_devices.py`                                                | Several devices talking to a running`server.py`                                      |
| `attacks.py`                                                    | Replay, tampering, stolen token, expired/revoked, plus bonus onboarding/ledger attacks |
| `demo.py`                                                       | The 10-step live demo with fog-side logs                                               |
| `gen_certs.py`                                                  | Private zone CA and fog TLS certificate                                                |
| `benchmark.py`, `batch_vs_individual.py`, `plot_results.py` | Performance evaluation and graphs                                                      |

## 4. How it works

**Phase 1: registration and batching**

1. The device authenticates with `HMAC(PSK, name|timestamp)`. The window is 60 s, and each MAC is accepted only once.
2. It sends its public key and signs the fog's fresh challenge (proof-of-possession).
3. It submits `did:iiot:factory-A:<sha256(pk)[:20]>` and its metadata. The fog queues the leaf `H(DID|PK)` in the open epoch.
4. When the window closes, the fog:
   - sorts the leaves and builds the tree;
   - anchors the root in the ledger, signed by the fog;
   - gives each device a signed proof package: DID, PK, epoch, root, sibling path.

**Phase 2: temporary access.** A device that joins while an epoch is still open gets a fog-signed token. The token:

- lasts 300 s (maximum 900 s);
- is limited to provisional permissions;
- is bound to the device's public key.

**Phase 3: verification.** Each request needs a fresh nonce issued by the fog, and is signed by the device.

| Mode  | Checks, in this order                                                                                                       |
| ----- | --------------------------------------------------------------------------------------------------------------------------- |
| Proof | nonce → Merkle proof against the anchored root → PoP signature → not revoked → active → policy                         |
| Token | token signature, expiry and revocation → device not revoked → nonce → PoP with the token's key → token scope and policy |

A valid identity is not the same as authorization. For example, a temperature sensor with a perfect proof is still denied `STOP production-line`.

**Revocation** takes effect immediately at the verifier. A revoked device is also left out of the next epoch's tree. Old roots stay on the ledger as audit history.

## 5. Cryptographic primitives

| Purpose                                                     | Primitive                                        |
| ----------------------------------------------------------- | ------------------------------------------------ |
| Device and fog key pairs                                    | ECC NIST P-256                                   |
| Signatures (PoP, requests, tokens, proof packages, anchors) | ECDSA with SHA-256                               |
| Leaves, tree nodes, block hashes                            | SHA-256 (tree nodes are`H(0x01‖left‖right)`) |
| Bootstrap authentication                                    | Per-device PSK,`HMAC-SHA256`                   |
| Transport                                                   | TLS 1.2+ with a private zone CA                  |
| Serialization                                               | Canonical JSON (sorted keys, no whitespace)      |

## 6. HTTP API (fog node)

| Method | Path                                              | Purpose                                                                     |
| ------ | ------------------------------------------------- | --------------------------------------------------------------------------- |
| POST   | `/register/start`                               | PSK bootstrap                                                               |
| POST   | `/register/pubkey`                              | Send the public key, receive the PoP challenge                              |
| POST   | `/register/pop`                                 | Send the signature over the challenge                                       |
| POST   | `/register/submit`                              | Send DID and metadata; leaf is queued (optionally with a token)             |
| POST   | `/proof`                                        | Fetch your own proof package                                                |
| POST   | `/access/challenge`                             | Get a fresh nonce                                                           |
| POST   | `/access/request`                               | Access in`proof` or `token` mode → ALLOW/DENY with each check's result |
| POST   | `/admin/finalize`                               | Close the epoch and anchor its root (admin)                                 |
| POST   | `/admin/revoke-device`, `/admin/revoke-token` | Revocation (admin)                                                          |
| GET    | `/registry/chain`                               | Inspect the ledger                                                          |

Admin routes require the header `X-Admin-Key` (the demo key is in `config.py`).

## 7. Design decisions and simplifications

- **Binary Merkle tree instead of a Sparse Merkle Tree.** It is enough to prove membership. Removal is handled by the revocation list plus exclusion from the next epoch.
- **Local hash-chained ledger instead of Quorum/Ethereum.** Roots are append-only and fog-signed; editing any block breaks `verify_chain`.
- **Epochs are closed by the operator** (`/admin/finalize`) rather than by a timer, so the demo is deterministic.
- **The PSK is derived from a master secret** for the simulation. A real deployment would provision a PSK per device at manufacture.
- **Commit–reveal and multi-zone roaming are left to Assignment 2.**

## 8. Team

| Member         | Main components                                                                                                        |
| ------------   | ---------------------------------------------------------------------------------------------------------------------- |
| Omar Malik     | Crypto utilities, protocol, Merkle tree, registry, onboarding, batch manager, TLS certificates, performance evaluation |
| Shaheer Shaban | Tokens, nonces, revocation, device client, attacks, live demo                                                          |
| Hammad Ahmed   | Access policy, verifier, fog node, HTTPS server and client, device runner, README                                      |
