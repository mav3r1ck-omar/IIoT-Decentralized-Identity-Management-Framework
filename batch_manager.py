from crypto_utils import sign_json
from merkle import build_levels, get_proof


class EpochBatchManager:
    """Collects devices during an epoch; at the end builds ONE tree, anchors ONE root,
    and hands every device a signed proof package."""

    def __init__(self, fog_id, fog_sk, registry):
        self.fog_id = fog_id
        self.fog_sk = fog_sk                               # fog's private key (signs anchors + packages)
        self.registry = registry                           # the RootRegistry from Lesson 5
        self.current_epoch = registry.latest_epoch() + 1   # continue after what's on the ledger
        self.pending = {}          # did -> record   joined THIS epoch, waiting for the batch to close
        self.active = {}           # did -> record   included in the latest finalized epoch
        self.trees = {}            # epoch_id -> levels   (old trees kept for history)
        self.proof_packages = {}   # did -> that device's latest proof package

    # ------------------------------------------------------------ during the epoch
    def add_to_batch(self, record):
        """O(1): just remember the device. NO tree is built here."""
        did = record["did"]
        if did in self.pending or did in self.active:
            raise ValueError("device already registered")
        self.pending[did] = record
        return self.current_epoch

    # ------------------------------------------------------------ helper
    def make_package(self, record, levels, epoch_id, root):
        """Everything a device needs later to prove membership, signed by the fog."""
        package = {
            "did": record["did"],
            "public_key": record["public_key"],
            "leaf": record["leaf"],
            "epoch_id": epoch_id,
            "root": root,
            "proof": get_proof(levels, record["leaf"]),
            "fog_id": self.fog_id,
        }
        # sign FIRST (over the package without a signature), THEN attach the signature
        package["fog_signature"] = sign_json(self.fog_sk, package)
        return package

    # ------------------------------------------------------------ end of the epoch
    def finalize_epoch(self, revoked_dids=frozenset()):
        # 1. everyone who should be in this epoch's tree: old active devices + new ones
        members = dict(self.active)
        members.update(self.pending)

        # 2. revoked devices are left out of the new tree (revocation layer 2)
        excluded = []
        for did in list(members):              # list(...) = safe to delete while looping
            if did in revoked_dids:
                excluded.append(did)
                del members[did]

        if not members:
            raise ValueError("nothing to finalize in this epoch")

        # 3. build the tree ONCE and take its root
        epoch_id = self.current_epoch
        leaves = [r["leaf"] for r in members.values()]
        levels = build_levels(leaves)
        root = levels[-1][0]

        # 4. anchor ONE root for the whole batch
        anchor_record = {"epoch_id": epoch_id, "root": root,
                         "leaf_count": len(leaves), "fog_id": self.fog_id}
        self.registry.anchor(anchor_record, sign_json(self.fog_sk, anchor_record))

        # 5. a proof package for every member
        for did, record in members.items():
            self.proof_packages[did] = self.make_package(record, levels, epoch_id, root)

        # 6. move to the next epoch
        new_devices = len(self.pending)        # count BEFORE clearing pending
        self.active = members
        self.pending = {}
        self.trees[epoch_id] = levels
        self.current_epoch += 1

        return {"epoch_id": epoch_id, "root": root, "leaf_count": len(leaves),
                "new_devices": new_devices, "excluded_revoked": excluded}

    # ------------------------------------------------------------ lookup
    def get_package(self, did):
        return self.proof_packages.get(did)    # None if the device has no package yet