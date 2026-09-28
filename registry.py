from crypto_utils import sha256_hex,canonical_json,verify_json

class RootRegistry:
    def __init__(self):
        self.blocks=[]
        self.signers={}

    def register_signer(self,fog_id,pk_hex):
        self.signers[fog_id]=pk_hex

    def block_hash(self,block):
        copy=dict(block)
        copy.pop("block_hash",None)
        return sha256_hex(canonical_json(copy))

    def get_root(self,epoch_id):
        for block in self.blocks:
            if epoch_id==block["record"]["epoch_id"]:
                return block["record"]["root"]
        
        return None
    
    def anchor(self,record,signature):
        if record["fog_id"] not in self.signers:
            raise ValueError
        elif verify_json(self.signers[record["fog_id"]],record,signature)!=True:
            raise ValueError
        elif self.get_root(record["epoch_id"]):
            raise ValueError

        if self.blocks==[]:
            prev_hash="0"*64
        else:
            prev_hash=self.blocks[-1]["block_hash"]

        self.blocks.append({"index":len(self.blocks),"prev_hash":prev_hash,"record":record,"signature":signature})

        self.blocks[-1]["block_hash"]=self.block_hash(self.blocks[-1])

        return self.blocks[-1]

    def latest_epoch(self):
        if self.blocks==[]:
            return 0
        else:
            return self.blocks[-1]["record"]["epoch_id"]

    def verify_chain(self):
        prev = "0" * 64               
        for block in self.blocks:
            if block["prev_hash"] != prev:
                return False
            if self.block_hash(block) != block["block_hash"]:
                return False
            
            fog_pk = self.signers.get(block["record"]["fog_id"]) 
            if fog_pk is None:                                   
                return False
            if not verify_json(fog_pk, block["record"], block["signature"]):
                return False

            prev = block["block_hash"]     

        return True              
    