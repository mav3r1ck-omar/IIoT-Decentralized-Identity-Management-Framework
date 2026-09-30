from crypto_utils import sha256_hex

def hash_pair(left_hex,right_hex)->str:
    pair=b"\x01"+bytes.fromhex(left_hex)+bytes.fromhex(right_hex)
    return sha256_hex(pair)

def next_level(level)->list:
    new_level=[]
    for i in range(0,len(level),2):
        if(i+1)<len(level):
            new_level.append(hash_pair(level[i],level[i+1]))
        else:
            new_level.append(level[i])

    return new_level

def build_levels(leaves)->list:
    if not leaves:
       raise ValueError('error:--leaves empty--')
    elif len(leaves)!=len(set(leaves)):
        raise ValueError('error:--duplicate devices in leaf list--')

    levels=[sorted(leaves)]
    while len(levels[-1])>1:
        levels.append(next_level(levels[-1]))

    return levels

def merkle_root(leaves)->str:
    levels=build_levels(leaves)
    return levels[-1][0]

def get_proof(levels,leaf)->list:
    proof=[]
    i=levels[0].index(leaf)

    for level in levels[:-1]:
        if i%2==0:
            if i+1<len(level):
                proof.append({"hash":level[i+1],"side":"R"})
        else:
            proof.append({"hash":level[i-1],"side":"L"})
        i=i//2

    return proof

def compute_root_from_proof(leaf,proof)->str:
    cur=leaf
    for step in proof:
        if step["side"]=="L":
            cur=hash_pair(step["hash"],cur)
        elif step["side"]=="R":
            cur=hash_pair(cur,step["hash"])
        else:
            raise ValueError

    return cur

def verify_proof(leaf,proof,root)->bool:
    try:
        if compute_root_from_proof(leaf,proof)==root:
            return True
        else:
            return False
    except (KeyError,ValueError,TypeError):
        return False
