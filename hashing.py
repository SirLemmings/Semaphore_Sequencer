import hashlib
from typing import List
from collections import namedtuple


MerkleProof = namedtuple("MerkleProof", ["item", "index", "path"])


def sha256(preimage: bytes) -> bytes:
    return hashlib.sha256(preimage).digest()


def build_merkle_tree(data: List[bytes]) -> List[List[bytes]]:
    """builds a merkle tree from a list of elements"""
    if data == []:
        return []

    def tree_hash(base):
        base = [sha256(item) for item in base]
        if len(base) == 1:
            return [base]
        if len(base) % 2 == 1:
            base.append(base[-1])
        left = base[::2]
        right = base[1::2]
        new_layer = [left[i] + right[i] for i in range(len(left))]
        above_layers = tree_hash(new_layer)
        above_layers.append(base)
        return above_layers

    tree = tree_hash(data)
    tree.append(data)
    return tree


def construct_merkle_proof(tree: List[List[bytes]], item: bytes) -> MerkleProof:
    """constructs a merkle path for a item in the tree"""
    if item not in tree[-1]:
        raise Exception(f"{item} not in data of {tree[0][0]}")
    data_index = tree[-1].index(item)
    index = data_index
    path = []
    for layer in tree[-2:0:-1]:
        if index % 2 == 0:
            path.append(layer[index + 1])
        else:
            path.append(layer[index - 1])
        index //= 2
    path.append(tree[0][0])
    return MerkleProof(item, data_index, path)


def verify_proof(proof: MerkleProof) -> bool:
    """verifies a merkle proof"""
    item = proof[0]
    index = proof[1]
    path = proof[2]
    node = sha256(item)
    for sibling in path[:-1]:
        if index % 2 == 0:
            preimage = node + sibling
        else:
            preimage = sibling + node
        index //= 2
        node = sha256(preimage)
    return node == path[-1]
