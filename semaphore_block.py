import hashing as hs
import json
from typing import List, Type
from ecdsa import SigningKey
from wrappers import Alias, Sig, Hash32, ChainCommit, StrippedBroadcast, BCPointer
import params as pm


class SemaphoreBlock:
    def __init__(
        self,
        processed_broadcasts: List[StrippedBroadcast],
        processed_replies: List[StrippedBroadcast],
        processed_broadcasts_sigs: List[Sig],
        processed_replies_sigs: List[Sig],
        chain_commit: ChainCommit,
        checkpoint: Hash32,
        timestamp: int,
        signature: Sig = Sig(b"\x00" * pm.SIG_LENGTH),
    ):
        """create identity block from processed alias mints and updates"""
        broadcasts = [bytes(bc.alias) + bc.message for bc in processed_broadcasts]
        replies = [
            bytes(bc.alias) + bytes(bc.parent) + bc.message for bc in processed_replies
        ]
        broadcasts_sigs = [bytes(sig) for sig in processed_broadcasts_sigs]
        replies_sigs = [bytes(sig) for sig in processed_replies_sigs]

        if len(broadcasts) > 0:
            bc_tree = hs.build_merkle_tree(broadcasts)
            sig_tree = hs.build_merkle_tree(broadcasts_sigs)
            self.broadcasts_root = bc_tree[0][0]
            self.broadcasts_sigs_root = sig_tree[0][0]
            self.broadcasts_body = bc_tree[-1]
            self.broadcasts_sigs_body = sig_tree[-1]
        else:
            self.broadcasts_root = hs.sha256(b"")
            self.broadcasts_sigs_root = hs.sha256(b"")
            self.broadcasts_body = []
            self.broadcasts_sigs_body = []

        if len(replies) > 0:
            bc_tree = hs.build_merkle_tree(replies)
            sig_tree = hs.build_merkle_tree(replies_sigs)
            self.replies_root = bc_tree[0][0]
            self.replies_sigs_root = sig_tree[0][0]
            self.replies_body = bc_tree[-1]
            self.replies_sigs_body = sig_tree[-1]
        else:
            self.replies_root = hs.sha256(b"")
            self.replies_sigs_root = hs.sha256(b"")
            self.replies_body = []
            self.replies_sigs_body = []

        self.chain_commit = chain_commit
        self.checkpoint = checkpoint
        self.timestamp = timestamp.to_bytes(pm.DB_INT_LENGTH, byteorder="big")
        self.signature = signature

    def __str__(self) -> str:
        s = ""
        d = self.__dict__
        for key, value in d.items():
            s += f"{key}: {value.hex()}\n"
        return s

    def sign_block(self, privkey: SigningKey) -> None:
        """Signs the block with the given private key"""
        block_hash = bytes(self.block_hash())
        self.signature = Sig(privkey.sign(block_hash))

    def block_hash(self) -> Hash32:
        """Returns the hash of the block header"""
        preimage = (
            bytes(self.chain_commit)
            + bytes(self.checkpoint)
            + self.timestamp
            + self.broadcasts_root
            + self.replies_root
        )
        return Hash32(hs.sha256(preimage))

    def serialize(self) -> bytes:
        """Converts the block to a dictionary and returns serialization"""
        str_sequencer_signature = self.signature.hex()
        str_chain_commit = self.chain_commit.hex()
        str_checkpoint = self.checkpoint.hex()
        str_timestamp = self.timestamp.hex()

        str_broadcasts_root = self.broadcasts_root.hex()
        str_replies_root = self.replies_root.hex()
        str_broadcasts_body = [i.hex() for i in self.broadcasts_body]
        str_replies_body = [i.hex() for i in self.replies_body]

        str_broadcasts_sigs_root = self.broadcasts_sigs_root.hex()
        str_replies_sigs_root = self.replies_sigs_root.hex()
        str_broadcasts_sigs_body = [i.hex() for i in self.broadcasts_sigs_body]
        str_replies_sigs_body = [i.hex() for i in self.replies_sigs_body]

        block = {
            "sequencer_signature": str_sequencer_signature,
            "chain_commit": str_chain_commit,
            "checkpoint": str_checkpoint,
            "timestamp": str_timestamp,
            "broadcasts_root": str_broadcasts_root,
            "replies_root": str_replies_root,
            "broadcasts_body": str_broadcasts_body,
            "replies_body": str_replies_body,
            "broadcasts_sigs_root": str_broadcasts_sigs_root,
            "replies_sigs_root": str_replies_sigs_root,
            "broadcasts_sigs_body": str_broadcasts_sigs_body,
            "replies_sigs_body": str_replies_sigs_body,
        }
        return json.dumps(block).encode("utf-8")


def deserialize_block(serialized_block: bytes) -> SemaphoreBlock:
    """Converts a serialized block to a block object"""
    block = json.loads(serialized_block.decode("utf-8"))

    sequencer_signature = Sig(bytes.fromhex(block["sequencer_signature"]))
    chain_commit = ChainCommit(bytes.fromhex(block["chain_commit"]))
    checkpoint = Hash32(bytes.fromhex(block["checkpoint"]))
    timestamp = int.from_bytes(bytes.fromhex(block["timestamp"]), byteorder="big")

    broadcasts_body = [bytes.fromhex(i) for i in block["broadcasts_body"]]
    replies_body = [bytes.fromhex(i) for i in block["replies_body"]]
    broadcasts_sigs_body = [
        Sig(bytes.fromhex(i)) for i in block["broadcasts_sigs_body"]
    ]
    replies_sigs_body = [Sig(bytes.fromhex(i)) for i in block["replies_sigs_body"]]

    broadcasts_body = [
        StrippedBroadcast(
            Alias(bc[: pm.ALIAS_LENGTH]),
            BCPointer(int(0).to_bytes(pm.ALIAS_LENGTH + pm.DB_INT_LENGTH, "big")),
            bc[pm.ALIAS_LENGTH :],
        )
        for bc in broadcasts_body
    ]
    replies_body = [
        StrippedBroadcast(
            Alias(bc[: pm.ALIAS_LENGTH]),
            BCPointer(bc[pm.ALIAS_LENGTH : pm.ALIAS_LENGTH*2 + pm.DB_INT_LENGTH]),
            bc[pm.ALIAS_LENGTH*2 + pm.DB_INT_LENGTH :],
        )
        for bc in replies_body
    ]

    return SemaphoreBlock(
        broadcasts_body,
        replies_body,
        broadcasts_sigs_body,
        replies_sigs_body,
        chain_commit,
        checkpoint,
        timestamp,
        sequencer_signature,
    )
