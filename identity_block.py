import hashing as hs
import json
from typing import List, Type
from ecdsa import SigningKey
from wrappers import Alias, Nym, Pubkey, Sig, Hash32
import params as pm


class IdentityBlock:
    def __init__(
        self,
        processed_mint_aliases: List[Alias],
        processed_mint_pubkeys: List[Pubkey],
        processed_update_aliases: List[Alias],
        processed_update_pubkeys: List[Pubkey],
        processed_update_sigs: List[Sig],
        processed_nym_aliases: List[Alias],
        processed_nym_nyms: List[Nym],
        processed_nym_sigs: List[Sig],
        prev_block_hash: Hash32,
        signature: Sig = Sig(b"\x00" * pm.SIG_LENGTH),
    ):
        """create identity block from processed alias mints and updates"""
        b_processed_mint_aliases = [bytes(alias) for alias in processed_mint_aliases]
        b_processed_mint_pubkeys = [bytes(pubkey) for pubkey in processed_mint_pubkeys]
        mint_aliases_tree = hs.build_merkle_tree(b_processed_mint_aliases)
        mint_pubkeys_tree = hs.build_merkle_tree(b_processed_mint_pubkeys)

        b_processed_update_aliases = [
            bytes(alias) for alias in processed_update_aliases
        ]
        b_processed_update_pubkeys = [
            bytes(pubkey) for pubkey in processed_update_pubkeys
        ]
        b_processed_update_sigs = [bytes(sig) for sig in processed_update_sigs]
        update_aliases_tree = hs.build_merkle_tree(b_processed_update_aliases)
        update_pubkeys_tree = hs.build_merkle_tree(b_processed_update_pubkeys)
        update_sigs_tree = hs.build_merkle_tree(b_processed_update_sigs)

        b_processed_nym_aliases = [bytes(alias) for alias in processed_nym_aliases]
        b_processed_nym_nyms = [bytes(nym) for nym in processed_nym_nyms]
        b_processed_nym_sigs = [bytes(sig) for sig in processed_nym_sigs]
        nym_aliases_tree = hs.build_merkle_tree(b_processed_nym_aliases)
        nym_nyms_tree = hs.build_merkle_tree(b_processed_nym_nyms)
        nym_sigs_tree = hs.build_merkle_tree(b_processed_nym_sigs)

        if len(mint_aliases_tree) > 0:
            self.mint_aliases_root = mint_aliases_tree[0][0]
            self.mint_pubkeys_root = mint_pubkeys_tree[0][0]
            self.mint_aliases_body = mint_aliases_tree[-1]
            self.mint_pubkeys_body = mint_pubkeys_tree[-1]
        else:
            self.mint_aliases_root = hs.sha256(b"")
            self.mint_pubkeys_root = hs.sha256(b"")
            self.mint_aliases_body = []
            self.mint_pubkeys_body = []

        if len(update_aliases_tree) > 0:
            self.update_aliases_root = update_aliases_tree[0][0]
            self.update_pubkeys_root = update_pubkeys_tree[0][0]
            self.update_sigs_root = update_sigs_tree[0][0]
            self.update_aliases_body = update_aliases_tree[-1]
            self.update_pubkeys_body = update_pubkeys_tree[-1]
            self.update_sigs_body = update_sigs_tree[-1]
        else:
            self.update_aliases_root = hs.sha256(b"")
            self.update_pubkeys_root = hs.sha256(b"")
            self.update_sigs_root = hs.sha256(b"")
            self.update_aliases_body = []
            self.update_pubkeys_body = []
            self.update_sigs_body = []

        if len(nym_aliases_tree) > 0:
            self.nym_aliases_root = nym_aliases_tree[0][0]
            self.nym_nyms_root = nym_nyms_tree[0][0]
            self.nym_sigs_root = nym_sigs_tree[0][0]
            self.nym_aliases_body = nym_aliases_tree[-1]
            self.nym_nyms_body = nym_nyms_tree[-1]
            self.nym_sigs_body = nym_sigs_tree[-1]
        else:
            self.nym_aliases_root = hs.sha256(b"")
            self.nym_nyms_root = hs.sha256(b"")
            self.nym_sigs_root = hs.sha256(b"")
            self.nym_aliases_body = []
            self.nym_nyms_body = []
            self.nym_sigs_body = []

        self.prev_block_hash = prev_block_hash
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
            bytes(self.prev_block_hash)
            + self.mint_aliases_root
            + self.mint_pubkeys_root
            + self.update_aliases_root
            + self.update_pubkeys_root
            + self.update_sigs_root
            + self.nym_aliases_root
            + self.nym_nyms_root
            + self.nym_sigs_root
        )
        return Hash32(hs.sha256(preimage))

    def serialize(self) -> bytes:
        """Converts the block to a dictionary and returns serialization"""
        str_sequencer_signature = bytes(self.signature).hex()
        str_prev_block_hash = bytes(self.prev_block_hash).hex()

        str_mint_aliases_root = self.mint_aliases_root.hex()
        str_mint_pubkeys_root = self.mint_pubkeys_root.hex()

        str_update_aliases_root = self.update_aliases_root.hex()
        str_update_pubkeys_root = self.update_pubkeys_root.hex()
        str_update_sigs_root = self.update_sigs_root.hex()

        str_nym_aliases_root = self.nym_aliases_root.hex()
        str_nym_nyms_root = self.nym_nyms_root.hex()
        str_nym_sigs_root = self.nym_sigs_root.hex()

        str_mint_aliases_body = [i.hex() for i in self.mint_aliases_body]
        str_mint_pubkeys_body = [i.hex() for i in self.mint_pubkeys_body]

        str_update_aliases_body = [i.hex() for i in self.update_aliases_body]
        str_update_pubkeys_body = [i.hex() for i in self.update_pubkeys_body]
        str_update_sigs_body = [i.hex() for i in self.update_sigs_body]

        str_nym_aliases_body = [i.hex() for i in self.nym_aliases_body]
        str_nym_nyms_body = [i.hex() for i in self.nym_nyms_body]
        str_nym_sigs_body = [i.hex() for i in self.nym_sigs_body]

        block = {
            "sequencer_signature": str_sequencer_signature,
            "prev_block_hash": str_prev_block_hash,
            "mint_aliases_root": str_mint_aliases_root,
            "mint_pubkeys_root": str_mint_pubkeys_root,
            "update_aliases_root": str_update_aliases_root,
            "update_pubkeys_root": str_update_pubkeys_root,
            "update_sigs_root": str_update_sigs_root,
            "nym_aliases_root": str_nym_aliases_root,
            "nym_nyms_root": str_nym_nyms_root,
            "nym_sigs_root": str_nym_sigs_root,
            "mint_aliases_body": str_mint_aliases_body,
            "mint_pubkeys_body": str_mint_pubkeys_body,
            "update_aliases_body": str_update_aliases_body,
            "update_pubkeys_body": str_update_pubkeys_body,
            "update_sigs_body": str_update_sigs_body,
            "nym_aliases_body": str_nym_aliases_body,
            "nym_nyms_body": str_nym_nyms_body,
            "nym_sigs_body": str_nym_sigs_body,
        }
        return json.dumps(block).encode("utf-8")


def deserialize_block(serialized_block: bytes) -> IdentityBlock:
    """Converts a serialized block to a block object"""
    block = json.loads(serialized_block.decode("utf-8"))

    sequencer_signature = Sig(bytes.fromhex(block["sequencer_signature"]))
    prev_block_hash = Hash32(bytes.fromhex(block["prev_block_hash"]))

    mint_aliases_body = [Alias(bytes.fromhex(i)) for i in block["mint_aliases_body"]]
    mint_pubkeys_body = [Pubkey(bytes.fromhex(i)) for i in block["mint_pubkeys_body"]]

    update_aliases_body = [
        Alias(bytes.fromhex(i)) for i in block["update_aliases_body"]
    ]
    update_pubkeys_body = [
        Pubkey(bytes.fromhex(i)) for i in block["update_pubkeys_body"]
    ]
    update_sigs_body = [Sig(bytes.fromhex(i)) for i in block["update_sigs_body"]]

    nym_aliases_body = [Alias(bytes.fromhex(i)) for i in block["nym_aliases_body"]]
    nym_nyms_body = [Nym(bytes.fromhex(i)) for i in block["nym_nyms_body"]]
    nym_sigs_body = [Sig(bytes.fromhex(i)) for i in block["nym_sigs_body"]]

    return IdentityBlock(
        mint_aliases_body,
        mint_pubkeys_body,
        update_aliases_body,
        update_pubkeys_body,
        update_sigs_body,
        nym_aliases_body,
        nym_nyms_body,
        nym_sigs_body,
        prev_block_hash,
        sequencer_signature,
    )
