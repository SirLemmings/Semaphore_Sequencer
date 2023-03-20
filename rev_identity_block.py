import pickle
from wrappers import Sig, Alias, Nym, Pubkey

class RevIdentityBlock:
    def __init__(
        self,
        reverted_mint_aliases: list[bytes],
        reverted_update_aliases: list[bytes],
        prev_update_pubkeys: list[bytes],
        reverted_nym_aliases: list[bytes],
        prev_nym_nyms: list[bytes],
    ):
        self.unminted_aliases = reverted_mint_aliases
        self.reverted_update_aliases = reverted_update_aliases
        self.reverted_update_pubkeys = prev_update_pubkeys
        self.reverted_nym_aliases = reverted_nym_aliases
        self.reverted_nym_nyms = prev_nym_nyms

    def serialize(self) -> bytes:
        return pickle.dumps(self)
    
    def show(self):
        print("unminted_aliases", self.unminted_aliases)
        print("reverted_update_aliases", self.reverted_update_aliases)
        print("reverted_update_pubkeys", self.reverted_update_pubkeys)
        print("reverted_nym_aliases", self.reverted_nym_aliases)
        print("reverted_nym_nyms", self.reverted_nym_nyms)


def deserialize(serialized: bytes) -> RevIdentityBlock:
    return pickle.loads(serialized)
