import plyvel
import os
from wrappers import *
import params as pm
import hashing as hs

class DB:
    def __init__(self, path: str, create_if_missing=True):
        self.db = plyvel.DB(path, create_if_missing=create_if_missing)

    def __iter__(self):
        return self.db.__iter__()

    def put(
        self,
        key: bytes | int | str | Basic,
        value: bytes | int | str | Basic,
        sync: bool = True,
    ) -> None:
        if isinstance(key, int):
            key = key.to_bytes(pm.DB_INT_LENGTH, "big")
        elif isinstance(key, str):
            key = key.encode("utf-8")
        elif isinstance(key, Basic):
            key = bytes(key)

        if isinstance(value, int):
            value = value.to_bytes(pm.DB_INT_LENGTH, "big")
        elif isinstance(value, str):
            value = value.encode("utf-8")
        elif isinstance(value, Basic):
            value = bytes(value)
        self.db.put(key, value, sync=sync)

    def get(self, key: bytes | int | str | Basic) -> bytes:
        if isinstance(key, int):
            key = key.to_bytes(pm.DB_INT_LENGTH, "big")
        elif isinstance(key, str):
            key = key.encode("utf-8")
        elif isinstance(key, Basic):
            key = bytes(key)
        return self.db.get(key)

    def delete(self, key: bytes | int | str | Basic) -> None:
        if isinstance(key, int):
            key = key.to_bytes(pm.DB_INT_LENGTH, "big")
        elif isinstance(key, str):
            key = key.encode("utf-8")
        elif isinstance(key, Basic):
            key = bytes(key)
        self.db.delete(key)


class Database:
    def __init__(self, path: str, reset: bool = False):
        """
        Initializes all node databases
        path: path to the directory in which all databases will be stored
        reset: if True, all databases will be deleted, except for privkeys
        """
        if not os.path.exists(path):
            os.makedirs(path)
        self.identity_alias = DB(path + "/identity_alias_db")  # alias -> pubkey
        self.identity_nym = DB(path + "/identity_nym_db")  # nym -> alias
        self.rev_identity_nym = DB(path + "/rev_identity_nym_db")  # alias -> nym
        self.identity_bc = DB(path + "/identity_bc_db")  # index -> block
        self.identity_bc_revert = DB(
            path + "/identity_bc_revert_db"
        )  # index -> rev_block
        self.identity_bc_hash = DB(path + "/identity_bc_hash_db")  # index -> hash
        self.rev_identity_bc_hash = DB(
            path + "/rev_identity_bc_hash_db"
        )  # hash -> index
        self.misc_values = DB(path + "/misc_values_db")

        self.semaphore_pointers = DB(path + "/semaphore_pointers_db")  # epoch -> aliases
        self.semaphore_bc = DB(path + "/semaphore_bc_db")  # index -> block
        self.semaphore_bc_hash = DB(path + "/semaphore_bc_hash_db")  # index -> hash
        self.rev_semaphore_bc_hash = DB(
            path + "/rev_semaphore_bc_hash_db"
        )  # hash -> index
        self.checkpoints = DB(path + "/checkpoints_db")  # i_hash -> s_hashes
        self.chain_commits = DB(path + "/chain_commits_db")  # index -> commit
        self.rev_chain_commits = DB(path + "/rev_chain_commits_db")  # commit -> index
        self.archive = DB(path + "/archive_db")  # epoch -> broadcasts

        if reset:
            for key, _ in self.identity_alias:
                self.identity_alias.delete(key)
            for key, _ in self.identity_nym:
                self.identity_nym.delete(key)
            for key, _ in self.rev_identity_nym:
                self.rev_identity_nym.delete(key)
            for key, _ in self.identity_bc:
                self.identity_bc.delete(key)
            for key, _ in self.identity_bc_revert:
                self.identity_bc_revert.delete(key)
            for key, _ in self.identity_bc_hash:
                self.identity_bc_hash.delete(key)
            for key, _ in self.rev_identity_bc_hash:
                self.rev_identity_bc_hash.delete(key)
            for key, _ in self.misc_values:
                if key == b"privkey":
                    continue
                self.misc_values.delete(key)

            for key, _ in self.semaphore_pointers:
                self.semaphore_pointers.delete(key)
            for key, _ in self.semaphore_bc:
                self.semaphore_bc.delete(key)
            for key, _ in self.semaphore_bc_hash:
                self.semaphore_bc_hash.delete(key)
            for key, _ in self.rev_semaphore_bc_hash:
                self.rev_semaphore_bc_hash.delete(key)
            for key, _ in self.chain_commits:
                self.chain_commits.delete(key)
            for key, _ in self.rev_chain_commits:
                self.rev_chain_commits.delete(key)
            for key, _ in self.archive:
                self.archive.delete(key)
            for key, _ in self.checkpoints:
                self.checkpoints.delete(key)

        if self.misc_values.get(b"identity_bc_index") is None:
            self.misc_values.put(b"identity_bc_index", 0)
        if self.misc_values.get(b"semaphore_bc_index") is None:
            self.misc_values.put(b"semaphore_bc_index", 0)
        if self.misc_values.get(b"semaphore_bc_time") is None:
            self.misc_values.put(b"semaphore_bc_time", 0)

    def set_privkey(self, privkey: bytes) -> None:
        self.misc_values.put(b"privkey", privkey)

    def create_alias_entry(self, alias: bytes, pubkey: bytes) -> None:
        """update the identity database with a new alias entry"""
        self.identity_alias.put(alias, pubkey)

    def remove_alias_entry(self, alias: bytes) -> None:
        """remove an alias entry from the identity database"""
        self.identity_alias.delete(alias)

    def create_nym_entry(self, nym: bytes, alias: bytes) -> None:
        """update the identity database with a new nym entry"""
        self.identity_nym.put(nym, alias)
        self.rev_identity_nym.put(alias, nym)

    def remove_nym_entry(self, alias: bytes) -> None:
        """remove a nym entry from the identity database"""
        nym = self.rev_identity_nym.get(alias)
        self.identity_nym.delete(nym)
        self.rev_identity_nym.delete(alias)

    def update_nym_entry(self, nym: bytes, alias: bytes) -> None:
        """update a nym entry in the identity database"""
        self.remove_nym_entry(alias)
        self.create_nym_entry(nym, alias)

    def db_hash(self) -> None:
        """compute the hash of the database"""
        preimage=b''
        for k, v in self.identity_alias:
            preimage += k + v
        preimage = hs.sha256(preimage)
        print(preimage[:8].hex())
        preimage = b''
        for k, v in self.identity_nym:
            preimage += k + v
        preimage = hs.sha256(preimage)
        print(preimage[:8].hex())
        preimage = b''
        for k, v in self.rev_identity_nym:
            preimage += k + v
        preimage = hs.sha256(preimage)
        print(preimage[:8].hex())
        preimage = b''
        for k, v in self.identity_bc:
            preimage += k + v
        preimage = hs.sha256(preimage)
        print(preimage[:8].hex())
        preimage = b''
        for k, v in self.identity_bc_revert:
            preimage += k + v
        preimage = hs.sha256(preimage)
        print(preimage[:8].hex())
        preimage = b''
        for k, v in self.identity_bc_hash:
            preimage += k + v
        preimage = hs.sha256(preimage)
        print(preimage[:8].hex())
        preimage = b''
        for k, v in self.rev_identity_bc_hash:
            preimage += k + v
        preimage = hs.sha256(preimage)
        print(preimage[:8].hex())
        preimage = b''
        for k, v in self.semaphore_pointers:
            preimage += k + v
        preimage = hs.sha256(preimage)
        print(preimage[:8].hex())
        preimage = b''
        for k, v in self.semaphore_bc:
            preimage += k + v
        preimage = hs.sha256(preimage)
        print(preimage[:8].hex())
        preimage = b''
        for k, v in self.semaphore_bc_hash:
            preimage += k + v
        preimage = hs.sha256(preimage)
        print(preimage[:8].hex())
        preimage = b''
        for k, v in self.rev_semaphore_bc_hash:
            preimage += k + v
        preimage = hs.sha256(preimage)
        print(preimage[:8].hex())
        preimage = b''
        for k, v in self.chain_commits:
            preimage += k + v
        preimage = hs.sha256(preimage)
        print(preimage[:8].hex())
        preimage = b''
        for k, v in self.rev_chain_commits:
            preimage += k + v
        preimage = hs.sha256(preimage)
        print(preimage[:8].hex())
        # for k, v in self.identity_bc_revert:
        #     print(k.hex(), v.hex())





class SequencerDatabase(Database):
    def __init__(self, path: str = "./sequencer_db", reset: bool = False):

        super().__init__(path, reset)
        if self.misc_values.get(b"next_available_alias") is None:
            next_available_alias = 0
            self.misc_values.put(
                b"next_available_alias", next_available_alias.to_bytes(4, "big")
            )


class ClientDatabase(Database):
    def __init__(self, path: str = "./client_db", reset: bool = False):
        super().__init__(path, reset)
        self.cached_identity_blocks = DB(
            path + "/cached_identity_blocks_db"
        )  # index -> block
        for key, _ in self.cached_identity_blocks:
            self.cached_identity_blocks.delete(key)

        for i in range(pm.DELAY):
            key = f"hidden_{i}".encode('utf-8')
            if self.misc_values.get(key) is None:
                self.misc_values.put(key, 0)