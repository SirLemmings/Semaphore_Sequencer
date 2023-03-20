import config as cfg
import identity_block as ib
import rev_identity_block as rib
import messages as ms
import connections as cn
from wrappers import Alias, Pubkey, Sig, Nym, Index, Hash32
import re
import params as pm


class IdentityProcessor:
    def __init__(self):
        self.cached_alias_mints = set()
        self.cached_alias_updates = set()
        self.cached_nym_updates = set()

    def cache_alias_mint(self, alias: Alias, pubkey: Pubkey) -> None:
        """cache a new alias mint to be processed in the next block"""
        if alias.value == b"\xff\xff\xff\xff":
            return
        self.cached_alias_mints.add((alias, pubkey))

    def cache_alias_update(self, alias: Alias, pubkey: Pubkey, sig: Sig) -> None:
        """cache a new alias update to be processed in the next block"""
        self.cached_alias_updates.add((alias, pubkey, sig))

    def cache_nym_update(self, alias: Alias, nym: Nym, sig: Sig) -> None:
        """cache a new nym update to be processed in the next block"""
        self.cached_nym_updates.add((alias, nym, sig))

    def step(self) -> None:
        """
        process the cached alias mints and updates,
        update the state,
        and create a new block
        """
        # initialize the block components
        seen_aliases = set()
        cached_alias_mints = sorted(self.cached_alias_mints)
        cached_alias_updates = sorted(self.cached_alias_updates)
        processed_mint_aliases = []
        processed_mint_pubkeys = []

        processed_update_aliases = []
        processed_update_pubkeys = []
        processed_update_sigs = []

        processed_nym_aliases = []
        processed_nym_nyms = []
        processed_nym_sigs = []

        prev_update_pubkeys = []
        prev_nym_nyms = []

        # process the cached alias mints and updates
        for alias, pubkey in cached_alias_mints:
            if alias in seen_aliases:
                continue
            if cfg.db.identity_alias.get(alias) is not None:
                continue

            seen_aliases.add(alias)
            processed_mint_aliases.append(alias)
            processed_mint_pubkeys.append(pubkey)
            cfg.db.create_alias_entry(alias, pubkey)
            alias_nym = str(int.from_bytes(alias, "big")).encode("utf-8")
            cfg.db.create_nym_entry(alias_nym, alias)

        for alias, pubkey, sig in cached_alias_updates:
            if alias in seen_aliases:
                continue
            if cfg.db.identity_alias.get(alias) is None:
                continue
            old_pubkey = cfg.db.identity_alias.get(alias)
            if not ms.verify_data_signature(
                old_pubkey, sig, bytes(alias), bytes(pubkey)
            ):
                continue

            seen_aliases.add(alias)
            processed_update_aliases.append(alias)
            processed_update_pubkeys.append(pubkey)
            processed_update_sigs.append(sig)
            prev_update_pubkeys.append(old_pubkey)
            cfg.db.create_alias_entry(alias, pubkey)

        for alias, nym, sig in self.cached_nym_updates:
            if alias in seen_aliases:
                continue
            if cfg.db.identity_alias.get(alias) is None:
                continue
            pubkey = cfg.db.identity_alias.get(alias)
            if cfg.db.identity_nym.get(nym) is not None:
                continue
            nym_str = bytes(nym).decode("utf-8")
            pattern = r"^(?=.*[a-zA-Z])[a-zA-Z0-9_]{1," + str(pm.NYM_MAX_LENGTH) + r"}$"
            if not re.match(pattern, nym_str):
                continue
            if not ms.verify_data_signature(pubkey, sig, bytes(alias), bytes(nym)):
                continue
            seen_aliases.add(alias)
            processed_nym_aliases.append(alias)
            processed_nym_nyms.append(nym)
            processed_nym_sigs.append(sig)
            prev_nym_nyms.append(cfg.db.rev_identity_nym.get(alias))
            cfg.db.update_nym_entry(nym, alias)

        self.cached_alias_mints = set()
        self.cached_alias_updates = set()
        self.cached_nym_updates = set()

        if (
            len(processed_mint_aliases) == 0
            and len(processed_update_aliases) == 0
            and len(processed_nym_aliases) == 0
        ):
            return
        identity_bc_index = Index(cfg.db.misc_values.get(b"identity_bc_index"))
        if identity_bc_index == 0:
            prev_hash = Hash32(b"0" * 32)
        else:
            prev_hash = Hash32(cfg.db.identity_bc_hash.get(identity_bc_index - 1))
        new_block = ib.IdentityBlock(
            processed_mint_aliases,
            processed_mint_pubkeys,
            processed_update_aliases,
            processed_update_pubkeys,
            processed_update_sigs,
            processed_nym_aliases,
            processed_nym_nyms,
            processed_nym_sigs,
            prev_hash,
        )
        new_rev_block = rib.RevIdentityBlock(
            processed_mint_aliases,
            processed_update_aliases,
            prev_update_pubkeys,
            processed_nym_aliases,
            prev_nym_nyms,
        )
        new_block.sign_block(cfg.sequencer_privkey)
        cfg.db.identity_bc.put(identity_bc_index, new_block.serialize())
        cfg.db.identity_bc_revert.put(identity_bc_index, new_rev_block.serialize())
        block_hash = new_block.block_hash()
        cfg.db.identity_bc_hash.put(identity_bc_index, block_hash)
        cfg.db.rev_identity_bc_hash.put(block_hash, identity_bc_index)

        identity_bc_index += 1
        cfg.db.misc_values.put(b"identity_bc_index", identity_bc_index)
        cn.push_chain_tip_i()
        cfg.update = 2
        print("+++",bytes(block_hash)[:5].hex())

