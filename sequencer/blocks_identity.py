import config as cfg
import rev_identity_block as rib
import blocks_semaphore as bs
from wrappers import Index, Hash32


def revert_block() -> None:
    """Undo all state transitions from the last block in the identity blockchain"""
    index = Index(cfg.db.misc_values.get(b"identity_bc_index")) - 1
    block_hash = Hash32(cfg.db.identity_bc_hash.get(index))
    print("---",bytes(block_hash)[:5].hex())
    checkpoints = cfg.db.checkpoints.get(block_hash)
    if checkpoints is not None:
        s_hash = Hash32(checkpoints[:32])
        bs.revert_through_block(s_hash)
        cfg.db.checkpoints.delete(block_hash)

    revert_block = cfg.db.identity_bc_revert.get(index)
    revert_block = rib.deserialize(revert_block)
    unminted_aliases = revert_block.unminted_aliases
    reverted_update_aliases = revert_block.reverted_update_aliases
    reverted_update_pubkeys = revert_block.reverted_update_pubkeys
    reverted_nym_aliases = revert_block.reverted_nym_aliases
    reverted_nym_nyms = revert_block.reverted_nym_nyms

    for alias in unminted_aliases:
        cfg.db.remove_alias_entry(alias)
        cfg.db.remove_nym_entry(alias)
    for alias, pubkey in zip(reverted_update_aliases, reverted_update_pubkeys):
        cfg.db.create_alias_entry(alias, pubkey)
    for alias, nym in zip(reverted_nym_aliases, reverted_nym_nyms):
        cfg.db.update_nym_entry(nym, alias)
    cfg.db.identity_bc.delete(index)
    cfg.db.identity_bc_revert.delete(index)
    cfg.db.identity_bc_hash.delete(index)
    cfg.db.rev_identity_bc_hash.delete(block_hash)
    cfg.db.misc_values.put(b"identity_bc_index", index)
    cfg.update = 1