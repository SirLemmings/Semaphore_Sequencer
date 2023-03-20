import config as cfg
from wrappers import Index, Hash32
import semaphore_block as sb
import node as nd

def revert_block() -> Hash32:
    """Undo all state transitions from the last block in the semaphore blockchain"""
    index = Index(cfg.db.misc_values.get(b"semaphore_bc_index")) - 1

    block_hash = Hash32(cfg.db.semaphore_bc_hash.get(index))
    block = sb.deserialize_block(cfg.db.semaphore_bc.get(index))
    epoch = block.timestamp
    print('-', bytes(block.checkpoint)[:5].hex(), Index(epoch))
    cfg.db.archive.delete(epoch)
    cfg.db.semaphore_pointers.delete(epoch)

    cfg.db.semaphore_bc.delete(index)
    cfg.db.semaphore_bc_hash.delete(index)
    cfg.db.rev_semaphore_bc_hash.delete(block_hash)

    prev_block = sb.deserialize_block(cfg.db.semaphore_bc.get(index - 1))
    prev_epoch = prev_block.timestamp
    cfg.db.misc_values.put(b"semaphore_bc_index", index)
    cfg.db.misc_values.put(b"semaphore_bc_time", prev_epoch)

    checkpoint = block.checkpoint
    hashes = cfg.db.checkpoints.get(checkpoint)
    hashes = hashes[:-32]
    if len(hashes) == 0:
        cfg.db.checkpoints.delete(checkpoint)
    else:
        cfg.db.checkpoints.put(checkpoint, hashes)

    for chain_commit in nd.epoch_processors:
        nd.cached_epoch_processor_deletions.append(chain_commit)
    cfg.update = 1
    return block_hash

    

def revert_through_block(final_hash: Hash32) -> None:
    if cfg.db.rev_semaphore_bc_hash.get(final_hash) is None:
        raise ValueError("Block hash not in semaphore blockchain")
    while True:
        block_hash = revert_block()
        if block_hash == final_hash:
            break