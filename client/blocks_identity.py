import config as cfg
import identity_block as ib
import rev_identity_block as rib
from query import Query
from codes import msg
import messages as ms
import ecdsa
from wrappers import Index, Hash32
import blocks_semaphore as bs
import params as pm

def process_block(
    new_block: ib.IdentityBlock, serialized_block: bytes, index: Index
) -> None:
    """
    given a new block, update the state and the database
    executes sanity checks for block validity, but that should be checked before
    new_block: the new block to be processed
    serialized_block: serialized block to be stored in the database
    index: the index of the new block in the identity blockchain
    """
    # sanity checks
    identity_bc_index = Index(cfg.db.misc_values.get(b"identity_bc_index"))
    if index != identity_bc_index:
        print("block index from sequencer does not match client block index")
        return
    if not check_block_validity(new_block):
        raise Exception("block from sequencer is not valid")
    # read block
    mint_aliases = new_block.mint_aliases_body
    mint_pubkeys = new_block.mint_pubkeys_body
    update_aliases = new_block.update_aliases_body
    update_pubkeys = new_block.update_pubkeys_body
    nym_aliases = new_block.nym_aliases_body
    nym_nyms = new_block.nym_nyms_body
    # update state
    prev_update_pubkeys = [cfg.db.identity_alias.get(alias) for alias in update_aliases]
    prev_nym_nyms = [cfg.db.rev_identity_nym.get(alias) for alias in nym_aliases]
    rev_block = rib.RevIdentityBlock(
        mint_aliases, update_aliases, prev_update_pubkeys, nym_aliases, prev_nym_nyms
    )
    for alias, pubkey in zip(mint_aliases, mint_pubkeys):
        cfg.db.create_alias_entry(alias, pubkey)
        cfg.db.create_nym_entry(
            str(int.from_bytes(alias, "big")).encode("utf-8"), alias
        )
    for alias, pubkey in zip(update_aliases, update_pubkeys):
        cfg.db.create_alias_entry(alias, pubkey)
        if alias == cfg.alias:
            new_privkey = cfg.db.misc_values.get(pubkey)
            cfg.client_privkey = ecdsa.SigningKey.from_string(
                new_privkey, curve=ecdsa.SECP256k1
            )
            cfg.client_pubkey = cfg.client_privkey.get_verifying_key()
    for alias, nym in zip(nym_aliases, nym_nyms):
        cfg.db.update_nym_entry(nym, alias)

    cfg.db.identity_bc.put(identity_bc_index, serialized_block)
    cfg.db.identity_bc_revert.put(identity_bc_index, rev_block.serialize())
    block_hash = new_block.block_hash()
    cfg.db.identity_bc_hash.put(identity_bc_index, block_hash)
    cfg.db.rev_identity_bc_hash.put(block_hash, identity_bc_index)
    identity_bc_index += 1
    cfg.db.misc_values.put(b"identity_bc_index", identity_bc_index)
    if cfg.show_sync:
        print("+++", bytes(block_hash)[:5].hex())


def load_block(serialized_block: bytes) -> None:
    """
    called when client is ready to process a received block
    process the block if it builds on the chain tip
    resync the chain if it does not build on the chain tip
    """
    index = Index(cfg.db.misc_values.get(b"identity_bc_index"))
    try:
        new_block = ib.deserialize_block(serialized_block)
        if check_block_validity(new_block) and check_block_new(
            new_block.block_hash(), index
        ):
            process_block(new_block, serialized_block, index)
        else:
            index -= 1
            if index < 0:
                return
            for key, _ in cfg.db.cached_identity_blocks:
                cfg.db.cached_identity_blocks.delete(key)
            initiate_chain_sync(index)
    except: #NOTE code reuse :'(
        print('deserialization error 1')
        index -= 1
        if index < 0:
            return
        for key, _ in cfg.db.cached_identity_blocks:
            cfg.db.cached_identity_blocks.delete(key)
        initiate_chain_sync(index)

def load_cached_block() -> bool:
    """loads the deepest cached block and removes from cache"""
    index = cfg.db.misc_values.get(b"identity_bc_index")
    serialized_block = cfg.db.cached_identity_blocks.get(index)
    if serialized_block is None:
        print("no cached blocks")
        return False
    cfg.db.cached_identity_blocks.delete(index)
    load_block(serialized_block)
    return True


def receive_new_block(serialized_block: bytes) -> None:
    """
    called when client receives a new block from sequencer
    stores block in db to be processed at a later time
    """
    offset = 0
    for _, _ in cfg.db.cached_identity_blocks:
        offset += 1
    index = Index(cfg.db.misc_values.get(b"identity_bc_index")) + offset
    try:
        block = ib.deserialize_block(serialized_block)
        block_hash = block.block_hash()
        cfg.db.cached_identity_blocks.put(index, serialized_block)
    except:
        print("deserialization error 2")
        pass


def check_block_new(block_hash: Hash32, index: Index) -> bool:
    """returns true if block is not in db, false otherwise"""
    if cfg.db.rev_identity_bc_hash.get(block_hash) is None:
        if cfg.db.identity_bc_hash.get(index) is not None:
            revert_old_tail(index)  # Revert stale blocks if they exist
        return True
    return False


def block_check_chain_tip(block: ib.IdentityBlock) -> bool:
    """returns true if block build on top of current chain tip, false otherwise"""
    prev_index = Index(cfg.db.misc_values.get(b"identity_bc_index")) - 1
    if prev_index == -1:
        if block.prev_block_hash == Hash32(b"0" * 32):
            return True
        else:
            return False
    prev_hash = Hash32(cfg.db.identity_bc_hash.get(prev_index))

    return prev_hash == block.prev_block_hash


def check_block_validity(block: ib.IdentityBlock) -> bool:
    """
    Returns true if block is valid, false otherwise
    Currenty only checks prev hash and sequencer signature, not state transition
    """
    if not block_check_chain_tip(block):
        if cfg.show_sync:
            print("prev hash does not match")
        return False
    block_hash = block.block_hash()
    if not ms.verify_data_signature(
        cfg.sequencer_pubkey, block.signature, bytes(block_hash)
    ):
        print("signature invalid")
        return False
    # TODO CHECK STATE TRANSITION
    return True


chain_sync_index = Index(b"\x00\x00\x00\x00")
chain_sync_step = 1


def initiate_chain_sync(index: Index, init: bool = True) -> None:
    """
    Initiates checking if the client is on the canonical chain from the given index
    Client sends block hash of index to sequencer
    Response processed with check_chain_sync
    index: the index of the block requested from the client
    init: True if this is the first request to reset chain_sync_index/step,
          False otherwise, if called by check_chain_sync
    """
    if init:
        global chain_sync_index
        chain_sync_index = index
    block_hash = cfg.db.identity_bc_hash.get(index)
    Query(msg.REQUEST_CHAIN_SYNC_I, check_chain_sync, block_hash)


def check_chain_sync(response: bytes, _) -> None:
    """
    Checks the sequencers response to chain_sync request
    if the client is not on the canonical chain request a previous block
    previous block depth increases exponentially
    if a previous block is not found, client syncs from genesis
    Once canonical chain is found, client syncs from that block
    response: b"0" if client is not on canonical chain,
              b"1" if client is on canonical chain
    _: unused
    """
    global chain_sync_index
    global chain_sync_step
    if response == b"0":
        if cfg.show_sync:
            print("sync failed", chain_sync_index)
        try:
            chain_sync_index -= chain_sync_step
        except OverflowError:
            if cfg.show_sync:
                print("index negative", chain_sync_index)
            chain_sync_step = 1
            sync_next_block(Index(b"\x00\x00\x00\x00"))
        else:
            chain_sync_step *= 2
            if cfg.show_sync:
                print("retrying", chain_sync_index)
            initiate_chain_sync(chain_sync_index, False)
    else:
        if cfg.show_sync:
            print("sync success", int(chain_sync_index))
        chain_sync_step = 1
        sync_next_block(chain_sync_index + 1, True)


def sync_next_block(index: Index, init: bool = False) -> None:
    """
    Initiate synchronization client to current chain tip
    Client sends index of requested block to sequencer
    response processed with check_next_block
    sync_next_block and check_next_block recursively call each other until chain tip is reached
    index: the index of the block from which syncing starts
    init: True if this is the first block to sync, reverts stale blocks
          False otherwise
    """
    if init:
        revert_old_tail(index)
    if cfg.show_sync:
        print('requesting i block', index)
        cfg.show_sync_vals()
    Query(msg.REQUEST_BLOCK_I, check_next_block, bytes(index))


def check_next_block(serialized_block: bytes, b_index: bytes) -> None:
    """
    Process the recieved block
    Request the next block
    If the chain tip is reached, stop
    """
    index = Index(b_index)
    if serialized_block == b"0":  # The chain tip has been reached #TODO come back to this
        # # now that we have the identity chain, we can sync the semaphore chain
        # s_index = Index(cfg.db.misc_values.get(b"semaphore_bc_index"))
        # s_index -= pm.DELAY
        # if s_index < 0:
        #     bs.sync_next_block(Index(0))
        # else:
        #     bs.initiate_chain_sync(s_index)
        return
    cfg.db.cached_identity_blocks.put(index, serialized_block)
    index += 1
    sync_next_block(index)


def revert_block(re_cache=False) -> None:
    """
    Delete the last block in the identity blockchain
    Revert the state to the previous block
    """
    index = Index(cfg.db.misc_values.get(b"identity_bc_index")) - 1
    block_hash = cfg.db.identity_bc_hash.get(index)
    if cfg.show_sync:
        print("---", bytes(block_hash)[:5].hex())
    checkpoints = cfg.db.checkpoints.get(block_hash)
    if checkpoints is not None:
        s_hash = Hash32(checkpoints[:32])
        bs.revert_through_block(s_hash)
        cfg.db.checkpoints.delete(block_hash)

    if re_cache:
        block = cfg.db.identity_bc.get(index)
        receive_new_block(block)

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
        if alias == cfg.alias:
            cfg.alias = None
    for alias, pubkey in zip(reverted_update_aliases, reverted_update_pubkeys):
        cfg.db.create_alias_entry(alias, pubkey)
        if alias == cfg.alias:
            old_privkey = cfg.db.misc_values.get(pubkey)
            cfg.client_privkey = ecdsa.SigningKey.from_string(
                old_privkey, curve=ecdsa.SECP256k1
            )
            cfg.client_pubkey = cfg.client_privkey.get_verifying_key()
    for alias, nym in zip(reverted_nym_aliases, reverted_nym_nyms):
        cfg.db.update_nym_entry(nym, alias)
    cfg.db.identity_bc.delete(index)
    cfg.db.identity_bc_revert.delete(index)
    cfg.db.identity_bc_hash.delete(index)
    cfg.db.rev_identity_bc_hash.delete(block_hash)
    cfg.db.misc_values.put(b"identity_bc_index", index)


def revert_old_tail(index: Index, re_cache=False) -> None:
    """revert blocks until the index is reached"""
    while True:
        if index == cfg.db.misc_values.get(b"identity_bc_index"):
            break
        revert_block(re_cache=re_cache)
