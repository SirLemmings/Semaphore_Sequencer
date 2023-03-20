import config as cfg
from wrappers import Index, Hash32, ChainCommit, Alias, StrippedBroadcast, BCPointer
import semaphore_block as sb
import hashing as hs
import params as pm
import messages as ms
from codes import msg
from query import Query
import blocks_identity as bi
import node as nd
import time


def get_current_chain_commit(time: int):
    """
    returns the chain commit for the current time and chain
    the chain commitment is a hash of the most recent pm.DELAY blocks
    and the offset of the current block in the chain mod pm.DELAY
    equivalent to the "previous block hash" in typical blockchains
    time: the time of the new block
    """
    shift = calc_shift(time)
    chain_tip_time = find_time(time)
    if time <= chain_tip_time:
        raise Exception("Time below chain tip")
    index = Index(cfg.db.misc_values.get(b"semaphore_bc_index")) - 1
    chain_commit_hashes = []

    for _ in range(pm.DELAY):
        if index - shift >= 0:
            chain_commit_hashes.append(cfg.db.semaphore_bc_hash.get(index - shift))
            index -= 1
        else:
            chain_commit_hashes.append(b"")
    preimage = ms.concatenate_bytes(*chain_commit_hashes[::-1])
    offset = int((time - chain_tip_time) / pm.EPOCH_TIME)- pm.FORWARD_SLACK_EPOCHS
    offset %= (pm.DELAY +1)
    offset = offset.to_bytes(1, "big")
    return ChainCommit(offset + hs.sha256(preimage))


def update_hidden(time: bytes) -> None:
    """
    updates the pm.DELAY most recent times for new blocks
    these times can be "hidden" because they have not been
    finalized by the time of a new block, unless epochs are skipped
    these times are used to calculate the offset of the chain commit
    by skipping epochs that were hidden for the sequencer
    initial values are set to 0 at genesis
    time: the time of the new block
    """
    hidden = [time]
    for i in range(pm.DELAY - 1):
        key = f"hidden_{i}".encode("utf-8")
        hidden.append(cfg.db.misc_values.get(key))
    for i in range(pm.DELAY):
        key = f"hidden_{i}".encode("utf-8")
        cfg.db.misc_values.put(key, hidden[i])


def reverse_hidden(time: bytes) -> None:
    """
    updates hidden times for reverted block
    time: the time of the old block re-entering the hidden times
    """
    hidden = []
    for i in range(1, pm.DELAY):
        key = f"hidden_{i}".encode("utf-8")
        hidden.append(cfg.db.misc_values.get(key))
    hidden.append(time)
    for i in range(pm.DELAY):
        key = f"hidden_{i}".encode("utf-8")
        cfg.db.misc_values.put(key, hidden[i])


def calc_shift(time: int) -> int:
    """calculates how many epochs are hidden"""
    shift = 0
    for i in range(pm.DELAY):
        key = f"hidden_{i}".encode("utf-8")
        hidden_time = int.from_bytes(cfg.db.misc_values.get(key), "big")
        if hidden_time == 0 or hidden_time > time - pm.EPOCH_TIME * pm.DELAY:
            shift += 1
    return shift


def find_time(time: int) -> int:
    """returns the most recent non-hidden time"""
    for i in range(pm.DELAY):
        key = f"hidden_{i}".encode("utf-8")
        hidden = int.from_bytes(cfg.db.misc_values.get(key), "big")
    for i in range(pm.DELAY):
        key = f"hidden_{i}".encode("utf-8")
        hidden = int.from_bytes(cfg.db.misc_values.get(key), "big")
        if hidden <= time - pm.EPOCH_TIME * (pm.DELAY):
            return hidden
    raise Exception("No valid time found")


def process_block(new_block: sb.SemaphoreBlock, serialized_block, index: Index) -> None:
    """
    given a new block, update the state and the database
    new_block: the new block to be processed
    serialized_block: serialized block to be stored in the database
    index: the index of the new block in the identity blockchain
    """
    block_hash = new_block.block_hash()
    semaphore_bc_index = Index(cfg.db.misc_values.get(b"semaphore_bc_index"))
    checkpoint = new_block.checkpoint
    timestamp = new_block.timestamp

    cfg.db.semaphore_bc.put(semaphore_bc_index, serialized_block)
    cfg.db.semaphore_bc_hash.put(semaphore_bc_index, block_hash)
    cfg.db.rev_semaphore_bc_hash.put(block_hash, semaphore_bc_index)
    cfg.db.chain_commits.put(semaphore_bc_index, new_block.chain_commit)
    cfg.db.rev_chain_commits.put(new_block.chain_commit, semaphore_bc_index)

    update_hidden(timestamp)
    semaphore_bc_index += 1
    cfg.db.misc_values.put(b"semaphore_bc_index", semaphore_bc_index)
    cfg.db.misc_values.put(b"semaphore_bc_time", timestamp)

    hashes = cfg.db.checkpoints.get(checkpoint)
    if hashes is None:
        hashes = b""
    hashes = hashes + bytes(block_hash)
    cfg.db.checkpoints.put(checkpoint, hashes)

    processed_aliases = []
    processed_broadcasts = []
    processed_replies = []
    for i in new_block.broadcasts_body:
        alias = Alias(i[: pm.ALIAS_LENGTH])
        parent = BCPointer(int(0).to_bytes(pm.ALIAS_LENGTH + pm.DB_INT_LENGTH, "big"))
        message = i[pm.ALIAS_LENGTH :]
        bc = StrippedBroadcast(alias, parent, message)
        processed_aliases.append(alias)
        processed_broadcasts.append(bc)

        if cfg.show_messages:
            nym = cfg.db.rev_identity_nym.get(alias)
            print(f"received: {nym.decode('utf-8')}: {message.decode('utf-8')}")
    for i in new_block.replies_body:
        alias = Alias(i[: pm.ALIAS_LENGTH])
        parent = BCPointer(i[pm.ALIAS_LENGTH : pm.ALIAS_LENGTH * 2 + pm.DB_INT_LENGTH])
        message = i[pm.ALIAS_LENGTH * 2 + pm.DB_INT_LENGTH :]
        bc = StrippedBroadcast(alias, parent, message)
        processed_aliases.append(alias)
        processed_replies.append(bc)

        if cfg.show_messages:
            nym = cfg.db.rev_identity_nym.get(alias)
            other_nym = cfg.db.rev_identity_nym.get(parent.alias)
            print(f"received: {nym.decode('utf-8')} -> {other_nym.decode('utf-8')}: {message.decode('utf-8')}")
    processed_aliases.sort()
    processed_aliases = b"".join([bytes(i) for i in processed_aliases])
    cfg.db.semaphore_pointers.put(timestamp, processed_aliases)

    i = 0
    j = 0
    all_broadcasts = []
    while i < len(processed_broadcasts) and j < len(processed_replies):
        if processed_broadcasts[i].alias < processed_replies[j].alias:
            all_broadcasts.append(processed_broadcasts[i])
            i += 1
        else:
            all_broadcasts.append(processed_replies[j])
            j += 1
    all_broadcasts += processed_broadcasts[i:]
    all_broadcasts += processed_replies[j:]
    archive = b""
    for i in all_broadcasts:
        bc = bytes(i.alias) + bytes(i.parent) + bytes(i.message)
        bc_len = len(bc).to_bytes(1, "big")
        bc = bc_len + bc
        archive += bc
    cfg.db.archive.put(timestamp, archive)
    if cfg.show_messages or True:
        print("+", bytes(checkpoint)[:5].hex(), int.from_bytes(timestamp, "big"))
    if not nd.syncing:
        print('len:',len(processed_aliases)/pm.ALIAS_LENGTH)


def receive_new_block(serialized_block: bytes) -> bool:
    """
    called when client receives a new block from sequencer
    if the block does not build on the chain tip, initiate chain sync
    if the checkpoint does not match, load cached identity blocks
    if the block is valid, process it
    """
    s_index = Index(cfg.db.misc_values.get(b"semaphore_bc_index"))
    i_index = Index(cfg.db.misc_values.get(b"identity_bc_index"))
    if i_index > 0:
        current_checkpoint = Hash32(cfg.db.identity_bc_hash.get(i_index - 1))
    else:
        current_checkpoint = Hash32(b"\x00" * 32)
    try:
        new_block = sb.deserialize_block(serialized_block)
    except:
        print('*****deserialization error 3*****')
        s_index -= pm.DELAY #NOTE: code reuse 
        if s_index < 0:
            if cfg.show_sync:
                print('syncing semaphore from 0')
            print('syncing semaphore from 0')
            sync_next_block(Index(0))
            return False
        if cfg.show_sync:
            print('syncing semaphore from', s_index)
        print('syncing semaphore from', s_index)
        initiate_chain_sync(s_index)
        return False
    # check the block is new
    if not check_block_new(new_block.block_hash(), s_index):  # TODO repeated below
        if cfg.show_sync:
            print('block not new')
        return False
    # if the block does not build on the chain tip, initiate chain sync
    if not block_check_chain_tip(new_block):
        if cfg.show_sync:
            print('block does not build on chain tip')
        s_index -= pm.DELAY
        if s_index < 0:
            if cfg.show_sync:
                print('syncing semaphore from 0')
            sync_next_block(Index(0))
            return False
        if cfg.show_sync:
            print('syncing semaphore from', s_index)
        initiate_chain_sync(s_index)
        return False
    # load cached identity blocks until checkpoint matches
    while current_checkpoint != new_block.checkpoint:
        if cfg.show_sync:
            print('checkpoint mismatch')
            print('current_checkpoint', current_checkpoint)
            print('new_block.checkpoint', new_block.checkpoint)
            for key, value in cfg.db.cached_identity_blocks:
                
                print(key.hex())
        if not bi.load_cached_block():
            nd.syncing = False
            if i_index > 0:
                if cfg.show_sync:
                    print('syncing identity chain from ', i_index - 1)
                bi.initiate_chain_sync(i_index - 1)
            else:
                if cfg.show_sync:
                    print('syncing identity from 0')
                bi.sync_next_block(Index(0))
            return False
        if cfg.show_sync:
            print('loading cached block')
        i_index = Index(cfg.db.misc_values.get(b"identity_bc_index"))
        #current_checkpoint = Hash32(cfg.db.identity_bc_hash.get(i_index - 1))#NOTE: H change
        if i_index > 0:
            current_checkpoint = Hash32(cfg.db.identity_bc_hash.get(i_index - 1))
        else:
            current_checkpoint = Hash32(b"\x00" * 32)
        if cfg.show_sync:
            print('new_checkpoint', current_checkpoint)
    if check_block_validity(new_block) and check_block_new(
        new_block.block_hash(), s_index
    ):
        process_block(new_block, serialized_block, s_index)
    else:
        s_index -= pm.DELAY
        if s_index < 0:
            return False
        initiate_chain_sync(s_index)
    return True



def check_block_new(block_hash: Hash32, index: Index) -> bool:
    """returns true if block is not in db, false otherwise"""
    if cfg.db.rev_semaphore_bc_hash.get(block_hash) is None:
        if cfg.db.semaphore_bc_hash.get(index) is not None:
            revert_old_tail(index)  # Revert stale blocks if they exist
        return True
    return False


def block_check_chain_tip(block: sb.SemaphoreBlock) -> bool:
    """
    returns true if block build on top of current chain tip, false otherwise
    checks only finalized blocks, not hidden
    """
    block_timestamp = int.from_bytes(block.timestamp, "big")
    correct_chain_commit = get_current_chain_commit(block_timestamp)
    return block.chain_commit == correct_chain_commit


def check_block_validity(block: sb.SemaphoreBlock) -> bool:
    """
    Returns true if block is valid, false otherwise
    Currenty only checks sequencer signature, not state transition
    """
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
    nd.syncing = True
    if init:
        global chain_sync_index
        chain_sync_index = index
    block_hash = cfg.db.semaphore_bc_hash.get(index)
    Query(msg.REQUEST_CHAIN_SYNC_S, check_chain_sync, block_hash)


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
    global common_index_ub
    global common_index_lb
    if response == b"0":
        common_index_ub = chain_sync_index
        chain_sync_index -= chain_sync_step
        if chain_sync_index < 0:
            chain_sync_step = 1
            sync_next_block(Index(b"\x00\x00\x00\x00"))
        else:
            chain_sync_step *= 2
            initiate_chain_sync(chain_sync_index, False)
    else:
        common_index_lb = chain_sync_index
        chain_sync_step = 1
        sync_next_block(chain_sync_index + 1, True)


common_index_lb = Index(b"\x00\x00\x00\x00")
common_index_ub = Index(b"\xff\xff\xff\xff")
common_index_middle = Index(b"\x00\x00\x00\x00")


def refine_chain_sync() -> None:
    """finds the most recent common block between the client and the sequencer"""
    global common_index_lb
    global common_index_ub
    global common_index_middle
    if common_index_lb == common_index_ub:
        sync_next_block(common_index_lb + 1, True)
        return
    common_index_middle = Index(int(common_index_lb + common_index_ub) // 2)
    block_hash = cfg.db.semaphore_bc_hash.get(chain_sync_index)
    Query(msg.REQUEST_CHAIN_SYNC_S, check_common_index, block_hash)


def check_common_index(response: bytes, _) -> None:
    """updates the bounds for recent common block"""
    global common_index_lb
    global common_index_ub
    global common_index_middle
    if response == b"0":
        common_index_ub = common_index_middle
    else:
        common_index_lb = common_index_middle
    refine_chain_sync()


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
    nd.syncing = True
    if init:
        revert_old_tail(index)
    if cfg.show_sync:
        print('requesting s block', index)
    Query(msg.REQUEST_BLOCK_S, check_next_block, bytes(index))


def check_next_block(serialized_block: bytes, b_index: bytes) -> None:
    """
    Process the recieved block
    Request the next block
    If the chain tip is reached, stop
    """
    index = Index(b_index)
    if serialized_block == b"0":  # The chain tip has been reached
        if cfg.show_sync:
            print("synced to chain tip")
        nd.syncing = False
        return
    
    if receive_new_block(serialized_block):
        index += 1
        sync_next_block(index)


def revert_block(revert_i=True) -> Hash32:
    """
    Undo all state transitions from the last block in the semaphore blockchain
    updates checkpoints/identity state
    """
    index = Index(cfg.db.misc_values.get(b"semaphore_bc_index")) - 1
    block_hash = Hash32(cfg.db.semaphore_bc_hash.get(index))
    block = sb.deserialize_block(cfg.db.semaphore_bc.get(index))
    epoch = block.timestamp
    if cfg.show_sync:
        print("-", bytes(block.checkpoint)[:5].hex(), Index(epoch))
    i_hash = block.checkpoint
    checkpoints = cfg.db.checkpoints.get(i_hash)
    prev_s_block = cfg.db.semaphore_bc.get(index - 1)
    prev_s_block = sb.deserialize_block(prev_s_block)

    cfg.db.archive.delete(epoch)
    cfg.db.semaphore_pointers.delete(epoch)

    cfg.db.semaphore_bc.delete(index)
    cfg.db.semaphore_bc_hash.delete(index)
    cfg.db.rev_semaphore_bc_hash.delete(block_hash)

    prev_epoch = prev_s_block.timestamp
    cfg.db.misc_values.put(b"semaphore_bc_index", index)
    cfg.db.misc_values.put(b"semaphore_bc_time", prev_epoch)

    # update hidden times
    if index >= pm.DELAY:
        prev_block = cfg.db.semaphore_bc.get(index - pm.DELAY)
        prev_block = sb.deserialize_block(prev_block)
        prev_epoch = prev_block.timestamp
        reverse_hidden(prev_epoch)

    # update checkpoints db entry
    hashes = checkpoints[:-32]
    if len(hashes) == 0:
        cfg.db.checkpoints.delete(i_hash)
    else:
        cfg.db.checkpoints.put(i_hash, hashes)

    # revert identity state if checkpoint changes
    if checkpoints[:32] == block_hash and revert_i:
        prev_i_hash = prev_s_block.checkpoint
        prev_i_index = cfg.db.rev_identity_bc_hash.get(prev_i_hash)
        bi.revert_old_tail(Index(prev_i_index) + 1, re_cache=False)
    return block_hash


def revert_through_block(final_hash: Hash32) -> None:
    """revert blocks until the final hash is reverted"""
    if cfg.db.rev_semaphore_bc_hash.get(final_hash) is None:
        raise ValueError("Block hash not in semaphore blockchain")
    while True:
        block_hash = revert_block(revert_i=False)
        if block_hash == final_hash:
            break


def revert_old_tail(index: Index) -> None:
    """revert blocks until the index is reached"""
    while True:
        if index == cfg.db.misc_values.get(b"semaphore_bc_index"):
            break
        revert_block()
