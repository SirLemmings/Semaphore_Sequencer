import config as cfg
import messages as ms
import hashing as hs
import semaphore_block as sb
import node as nd
import params as pm
from wrappers import Index, ChainCommit, Hash32, Broadcast, StrippedBroadcast, BCPointer
import connections as cn


def get_current_chain_commit(time: int):
    """
    returns the chain commit for the current time and chain
    the chain commitment is a hash of the most recent pm.DELAY blocks
    and the offset of the current block in the chain mod pm.DELAY
    equivalent to the "previous block hash" in typical blockchains
    note: sequencer does not have hidden blocks to ignore
    time: the time of the new block
    """
    chain_tip_time = cfg.db.misc_values.get(b"semaphore_bc_time")
    chain_tip_time = int.from_bytes(chain_tip_time, "big")
    if time <= chain_tip_time:
        raise Exception("Time below chain tip")
    index = Index(cfg.db.misc_values.get(b"semaphore_bc_index")) - 1
    chain_commit_hashes = []
    for _ in range(pm.DELAY):
        if index >= 0:
            chain_commit_hashes.append(cfg.db.semaphore_bc_hash.get(index))
            index -= 1
        else:
            chain_commit_hashes.append(b"")
    preimage = ms.concatenate_bytes(*chain_commit_hashes[::-1])
    offset = int((time - chain_tip_time) / pm.EPOCH_TIME)
    offset %= pm.DELAY + 1
    offset = offset.to_bytes(1, "big")
    return ChainCommit(offset + hs.sha256(preimage))


class EpochProcessor:
    def __init__(self, chain_commit: ChainCommit, epoch_time: int):
        self.cached_broadcasts = set()
        self.chain_commit = chain_commit
        self.epoch_time = epoch_time
        self.steps = 0

    def cache_broadcast(self, bc: Broadcast) -> None:
        if bc.chain_commit != self.chain_commit:
            return
        self.cached_broadcasts.add(bc)

    def step(self):
        """
        process broadcasts
        update the state
        and create a new block
        """

        self.steps += 1
        if self.steps == pm.DELAY - pm.SYNC_EPOCHS:
            seen_aliases = set()
            cached_broadcasts = sorted(self.cached_broadcasts)
            self.processed_stripped_broadcasts = []
            self.processed_stripped_replies = []
            self.processed_broadcasts_sigs = []
            self.processed_replies_sigs = []
            self.processed_aliases = []
            index = Index(cfg.db.misc_values.get(b"identity_bc_index")) - 1
            if index < 0:
                nd.cached_epoch_processor_deletions.append(self.chain_commit)
                return
            self.identity_checkpoint = Hash32(cfg.db.identity_bc_hash.get(index))
            for bc in cached_broadcasts:
                if bc.alias in seen_aliases:
                    continue
                pubkey = cfg.db.identity_alias.get(bc.alias)
                if not ms.verify_data_signature(
                    pubkey,
                    bc.signature,
                    bytes(bc.chain_commit),
                    bytes(bc.alias),
                    bytes(bc.parent),
                    bc.message,
                ):
                    continue
                if len(bc.message) > pm.MAX_MESSAGE_LENGTH:
                    continue
                if len(bc.message) == 0:
                    continue
                seen_aliases.add(bc.alias)
                stripped_bc = StrippedBroadcast(bc.alias, bc.parent, bc.message)
                sig = bc.signature
                if bc.parent == BCPointer(int(0).to_bytes(pm.PARENT_LENGTH, "big")):
                    self.processed_stripped_broadcasts.append(stripped_bc)
                    self.processed_broadcasts_sigs.append(sig)
                    self.processed_aliases.append(bc.alias)
                    if cfg.show_messages:
                        nym = cfg.db.rev_identity_nym.get(bc.alias)
                        print(f"{nym.decode('utf-8')}: {bc.message.decode('utf-8')}")
                else:
                    epoch = bc.parent.epoch
                    alias = bc.parent.alias
                    history_aliases = cfg.db.semaphore_pointers.get(epoch)
                    if history_aliases is None:
                        print("history aliases is none")
                        continue
                    for i in range(0, len(history_aliases), pm.ALIAS_LENGTH):
                        if history_aliases[i : i + pm.ALIAS_LENGTH] == alias.to_bytes(
                            pm.ALIAS_LENGTH, "big"
                        ):
                            self.processed_stripped_replies.append(stripped_bc)
                            self.processed_replies_sigs.append(sig)
                            self.processed_aliases.append(bc.alias)
                    if cfg.show_messages:
                        nym = cfg.db.rev_identity_nym.get(bc.alias)
                        other_nym = cfg.db.rev_identity_nym.get(bc.parent.alias)
                        print(
                            f"{nym.decode('utf-8')} -> {other_nym.decode('utf-8')}: {bc.message.decode('utf-8')}"
                        )

            self.new_block = sb.SemaphoreBlock(
                self.processed_stripped_broadcasts,
                self.processed_stripped_replies,
                self.processed_broadcasts_sigs,
                self.processed_replies_sigs,
                self.chain_commit,
                self.identity_checkpoint,
                self.epoch_time,
            )
            self.new_block.sign_block(cfg.sequencer_privkey)

        elif self.steps == pm.DELAY:  # TODO drop block if empty
            nd.cached_epoch_processor_deletions.append(self.chain_commit)
            block_hash = self.new_block.block_hash()
            semaphore_bc_index = Index(cfg.db.misc_values.get(b"semaphore_bc_index"))
            if (
                len(self.new_block.replies_body) == 0
                and len(self.new_block.broadcasts_body) == 0
                and cfg.update != 1
                and semaphore_bc_index > pm.DELAY * 2
            ):
 
                # check if this block will send identity update
                if self.identity_checkpoint == Hash32(cfg.db.identity_bc_hash.get(
                    Index(cfg.db.misc_values.get(b"identity_bc_index")) - 1)
                ):
                    print("empty block")
                    return

            cfg.db.semaphore_bc.put(semaphore_bc_index, self.new_block.serialize())
            cfg.db.semaphore_bc_hash.put(semaphore_bc_index, block_hash)
            cfg.db.rev_semaphore_bc_hash.put(block_hash, semaphore_bc_index)
            cfg.db.chain_commits.put(semaphore_bc_index, self.chain_commit)
            cfg.db.rev_chain_commits.put(self.chain_commit, semaphore_bc_index)

            semaphore_bc_index += 1
            cfg.db.misc_values.put(b"semaphore_bc_index", semaphore_bc_index)
            cfg.db.misc_values.put(b"semaphore_bc_time", self.epoch_time)

            hashes = cfg.db.checkpoints.get(self.identity_checkpoint)
            if hashes is None:
                hashes = b""
            hashes = hashes + bytes(block_hash)
            cfg.db.checkpoints.put(self.identity_checkpoint, hashes)

            aliases = b"".join([bytes(i) for i in self.processed_aliases])
            cfg.db.semaphore_pointers.put(self.epoch_time, aliases)
            cn.push_chain_tip_s()
            print("+", bytes(self.identity_checkpoint)[:5].hex(), self.epoch_time)
            if cfg.update > 0:
                cfg.update -= 1
