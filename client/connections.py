import config as cfg
import node as nd
from codes import msg
import params as pm
import messages as ms
import sys
import errno
from query import Query
import ecdsa
import messages as ms
import blocks_identity as bi
import blocks_semaphore as bs
import socket
from typing import Tuple
from wrappers import Index, Alias, Pubkey, Sig, Nym, BCPointer, ChainCommit
import time
import gui
from hashing import sha256

def request_alias(pubkey: Pubkey):
    """A client without an assigned alias can request one from the sequencer"""
    if cfg.show_messages:
        print("requesting alias")
    Query(msg.REQUEST_ALIAS, update_alias, bytes(pubkey))


def update_alias(alias: bytes, pubkey: bytes) -> None:
    """When sequencer responds to alias request, update alias in config and db"""
    if pubkey != cfg.client_pubkey.to_string():  # type: ignore
        print("pubkey from sequencer does not match client pubkey")
        return
    if cfg.show_messages:
        print(f"received alias {int.from_bytes(alias, 'big')}")
    cfg.alias = alias
    cfg.db.misc_values.put(b"alias", alias)


def request_alias_update(alias: Alias, new_pubkey: Pubkey, signature: Sig) -> None:
    """Send request for new pubkey to sequencer"""
    args = (bytes(alias), bytes(new_pubkey), bytes(signature))
    data = ms.concatenate_bytes(*args)
    Query(msg.REQUEST_ALIAS_UPDATE, process_key_update, data)


def process_key_update(new_pubkey: bytes, data: bytes) -> None:
    data_new_pubkey = data[4:68]
    if new_pubkey != data_new_pubkey:
        print("pubkey from sequencer does not match client pubkey")


def initiate_key_update(alias: Alias, current_privkey: ecdsa.SigningKey) -> None:
    """Stores new pk, sk pair in db and sends request to sequencer"""
    next_client_privkey = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
    new_privkey = next_client_privkey.to_string()
    new_pubkey = Pubkey(next_client_privkey.get_verifying_key().to_string())  # type: ignore
    cfg.db.misc_values.put(new_pubkey, new_privkey)
    signature = Sig(
        ms.calc_data_signature(current_privkey, bytes(alias), bytes(new_pubkey))
    )
    request_alias_update(cfg.alias, new_pubkey, signature)


def request_nym_update(alias: Alias, nym: Nym, privkey: ecdsa.SigningKey) -> None:
    """Send request for new nym to sequencer"""
    signature = ms.calc_data_signature(privkey, bytes(alias), bytes(nym))
    args = (signature, bytes(alias), bytes(nym))
    data = ms.concatenate_bytes(*args)
    if cfg.show_messages:
        print(f"requesting nym \"{bytes(nym).decode('utf-8')}\"")
    Query(msg.REQUEST_NYM_UPDATE, process_nym_update, data)


def process_nym_update(nym: bytes, data: bytes) -> None:
    data_nym = data[68:]
    if nym != data_nym:
        print("nym from sequencer does not match client nym")
    if cfg.show_messages:
        print(f"nym update to \"{nym.decode('utf-8')}\" successful")


def request_broadcast(
    alias: Alias,
    parent: BCPointer,
    message: bytes,
    chain_commit: ChainCommit,
    privkey: ecdsa.SigningKey,
) -> None:
    signature = ms.calc_data_signature(
        privkey, bytes(chain_commit), bytes(alias), bytes(parent), message
    )
    args = (signature, bytes(chain_commit), bytes(alias), bytes(parent), message)
    data = ms.concatenate_bytes(*args)
    if cfg.show_messages:
        print(f"broadcasting {int.from_bytes(bytes(alias),'big')} -> {parent} \"{message.decode('utf-8')}\"")
    Query(msg.REQUEST_BC, None, data)


def generate_broadcast(parent: BCPointer, message: bytes | str) -> None:
    if isinstance(message, str):
        message = message.encode()
    if len(message) > pm.MAX_MESSAGE_LENGTH:
        print("message too long")
        return
    alias = cfg.alias
    t = int(time.time())
    offset = t % pm.EPOCH_TIME
    t -= offset
    chain_commit = bs.get_current_chain_commit(t)
    request_broadcast(alias, parent, message, chain_commit, cfg.client_privkey)


def receive_message(client_socket: socket.socket) -> Tuple[bytes, bool]:
    """Receive message from sequencer. Strip header and handle errors"""
    try:
        message_header = client_socket.recv(pm.HEADER_LENGTH)
        if not len(message_header):
            return b"", False
        message_length = int.from_bytes(message_header, "big")+32#NOTE: checksum added as afterthought
        return client_socket.recv(message_length), True

    except IOError as e:
        if e.errno != errno.EAGAIN and e.errno != errno.EWOULDBLOCK:
            print("Reading error: {}".format(str(e)))
            sys.exit()
        return b"", False
    except Exception as e:
        print("Reading error?: {} ".format(str(e)))
        sys.exit()


def interpret_message(message: bytes) -> None:
    """Interpret message from sequencer and handle accordingly"""
    checksum, message = message[-32:], message[:-32]
    msg_type = bytes([message[0]])
    msg_body = message[1:]
    if checksum != sha256(message):
        print("checksum error", msg_type)
        return

    if msg_type == msg.QUERY_RESPONSE:
        query_id = msg_body[:4]
        query_id = int.from_bytes(query_id, "big")
        response = msg_body[4:]
        if query_id in nd.open_queries:
            nd.open_queries[query_id].process_query_response(response)
        else:
            print("query id not in open queries")
    elif msg_type == msg.PUSH_BLOCK_I:
        bi.receive_new_block(msg_body)
    elif msg_type == msg.PUSH_BLOCK_S and nd.syncing is False:
        bs.receive_new_block(msg_body)


def socket_events() -> None:
    """Handle the notified socket. Run in a separate thread"""
    while True:
        message, success = receive_message(cfg.client_socket)
        if success is False:
            continue
        interpret_message(message)


def commands() -> None:
    """Handle user input. Runs in a separate thread"""
    while True:
        if cfg.bot:
            break
        message = input(f"> ")
        if message:
            if message == "mint":  # request a new alias
                request_alias(Pubkey(cfg.client_pubkey.to_string()))  # type: ignore

            elif message == "key":  # update alias pubkey
                if cfg.alias is None:
                    print("alias not set")
                    continue
                initiate_key_update(cfg.alias, cfg.client_privkey)

            elif message == "show_privkey":  # show client privkey
                print(cfg.client_privkey.to_string().hex())
                print(cfg.db.misc_values.get(b"identity_bc_index"))
            elif message == "nym":  # request a new nym
                if cfg.alias is None:
                    print("alias not set")
                    continue
                nym = input("nym: ")
                request_nym_update(
                    cfg.alias, Nym(nym.encode("utf-8")), cfg.client_privkey
                )

            elif message == "hashes":  # print block indexes, hashes
                for key, value in cfg.db.identity_bc_hash:
                    print(key.hex(), value.hex())
                print()
                for key, _ in cfg.db.cached_identity_blocks:
                    print(key.hex())

            elif message == "resync":  # sync from genesis
                bi.sync_next_block(Index(b"\x00\x00\x00\x00"), True)

            elif message == "show_rev":  # print indexes and rev blocks
                for key, value in cfg.db.identity_bc_revert:
                    print(key.hex(), value.hex())
                print(cfg.db.misc_values.get(b"identity_bc_index").hex())

            elif message == "show_nyms":  # print alias, nym state
                for key, value in cfg.db.identity_alias:
                    print(key.hex(), value.hex())
                for key, value in cfg.db.identity_nym:
                    print(key.hex(), value.hex())
                for key, value in cfg.db.rev_identity_nym:
                    print(key.hex(), value.hex())

            elif message == "ri":  # revert last block
                bi.revert_block()
            elif message == "rs":  # revert last block
                bs.revert_block()

            elif message == "sync":  # sync from chain tip
                index = Index(cfg.db.misc_values.get(b"identity_bc_index")) - 1
                bi.initiate_chain_sync(index)
            elif message == "load":  # load cached block
                bi.load_cached_block()
            elif message == "checkpoints":
                for _, value in cfg.db.identity_bc_hash:
                    print(value.hex())
                    umm = cfg.db.checkpoints.get(value)
                    for i in range(0, len(umm), 32):
                        print("    " + umm[i : i + 32].hex())
            elif message == "bc":
                msg = input("message: ")
                parent = int(0).to_bytes(pm.PARENT_LENGTH, "big")
                generate_broadcast(BCPointer(parent), msg)
            elif message == "toggle_show":
                cfg.show_messages = not cfg.show_messages
            elif message == "archive":
                gui.archive_to_list()
            elif message == "show":
                cfg.show_sync_vals()