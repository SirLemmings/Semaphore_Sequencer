import socket
import select
import config as cfg
from codes import msg
import messages as ms
import blocks_identity as bk
import node as nd
from typing import Tuple
import params as pm
from wrappers import Alias, Pubkey, Sig, Nym, Hash32, Index, ChainCommit, BCPointer, Broadcast
import blocks_semaphore as bs
import sys
from hashing import sha256

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server_socket.bind((cfg.IP, cfg.PORT))
server_socket.listen()

sockets_list = [server_socket]

print(f"Listening for connections on {cfg.IP}:{cfg.PORT}...")


def receive_message(client_socket: socket.socket) -> Tuple[bytes, bool]:
    """Receive message from client. Strip header and handle errors"""
    try:
        message_header = client_socket.recv(pm.HEADER_LENGTH)
        if not len(message_header):
            return b"", False
        message_length = int.from_bytes(message_header, "big")
        return client_socket.recv(message_length), True
    except:
        return b"", False


def interpret_message(message: bytes, notified_socket: socket.socket) -> None:
    """
    Handle message from client
    Message type stripped from message before handling
    """
    msg_type = bytes([message[0]])
    msg_body = message[1:]
    if msg_type == msg.REQUEST_ALIAS:
        # assign the next available alias to the client
        # submit alias mint transaction
        try:
            query_id, msg_body = (
                msg_body[: pm.DB_INT_LENGTH],
                msg_body[pm.DB_INT_LENGTH :],
            )
            pubkey = Pubkey(msg_body[: pm.PUBKEY_LENGTH])
        except:
            print("slicing error")
            return

        alias = Alias(cfg.db.misc_values.get(b"next_available_alias"))
        next_available_alias = Index(bytes(alias)) + 1
        cfg.db.misc_values.put(b"next_available_alias", next_available_alias)
        nd.identity_processor.cache_alias_mint(alias, pubkey)
        generate_query_response(notified_socket, query_id, bytes(alias))

    elif msg_type == msg.REQUEST_ALIAS_UPDATE:
        # submit transaction updating alias pubkey
        try:
            query_id, msg_body = msg_body[: pm.DB_INT_LENGTH], msg_body[pm.DB_INT_LENGTH :]
            alias, msg_body = Alias(msg_body[:pm.ALIAS_LENGTH]),msg_body[pm.ALIAS_LENGTH :]
            new_pubkey, msg_body = Pubkey(msg_body[: pm.PUBKEY_LENGTH]),msg_body[pm.PUBKEY_LENGTH :]
            signature = Sig(msg_body[:pm.SIG_LENGTH])
        except:
            print("slicing error")
            return

        nd.identity_processor.cache_alias_update(alias, new_pubkey, signature)
        generate_query_response(notified_socket, query_id, bytes(new_pubkey))

    elif msg_type == msg.REQUEST_NYM_UPDATE:
        # submit transaction updating alias nym
        # identity processor will check if nym is valid
        try:
            query_id, msg_body = msg_body[:pm.DB_INT_LENGTH], msg_body[pm.DB_INT_LENGTH:]
            signature , msg_body = Sig(msg_body[:pm.SIG_LENGTH]), msg_body[pm.SIG_LENGTH:]
            alias, msg_body = Alias(msg_body[:pm.ALIAS_LENGTH]), msg_body[pm.ALIAS_LENGTH:]
            nym = Nym(msg_body[:pm.NYM_MAX_LENGTH])
        except Exception as e:
            print(e)
            print("slicing error")
            return
        nd.identity_processor.cache_nym_update(alias, nym, signature)
        generate_query_response(notified_socket, query_id, bytes(nym))

    elif msg_type == msg.REQUEST_BLOCK_I:
        # send client block of the requested index
        try:
            query_id, msg_body = msg_body[:pm.DB_INT_LENGTH], msg_body[pm.DB_INT_LENGTH:]
            block_index = Index(msg_body[:pm.DB_INT_LENGTH])
        except:
            print("slicing error")
            return
        block = cfg.db.identity_bc.get(block_index)
        if block is not None:
            generate_query_response(notified_socket, query_id, block)
        else:
            generate_query_response(notified_socket, query_id, b"0")

    elif msg_type == msg.REQUEST_CHAIN_SYNC_I:
        # tell the client if provided block hash is in the chain
        try:
            query_id, msg_body = msg_body[:pm.DB_INT_LENGTH], msg_body[pm.DB_INT_LENGTH:]
            block_hash = Hash32(msg_body[:32])
        except:
            print("slicing error")
            return
        index = cfg.db.rev_identity_bc_hash.get(block_hash)
        if index is None:
            generate_query_response(notified_socket, query_id, b"0")
        else:
            generate_query_response(notified_socket, query_id, b"1")

    elif msg_type == msg.REQUEST_BLOCK_S:
        # send client block of the requested index
        try:
            query_id, msg_body = msg_body[:pm.DB_INT_LENGTH], msg_body[pm.DB_INT_LENGTH:]
            block_index = Index(msg_body[:pm.DB_INT_LENGTH])
        except:
            print("slicing error")
            return
        block = cfg.db.semaphore_bc.get(block_index)
        if block is not None:
            generate_query_response(notified_socket, query_id, block)
        else:
            generate_query_response(notified_socket, query_id, b"0")

    elif msg_type == msg.REQUEST_CHAIN_SYNC_S:
        # tell the client if provided block hash is in the chain
        try:
            query_id, msg_body = msg_body[:pm.DB_INT_LENGTH], msg_body[pm.DB_INT_LENGTH:]
            block_hash = Hash32(msg_body[:32])
        except:
            print("slicing error")
            return
        index = cfg.db.rev_semaphore_bc_hash.get(block_hash)
        if index is None:
            generate_query_response(notified_socket, query_id, b"0")
        else:
            generate_query_response(notified_socket, query_id, b"1")
    elif msg_type == msg.REQUEST_BC:
        try:
            query_id, msg_body = msg_body[:pm.DB_INT_LENGTH], msg_body[pm.DB_INT_LENGTH:]
            signature, msg_body = Sig(msg_body[:pm.SIG_LENGTH]), msg_body[pm.SIG_LENGTH:]
            chain_commit, msg_body = ChainCommit(msg_body[:33]), msg_body[33:]
            alias, msg_body = Alias(msg_body[:pm.ALIAS_LENGTH]), msg_body[pm.ALIAS_LENGTH:]
            parent, message = BCPointer(msg_body[:pm.PARENT_LENGTH]), msg_body[pm.PARENT_LENGTH:]
            if chain_commit in nd.epoch_processors:
                bc = Broadcast(alias,parent,message,chain_commit,signature)
                nd.epoch_processors[chain_commit].cache_broadcast(bc)
        except:
            print("slicing error")
            return
    else:
        print(message)


def generate_query_response(
    notified_socket: socket.socket, query_id: bytes, *args: bytes
) -> None:
    message = ms.format_message(msg.QUERY_RESPONSE, query_id, *args)
    checksum = sha256(message[pm.HEADER_LENGTH:])

    notified_socket.send(message+checksum)


def push_chain_tip_i() -> None:
    """Push the most recent block to all connected clients."""
    index = Index(cfg.db.misc_values.get(b"identity_bc_index")) - 1
    block = cfg.db.identity_bc.get(index)
    message = ms.format_message(msg.PUSH_BLOCK_I, block)
    checksum = sha256(message[pm.HEADER_LENGTH:])
    for socket in sockets_list:
        if socket != server_socket:
            socket.send(message+checksum)

def push_chain_tip_s() -> None:
    """Push the most recent block to all connected clients."""
    index = Index(cfg.db.misc_values.get(b"semaphore_bc_index")) - 1
    block = cfg.db.semaphore_bc.get(index)
    message = ms.format_message(msg.PUSH_BLOCK_S, block)
    checksum = sha256(message[pm.HEADER_LENGTH:])

    for socket in sockets_list:
        if socket != server_socket:
            socket.send(message+checksum)

def socket_events() -> None:
    """Handle the notified socket. Run in a separate thread"""
    while True:
        read_sockets, _, exception_sockets = select.select(
            sockets_list, [], sockets_list
        )
        for notified_socket in read_sockets:
            # Connection from new client
            if notified_socket == server_socket:
                client_socket, client_address = server_socket.accept()
                sockets_list.append(client_socket)
                client_id = client_address[0] + str(client_address[1])
                nd.clients[client_socket] = client_id
                print("new connection")
            # Communication from existing client
            else:
                message, success = receive_message(notified_socket)
                if success is False:
                    print(
                        "Closed connection from: {}".format(nd.clients[notified_socket])
                    )
                    sockets_list.remove(notified_socket)
                    del nd.clients[notified_socket]
                    continue
                interpret_message(message, notified_socket)
        # Exception handling
        for notified_socket in exception_sockets:
            print('aa')
            sockets_list.remove(notified_socket)
            del nd.clients[notified_socket]


def commands() -> None:
    """Handle user input. Runs in a separate thread."""
    while True:
        cmd = input("> ")
        if cmd:
            if cmd == "hashes":
                for key, value in cfg.db.identity_bc_hash:
                    print(key.hex(), value.hex())

            elif cmd == "show_rev":
                for key, value in cfg.db.identity_bc_revert:
                    print(key.hex(), value.hex())
                print(cfg.db.misc_values.get(b"identity_bc_index").hex())

            elif cmd == "show_nyms":
                for key, value in cfg.db.identity_alias:
                    print(key.hex(), value.hex())
                for key, value in cfg.db.identity_nym:
                    print(key.hex(), value.hex())
                for key, value in cfg.db.rev_identity_nym:
                    print(key.hex(), value.hex())

            elif cmd == "ihashes":
                for key, value in cfg.db.identity_bc_hash:
                    print(key.hex(), value.hex())
            elif cmd == "shashes":
                for key, value in cfg.db.semaphore_bc_hash:
                    print(key.hex(), value.hex())
            elif cmd == "checkpoints":
                for _, value in cfg.db.identity_bc_hash:
                    print(value.hex())
                    umm = cfg.db.checkpoints.get(value)
                    for i in range(0, len(umm), 32):
                        print('    '+umm[i:i+32].hex())
            elif cmd == "show":
                for key, value in cfg.db.identity_bc_hash:
                    print(key.hex(), value.hex())
                print()
                for key, value in cfg.db.semaphore_bc_hash:
                    print(key.hex(), value.hex())
                print()
                for _, value in cfg.db.identity_bc_hash:
                    print(value.hex())
                    umm = cfg.db.checkpoints.get(value)
                    for i in range(0, len(umm), 32):
                        print('    '+umm[i:i+32].hex())
                
            elif cmd == "ri":
                bk.revert_block()
            elif cmd == "rs":
                bs.revert_block()

            elif cmd == "pubkey":
                print(cfg.sequencer_pubkey.to_string().hex())#type: ignore
            
            elif cmd == "toggle_show":
                cfg.show_messages = not cfg.show_messages
            elif cmd == "exit":
                sys.exit()
            
