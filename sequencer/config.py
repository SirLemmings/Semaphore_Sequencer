import sys
import os
import database as db
import ecdsa
import socket
import params as pm

current_file = os.path.abspath(__file__)
parent_directory = os.path.dirname(os.path.dirname(current_file))
sys.path.append(parent_directory)

if pm.SEQUENCER_IP =="":
    IP = socket.gethostbyname("localhost")
else:
    IP = input("internal IP: ")
PORT = pm.SEQUENCER_PORT
update = 0
db = db.SequencerDatabase(reset=bool(pm.RESET))

# initialize signing info
# if sequencer_db directory does not exist, create it
privkey_bytes = db.misc_values.get(b"privkey")
if privkey_bytes is None:
    privkey_bytes = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1).to_string()
    db.misc_values.put(b"privkey", privkey_bytes)
sequencer_privkey = ecdsa.SigningKey.from_string(privkey_bytes, curve=ecdsa.SECP256k1)

sequencer_pubkey = sequencer_privkey.get_verifying_key()
if sequencer_pubkey.to_string().hex() != pm.SEQUENCER_PUBKEY:  # type:ignore
    print("current: ", sequencer_pubkey.to_string().hex())  # type:ignore
    print("file: ", pm.SEQUENCER_PUBKEY)
    raise Exception("Public key does not match the one in params.json")

show_messages = False
