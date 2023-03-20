import sys
import os
import params as pm
import database as db
import hashing as hs
import ecdsa
import socket
import os
from wrappers import Alias

current_file = os.path.abspath(__file__)
parent_directory = os.path.dirname(os.path.dirname(current_file))
sys.path.append(parent_directory)
bot = True

def get_next_node_number():
    # Set the base directory where the node directories will be created
    base_dir = "./"

    # Find the highest node number used so far
    node_dirs = os.listdir(base_dir)
    node_nums = [int(name.split("node_")[1]) for name in node_dirs if "node_" in name]
    if node_nums:
        highest_node_num = max(node_nums)
    else:
        highest_node_num = -1

    # Return the next available node number
    return f"node_{highest_node_num + 1}"

# connection info for node
if pm.SEQUENCER_IP =="":
    SEQUENCER_IP = socket.gethostbyname("localhost")
else:
    SEQUENCER_IP = pm.SEQUENCER_IP
    
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
client_socket.connect((SEQUENCER_IP, pm.SEQUENCER_PORT))
client_socket.setblocking(False)

# distinguish between different clients running on the same machine
# sys_id = input("id: ")
sys_id = get_next_node_number()
if sys_id != "":
    sys_id = "/" + sys_id
identity_processor = None

# initialize stuffs
path = f".{sys_id}/client_db"
if os.path.exists(path):
    initialized = True
else:
    initialized = False
    os.makedirs(path)
db = db.ClientDatabase(path, reset=bool(pm.RESET))

if not initialized:
    pk = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1) #type: ignore
    db.set_privkey(pk.to_string())
client_privkey = ecdsa.SigningKey.from_string(
    db.misc_values.get(b"privkey"), curve=ecdsa.SECP256k1
)
client_pubkey = client_privkey.get_verifying_key()

db.misc_values.put(client_pubkey.to_string(), client_privkey.to_string())  # type: ignore

if db.misc_values.get(b"alias") is not None:
    alias = Alias(db.misc_values.get(b"alias"))
else:
    alias = Alias(b'\xff\xff\xff\xff')


sequencer_pubkey = ecdsa.VerifyingKey.from_string(
    bytes.fromhex(pm.SEQUENCER_PUBKEY), curve=ecdsa.SECP256k1
)

show_messages = False
show_sync = False
def show_sync_vals():
    print("cached:")
    for key, value in db.cached_identity_blocks:
        print(key.hex()) 
    print()   
    print("identity:")
    for key, value in db.identity_bc_hash:
        print(key.hex(), value.hex())
    print()
    print("semaphore:")
    for key, value in db.semaphore_bc_hash:
        print(key.hex(), value.hex())
    

