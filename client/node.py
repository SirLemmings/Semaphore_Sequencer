import connections as cn
from threading import Thread
import config as cfg
import blocks_identity as bk
from wrappers import Index, Pubkey
import gui
import time
import timing as tm

current_time = -1
open_queries = {}
syncing = False
def main() -> None:
    t_socket = Thread(target=cn.socket_events,name='socket')
    t_commands = Thread(target=cn.commands,name='commands')
    t_socket.start()
    t_commands.start()
    gui.start()

        

if __name__ == "__main__":
    main()