import connections as cn
import timing as tm
from threading import Thread
import identity_processor as ip

current_time = -1
identity_processor = ip.IdentityProcessor()
epoch_processors = {}
cached_epoch_processor_deletions = []
clients = {}


def main() -> None:
    t_socket = Thread(target=cn.socket_events, name="socket")
    t_timing = Thread(target=tm.time_events, name="timing")
    t_commands = Thread(target=cn.commands, name="commands")
    t_socket.start()
    t_timing.start()
    t_commands.start()


if __name__ == "__main__":
    main()
