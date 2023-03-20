import sched
import time
import config as cfg
import node as nd
import epoch_processor as ep
import params as pm


def time_events() -> None:
    """
    This function is called once at the start of the program.
    It sets up the event loop to run the run_epoch function every epoch.
    It runs in it's own thread.
    """

    def event_loop() -> None:
        """
        This function runs on a timer with the epoch time as the interval
        run_epoch is called at the start of every epoch
        """
        _run_epoch()
        offset = time.time() % pm.EPOCH_TIME
        s.enter(pm.EPOCH_TIME - offset, 0, event_loop)

    s = sched.scheduler(time.time, time.sleep)
    offsest = time.time() % pm.EPOCH_TIME
    s.enter(pm.EPOCH_TIME - offsest, 0, event_loop)
    s.run()


def _run_epoch() -> None:
    """This executes the functions for a new epoch"""
    nd.current_time = int(time.time())
    for chain_commit in set(nd.cached_epoch_processor_deletions):
        del nd.epoch_processors[chain_commit]
    nd.cached_epoch_processor_deletions.clear()

    nd.identity_processor.step()

    for processor in nd.epoch_processors.values():
        processor.step()
    chain_commit = ep.get_current_chain_commit(nd.current_time)
    nd.epoch_processors[chain_commit] = ep.EpochProcessor(
        chain_commit, nd.current_time + pm.FORWARD_SLACK_EPOCHS * pm.EPOCH_TIME
    )
