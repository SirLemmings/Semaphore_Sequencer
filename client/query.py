import sched
import time
import random
import config as cfg
import messages as ms
from typing import Callable
import node as nd
import params as pm
from threading import Thread

class Query:
    """
    A class used to track and handle all of the node's open queries
    Queries are used to handle communications with the sequencer.
    Once sent, the open query is stored and dropped once a response is received or the query times out.
    Once a response is received, the query can run a processing function to handle the response.
    """

    def __init__(
        self,
        query_type: bytes,
        processing_function: Callable | None = None,
        data: bytes = b"",
        alloted_time: float | None = .5,
    ):
        self.alloted_time = alloted_time
        self.response = None
        self.query_type = query_type
        self.processing_function = processing_function
        self.data = data

        if self.alloted_time is not None:
            self.scheduler = sched.scheduler(time.time, time.sleep)
            self.scheduler.enter(self.alloted_time, 0, self.delete)
            # self.scheduler.run()
            t_del = Thread(target=self.scheduler.run, name="delete")
            t_del.start()

        while True:
            self.query_id = random.randint(0, 2**(pm.DB_INT_LENGTH*8))
            if self.query_id not in nd.open_queries.keys():
                break
        nd.open_queries[self.query_id] = self
        self.send_query()

    def send_query(self) -> None:
        """send message to sequencer with info for query"""
        query_id = self.query_id.to_bytes(4, "big")
        message = ms.format_message(self.query_type, query_id, self.data)
        cfg.client_socket.send(message)

    def delete(self) -> None:
        if self.query_id in nd.open_queries.keys():
            del nd.open_queries[self.query_id]

    def process_query_response(self, response: bytes):
        """process the query response and delete the query"""
        if self.processing_function is not None:
            self.processing_function(response, self.data)
        self.delete()
