import multiprocessing as mp
import os
from queue import PriorityQueue
from time import sleep
from typing import List

import numpy as np


class Philosopher:
    __message_id_to_title =\
        {
            0: "zahtjev",
            1: "odgovor",
            2: "izlazak"
        }

    def __init__(self, n_philosophers=None):
        self._read_p = list()
        self._write_p = list()
        self._read_ids = list()

        self._queue = PriorityQueue()
        self._replies = PriorityQueue()
        self._clock = np.random.randint(0, int(1e6) if n_philosophers is None else n_philosophers)
        self._identifier = None

    # region Properties
    @property
    def read_p(self):
        return self._read_p

    @property
    def write_p(self):
        return self._write_p

    @property
    def read_ids(self):
        return self._read_ids

    @property
    def queue(self):
        return self._queue

    @property
    def replies(self):
        return self._replies

    @property
    def clock(self):
        return self._clock

    @property
    def identifier(self):
        return self._identifier
    # endregion

    # region Transformations
    @staticmethod
    def get_message_tuple(message):
        return [int(x) for x in message.strip().split("\t")]

    @staticmethod
    def message_to_interpretation(message_tuple):
        message_title = Philosopher.__message_id_to_title.get(message_tuple[0], "nedefinirano")

        return f"{message_title}(i = {message_tuple[1]}, T[i] = {message_tuple[2]})"
    # endregion

    #   Note: I am aware that this could all be achieved by two messaging methods,
    #   but doing it like this gives me more flexibility and isn't strictly
    #   prohibited by the task itself.
    # region Messaging
    def request(self, identifier):
        self._queue.put((self.clock, 0, identifier))

        request = f"0\t{identifier}\t{self.clock}\n"

        for pipe in self._write_p:
            os.write(pipe, bytes(request, encoding="utf8"))

            message_interpretation = self.message_to_interpretation(Philosopher.get_message_tuple(request))
            print(f"[Filozof {self.identifier}] šalje:\t'{message_interpretation}'\n", end="")

    def reply(self, identifier):
        reply = f"1\t{identifier}\t{self.clock}\n"

        for pipe in self._write_p:
            os.write(pipe, bytes(reply, encoding="utf8"))

            message_interpretation = self.message_to_interpretation(Philosopher.get_message_tuple(reply))
            print(f"[Filozof {self.identifier}] šalje:\t'{message_interpretation}'\n", end="")

    def wait_for_requests(self):
        for fd in self._read_p:
            response = fd.readline()

            message_tuple = Philosopher.get_message_tuple(response)
            self.queue.put((message_tuple[2], message_tuple[0], message_tuple[1]))

            self._clock = max(self._clock, message_tuple[2]) + 1

            message_interpretation = self.message_to_interpretation(message_tuple)
            print(f"[Filozof {self.identifier}] čita:\t'{message_interpretation}'\n", end="")

        self.reply(self.identifier)

    def wait_for_replies(self):
        for fd in self._read_p:
            reply = fd.readline()

            message_tuple = Philosopher.get_message_tuple(reply)
            self.replies.put((message_tuple[2], message_tuple[0], message_tuple[1]))

            message_interpretation = self.message_to_interpretation(message_tuple)
            print(f"[Filozof {self.identifier}] čita:\t'{message_interpretation}'\n", end="")

    def exit(self):
        queue_get = self.queue.get()
        exit_message = f"2\t{queue_get[2]}\t{queue_get[0]}\n"

        for pipe in self._write_p:
            os.write(pipe, bytes(exit_message, encoding="utf8"))

            message_interpretation = self.message_to_interpretation(Philosopher.get_message_tuple(exit_message))
            print(f"[Filozof {self.identifier}] šalje:\t'{message_interpretation}'\n", end="")

    def wait_for_exits(self):
        #   Before trying to understand how this works, please understand how the
        #   pipe network is constructed with Conference.connect_philosophers.
        #   Anyways, because it is constructed in a deterministic way, we know
        #   what pipe to listen to based on the first element of the queue.
        #   Without it, we'd have to use non-blocking pipes, which are not
        #   available on every Unix and Windows OS like the regular pipes.

        while True:
            identifier_to_wait_for = self.queue.queue[0][2]

            if identifier_to_wait_for == self.identifier:
                break

            index_to_wait_for = identifier_to_wait_for

            if index_to_wait_for > self.identifier:
                index_to_wait_for -= 1

            exit_message = self._read_p[index_to_wait_for].readline()

            self.queue.get()

            message_interpretation = self.message_to_interpretation(self.get_message_tuple(exit_message))
            print(f"[Filozof {self.identifier}] čita:\t'{message_interpretation}'\n", end="")
    # endregion

    def do(self, identifier: int):
        self._identifier = identifier

        sleep(np.random.uniform(0.1, 2.))

        self.request(identifier)
        self.wait_for_requests()
        self.wait_for_replies()

        if self.queue.queue[0][2] != identifier:
            self.wait_for_exits()

        print(f"\nFilozof {identifier} je za stolom\n\n", end="")
        sleep(3.)

        self.exit()
        sleep(np.random.uniform(0.1, 2.))


class Conference:
    def __init__(self, n_philosophers: int):
        #   Note that the constraints below are not arbitrary, but a task limitation.
        #   Normally, the limit of philosophers is likely the square of pipes that
        #   can be opened on one system (as they scale quadratically).

        if n_philosophers is None or n_philosophers < 3:
            n_philosophers = 3

        if n_philosophers > 10:
            n_philosophers = 10

        self._philosopher_count = n_philosophers
        self._pipes = list()

    @property
    def philosopher_count(self):
        return self._philosopher_count

    def connect_philosophers(self, philosophers: List[Philosopher]):
        for i in range(len(philosophers)):
            for j in range(i + 1, len(philosophers)):
                i_r, i_w = os.pipe()
                j_r, j_w = os.pipe()

                philosophers[i].read_p.append(os.fdopen(j_r))
                philosophers[j].read_p.append(os.fdopen(i_r))
                philosophers[i].write_p.append(i_w)
                philosophers[j].write_p.append(j_w)

                self._pipes.extend([i_r, i_w, j_r, j_w])

    def start(self):
        philosophers = [Philosopher() for _ in range(self.philosopher_count)]
        self.connect_philosophers(philosophers)

        processes = list()

        for i, philosopher in enumerate(philosophers):
            processes.append(mp.Process(target=philosopher.do,
                                        args=(i, ),
                                        name=f"philosopher {i}",
                                        daemon=True))
            processes[-1].start()

        for process in processes:
            process.join()

        for pipe in self._pipes:
            os.close(pipe)

        print(f"\n\nKonferencija je završena!\n", end="")
