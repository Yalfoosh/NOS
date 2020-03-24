#   Copyright 2020 Miljenko Šuflaj
#
#    Licensed under the Apache License, Version 2.0 (the "License");
#    you may not use this file except in compliance with the License.
#    You may obtain a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and
#    limitations under the License.


import multiprocessing as mp
from time import sleep
from typing import List

import numpy as np


class Visitor:
    def __init__(self, name: str):
        #   I know that the identifier property can be done with simple
        #   integers, but my thinking was to allow string identifiers
        #   from the get go, irrespective of what I'd end up using.

        self._name = "visitor" if name is None else name
        self._process = None

    @property
    def name(self):
        return self._name

    @property
    def process(self):
        return self._process

    def start(self, in_q: mp.Queue, out_q: mp.Queue):
        self._process = mp.Process(target=self._do,
                                   args=(in_q, out_q),
                                   daemon=True,
                                   name=self.name)
        self._process.start()

    def _do(self, in_q: mp.Queue, out_q: mp.Queue):
        #   The number 3 is task specific; it's arbitrary otherwise.
        for _ in range(3):
            sleep(np.random.uniform(0.1, 2.))
            out_q.put("Želim se voziti")

            while True:
                message = in_q.get()

                if message != "Sjedni":
                    in_q.put(message)
                else:
                    break

            print(f"Sjeo posjetitelj {self.name}\n", end="")

            while True:
                message = in_q.get()

                if message != "Ustani":
                    in_q.put(message)
                else:
                    break

                #   This is optional, I like to sleep inactive threads in
                #   an infinite loop to give others some breathing room.
                sleep(0.05)

            print(f"Sišao posjetitelj {self.name}\n", end="")

        print(f"\nPosjetitelj {self.name} završio.\n\n", end="")


class Carousel:
    def __init__(self, max_visitors=None):
        self._max_visitors = 4 if max_visitors is None else max_visitors

        self._in_q = mp.Queue()
        self._out_q = mp.Queue()

        self._process = None
        self._workers: List[Visitor] = list()

    @property
    def in_q(self):
        return self._in_q

    @property
    def out_q(self):
        return self._out_q

    @property
    def max_visitors(self):
        return self._max_visitors

    def do(self, n_visitors=None):
        for i in range(8 if n_visitors is None else n_visitors):
            self._workers.append(Visitor(f"{i}"))

        for worker in self._workers:
            worker.start(self.out_q, self.in_q)

        non_zero_count = self.max_visitors

        while non_zero_count >= self.max_visitors:
            while self.in_q.get() != "Želim se voziti" and non_zero_count != 0:
                pass

            for _ in range(self.max_visitors):
                self.out_q.put("Sjedni")

            while self.out_q.qsize() != 0:
                sleep(0.05)

            print("\nPokrenuo vrtuljak\n", end="")
            sleep(np.random.uniform(1., 3.))
            print("\nVrtuljak zaustavljen\n\n", end="")

            for _ in range(self.max_visitors):
                self.out_q.put("Ustani")

            while self.out_q.qsize() != 0:
                sleep(0.05)

            non_zero_count = np.count_nonzero(np.array([x.process.exitcode is None for x in self._workers]))
