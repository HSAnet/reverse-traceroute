"""
Copyright 2022 University of Applied Sciences Augsburg

This file is part of Augsburg-Traceroute.

Augsburg-Traceroute is free software: you can redistribute it and/or modify it under the terms
of the GNU General Public License as published by the Free Software Foundation,
either version 3 of the License, or (at your option) any later version.

Augsburg-Traceroute is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with Augsburg-Traceroute.
If not, see <https://www.gnu.org/licenses/>.
"""

import random
import time
import math
import logging
import itertools
from typing import Generator
from collections.abc import Iterable
from functools import reduce
from scapy.sendrecv import sr

from .container import TracerouteVertex, BlackHoleVertex, TracerouteHop
from .mda import stopping_point
from .probe_gen import AbstractProbeGen


log = logging.getLogger(__name__)

class AbstractEngine:
    def __init__(self, inter: float, timeout: float, abort: int):
        assert inter >= 0
        self.inter = inter
        assert timeout > 0
        self.timeout = timeout
        assert abort >= 2
        self.abort = abort

    def _init_root_vertex(self, root: TracerouteVertex):
        pass

    def _probe_and_update(
        self,
        probe_generator: AbstractProbeGen,
        hop: TracerouteHop,
        next_hop: TracerouteHop,
    ):
        raise NotImplementedError

    def discover(
        self,
        probe_generator: AbstractProbeGen,
        min_ttl: int,
        max_ttl: int,
        first_hop: str,
        target: str = None,
    ) -> TracerouteVertex:
        """The main discovery logic of the traceroute engines.
        It proceeds until the target is hit (if defined) or successive identical
        vertices possibly intermixed with black holes are found in a length
        greater than the abort attribute."""
        assert min_ttl > 0 and max_ttl >= min_ttl

        root = TracerouteVertex(first_hop)
        self._init_root_vertex(root)
        addresses = lambda hop: set(v.address for v in hop)
        hop = TracerouteHop(0, [root])

        unresponsive = 0
        last_known_vertex = None

        for ttl in range(min_ttl, max_ttl + 1):
            log.info(f"Probing hop with TTL {ttl}")
            next_hop = TracerouteHop(ttl)
            self._probe_and_update(probe_generator, hop, next_hop)

            # Connect all vertices without successors to a newly created
            # black hole, which inherits the flows of its predecessors.
            # Thus we can chain multiple black holes by flow inheritance,
            # which can be reconnected once a successor vertex with a matching flow is found.
            dangling_vertices = [v for v in hop if not v.successors]
            for v in dangling_vertices:
                black_hole = BlackHoleVertex(v)
                next_hop.add(black_hole)

            # Check if the abort condition is met.
            # If multiple successive black holes possibly intermixed with a single vertex
            # are found, increment the unresponsive counter.
            has_black_holes = all(isinstance(v, BlackHoleVertex) for v in next_hop)
            has_single_vertex = (
                sum(1 for v in next_hop if not isinstance(v, BlackHoleVertex)) == 1
            )
            if has_black_holes ^ has_single_vertex:
                next_vertex = next_hop.first()

                if has_black_holes:
                    unresponsive += 1
                elif next_vertex == last_known_vertex:
                    unresponsive += 1
                else:
                    if target and next_vertex.address == target:
                        last_known_vertex = None
                        break

                    unresponsive = 0
                    last_known_vertex = next_vertex
            else:
                unresponsive = 0
                last_known_vertex = None

            if unresponsive >= self.abort:
                log.info("Limit of unresponsive hops exceeded. Aborting.")
                break

            hop = next_hop

        # Track back to the last known vertex and disconnect
        # successive black holes if such a vertex is known.
        if last_known_vertex is not None:
            last_known_vertex.successors.clear()
        return root


class SinglepathEngine(AbstractEngine):
    """A classic single path traceroute with a fixed flow."""

    def __init__(
        self, flow: int, probes_per_hop: int, inter: float, timeout: float, abort: int
    ):
        super().__init__(inter, timeout, abort)
        assert probes_per_hop > 0
        self.probes_per_hop = probes_per_hop
        assert flow > 0
        self.flow = flow

    def __send_probes_to_hop(
        self, probe_generator: AbstractProbeGen, hop: TracerouteHop
    ):
        probes = [
            probe_generator.create_probe(hop.ttl, self.flow)
            for _ in range(self.probes_per_hop)
        ]

        ans, _ = sr(probes, inter=self.inter, timeout=self.timeout, verbose=0)

        for req, resp in ans:
            address, rtt = probe_generator.parse_probe_response(req, resp)
            vertex = TracerouteVertex(address)

            hop.add_or_update(vertex, self.flow, rtt)

    def _init_root_vertex(self, root: TracerouteVertex):
        root.flow_set.add(self.flow)

    def _probe_and_update(
        self,
        probe_generator: AbstractProbeGen,
        hop: TracerouteHop,
        next_hop: TracerouteHop,
    ):
        self.__send_probes_to_hop(probe_generator, next_hop)
        hop.connectTo(next_hop)


class MultipathEngine(AbstractEngine):
    """A hop-by-hop variation of the existing diamond miner algorithm."""

    def __init__(self, confidence, retry, min_burst, max_burst, inter, timeout, abort):
        super().__init__(inter, timeout, abort)
        assert confidence > 0 and confidence < 1
        self.confidence = confidence
        assert retry >= 0
        self.retry = retry
        assert min_burst > 0 and min_burst < max_burst
        self.min_burst = min_burst
        self.max_burst = max_burst

    def __next_flow(self) -> int:
        """Generates a pseudo-random uniform flow identifier in the range
        between 10000 and 65535."""
        return int(random.uniform(10000, 65535))

    def __generate_flows(self, hop) -> Generator[int, None, None]:
        """Generates flow identifiers to be used for the current hop.
        First all previously used identifiers are returned vertex by vertex.
        If they are exhausted, new identifiers are generated."""
        prev_flows = hop.flows
        yield from prev_flows
        while True:
            flow = self.__next_flow()
            if flow not in prev_flows:
                prev_flows.add(flow)
                yield flow

    def __send_probes_to_hop(self, probe_generator, hop, flows):
        """Sends probes with a given ttl and flows.
        The algorithm works like the regular scapy sr() function,
        but a reimplementation is needed to create new probes with unique
        identifiers each round."""

        ttl = hop.ttl
        chunk_size = self.min_burst

        retry_counter = 0
        unresp_flows = set(flows)

        while unresp_flows:
            log.debug(f"Attempting to send {len(unresp_flows)} probes to {hop}")

            iter_flows = iter(list(unresp_flows))
            while chunk := list(itertools.islice(iter_flows, chunk_size)):
                log.debug(f"Using chunk size {chunk_size}")

                probes = [probe_generator.create_probe(ttl, flow) for flow in chunk]
                ans, unans = sr(probes, inter=self.inter, timeout=self.timeout, verbose=0)

                for req, resp in ans:
                    flow = chunk[probes.index(req)]
                    address, rtt = probe_generator.parse_probe_response(req, resp)
                    vertex = TracerouteVertex(address)

                    hop.add_or_update(vertex, flow, rtt)
                    unresp_flows.discard(flow)

                log.debug(f"Received {len(ans)} responses, {len(unans)} remaining.")
                if len(ans) == chunk_size:
                    chunk_size = min(self.max_burst, chunk_size * 2)
                else:
                    chunk_size = self.min_burst

            if retry_counter >= abs(self.retry):
                log.warn("Exceeded retry limit. Breaking from send loop.")
                break
            retry_counter += 1



    def __nprobes(self, hop: TracerouteHop) -> int:
        """Computes the number of flows needed for the next hop."""
        probes = lambda v: stopping_point(
            max(1, len(v.successors)) + 1, self.confidence
        )

        total_flows = len(hop.flows)
        max_probes = 0
        for vertex in hop:
            denominator = len(vertex.flow_set) / total_flows if vertex.flow_set else 1
            result = math.ceil(probes(vertex) / denominator)
            if result > max_probes:
                max_probes = result
        return max_probes

    def _probe_and_update(self, probe_generator: AbstractProbeGen, hop, next_hop):
        iter_flows = self.__generate_flows(hop)

        start = 0
        stop = self.__nprobes(hop)
        while stop > start:
            flows = set(next(iter_flows) for _ in range(start, stop))
            log.debug(f"Generated {len(flows)} flows.")

            # If the current hop only contains a single vertex,
            # all links will originate from it.
            # Thus there is no need to probe the hop with unknown flows,
            # which is why we assign all flows to it's flow set beforehand.
            if len(hop) == 1:
                hop.first().flow_set.update(flows)
                log.debug(
                    f"Filled flow set of single vertex hop {hop.first()} at {hop}"
                )
            n_hops = len(next_hop)

            # Do not send flows that already reached the current hop.
            self.__send_probes_to_hop(probe_generator, hop, flows - hop.flows)
            self.__send_probes_to_hop(probe_generator, next_hop, flows & hop.flows)

            hop.connectTo(next_hop)

            # If no new vertices were discovered in this round
            # we break out from the loop.
            # Otherwise rate limited vertices in the current hop
            # will amplify the number of probes in each iteration,
            # without providing any new results.
            if len(next_hop) == n_hops:
                log.debug("No new vertices discovered. Stopped probing.")
                break

            start = stop
            stop = self.__nprobes(hop)
