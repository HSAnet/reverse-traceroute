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
from random import shuffle
from itertools import islice, product
from typing import Generator
from collections.abc import Iterable
from functools import reduce
from scapy.sendrecv import sr

from .container import TracerouteVertex, BlackHoleVertex, TracerouteHop
from .mda import stopping_point
from .probe_gen import AbstractProbeGen


log = logging.getLogger(__name__)


class AbstractEngine:
    """An abstract implementation of a traceroute probing engine."""

    def __init__(
        self,
        inter: float,
        timeout: float,
        abort: int,
    ):
        assert inter >= 0
        self.inter = inter
        assert timeout > 0
        self.timeout = timeout
        assert abort >= 2
        self.abort = abort

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

    def _probe_and_update(
        self,
        probe_generator: AbstractProbeGen,
        hop: TracerouteHop,
        next_hop: TracerouteHop,
    ):
        probes = [
            probe_generator.create_probe(next_hop.ttl, self.flow)
            for _ in range(self.probes_per_hop)
        ]

        ans, _ = sr(probes, inter=self.inter, timeout=self.timeout, verbose=0)

        for req, resp in ans:
            address, rtt = probe_generator.parse_probe_response(req, resp)
            vertex = TracerouteVertex(address)
            next_hop.add_or_update(vertex, self.flow, rtt)

        hop.first().flow_set.add(self.flow)
        hop.connectTo(next_hop)


class MultipathEngine(AbstractEngine):
    """A hop-by-hop variation of the existing diamond miner algorithm."""

    flow_range = set(range(10000, 0xFFFF + 1))

    def __init__(
        self,
        confidence: float,
        retry: int,
        min_burst: int,
        max_burst: int,
        opt_single_vertex_hop: bool,
        inter: float,
        timeout: float,
        abort: int,
    ):
        super().__init__(inter, timeout, abort)
        assert confidence > 0 and confidence < 1
        self.confidence = confidence
        assert retry >= 0
        self.retry = retry
        assert min_burst > 0 and min_burst < max_burst
        self.min_burst = min_burst
        self.max_burst = max_burst
        self.opt_single_vertex_hop = opt_single_vertex_hop

    def __send_probes_to_hop(
        self, probe_generator: AbstractProbeGen, hop: TracerouteHop, flows: set[int]
    ):
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
            while chunk := list(islice(iter_flows, chunk_size)):
                log.debug(f"Using chunk size {chunk_size}")

                probes = [probe_generator.create_probe(ttl, flow) for flow in chunk]
                ans, unans = sr(
                    probes, inter=self.inter, timeout=self.timeout, verbose=0
                )

                for req, resp in ans:
                    flow = chunk[probes.index(req)]
                    address, rtt = probe_generator.parse_probe_response(req, resp)
                    vertex = TracerouteVertex(address)

                    hop.add_or_update(vertex, flow, rtt)
                    unresp_flows.discard(flow)

                log.debug(f"Received {len(ans)}/{len(probes)} responses")
                if len(ans) == chunk_size:
                    chunk_size = min(self.max_burst, chunk_size * 2)
                else:
                    chunk_size = self.min_burst

            if retry_counter >= abs(self.retry):
                log.warn("Exceeded retry limit, breaking from send loop")
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
            denominator = len(vertex.flows) / total_flows if vertex.flow_set else 1
            result = math.ceil(probes(vertex) / denominator)
            if result > max_probes:
                max_probes = result
        return max_probes

    def __generate_flows(self, hop: TracerouteHop) -> Generator[set[int], None, None]:
        """Generates flow sets until an optimal stopping point is reached."""

        def generate():
            yield from range(10000, 65535)
            log.warn(f"Exhausted all possible flows for {hop=}")

        start = 0
        flow_generator = generate()

        while (stop := self.__nprobes(hop)) > start:
            yield set(islice(flow_generator, stop - start))
            start = stop

    def _probe_and_update(
        self,
        probe_generator: AbstractProbeGen,
        hop: TracerouteHop,
        next_hop: TracerouteHop,
    ):
        """Probes a pair of hops and connects their vertices to each other."""
        for flows in self.__generate_flows(hop):
            # Send probes to the next hop first.
            # For the path A -> B -> C -> D this leads to the following probing pattern:
            # "B -> A -> C -> B -> D -> C" instead of
            # "A -> B -> B -> C -> C -> D".
            # By avoiding to probe hops twice in a row the impact of rate limiting
            # is reduced.
            self.__send_probes_to_hop(probe_generator, next_hop, flows)

            missing_flows = next_hop.flows - hop.flows
            send_probes = lambda: self.__send_probes_to_hop(
                probe_generator, hop, missing_flows
            )

            if missing_flows:
                if len(hop) == 1:
                    if hop.ttl == 0:
                        log.debug("Root hop found -> Skipping send_probes")
                        hop.first().flow_set.update(missing_flows)
                    elif self.opt_single_vertex_hop:
                        log.debug("Single vertex hop found -> Skipping send_probes")
                        hop.first().shadow_flow_set.update(missing_flows)
                    else:
                        send_probes()
                else:
                    send_probes()

            # The rationale behind stopping when no more *NEW* links are detected
            # is that when at a given hop one node hits rate-limiting, the distribution
            # of answered probes starts to shift.
            # The flow generator uses said distribution to calculate the number of new flows
            # needed to reach the successors of each node in question, resulting in a higher
            # number of flows needed for the rate-limited node as less probes are known to 'reach' it.
            # In each following iteration the distribution gets more unbalanced, as the rate-limited node
            # is not attributed any new probes whilst the likelihood of reaching the other nodes increases
            # with each answered probe, resulting in statistically more probes needed for the rate-limited node
            # to reach it's successors.
            # By stopping the probing when no new links were detected in an iteration said problem is eliminated.
            if hop.connectTo(next_hop) == 0:
                log.warn("No more links detected. Breaking from send loop.")
                break
