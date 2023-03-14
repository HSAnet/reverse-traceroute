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

import logging
from typing import Generator
from collections.abc import MutableSet, Mapping
from itertools import groupby, product
from functools import reduce
from itertools import chain


log = logging.getLogger(__name__)


class HashSet(MutableSet, Mapping):
    """A set, which maps an objects hash to the object itself.
    It behaves like a set but also allows lookup of existing elements with the
    __get_item__ operator.
    Hence its main purpose is to store objects or lookup an existing reference
    if an equal object is already stored."""

    def __init__(self, collection=[]):
        super().__init__()
        self.map = {hash(value): value for value in collection}

    def __contains__(self, value):
        return hash(value) in self.map

    def __iter__(self):
        yield from self.map.values()

    def __len__(self):
        return len(self.map)

    def add(self, value):
        key = hash(value)
        if not key in self.map:
            self.map[key] = value

    def discard(self, value):
        key = hash(value)
        if key in self.map:
            del self.map[key]

    def clear(self):
        self.map.clear()

    def __getitem__(self, value):
        return self.map[hash(value)]

    def __repr__(self):
        return "{" + ", ".join(map(repr, self.map.values())) + "}"


class TracerouteVertex:
    def __init__(self, address: str):
        self.address = address
        self.flow_set = set()
        self.rtt_list = list()
        self.successors = set()

        # The shadow flow set contains flows
        # which never really reached the vertex but
        # should be treated like they did.
        # E.g. black holes only contain shadow flows.
        self.shadow_flow_set = set()

    @property
    def flows(self):
        """Returns the current flow set, including the shadow flows."""
        return self.flow_set | self.shadow_flow_set

    def update(self, flow: int, rtt: int):
        """Update the flow identifier and rtt measurements for a vertex."""
        self.flow_set.add(flow)
        self.rtt_list.append(rtt)

    def add_successor(self, other: "TracerouteVertex"):
        """Adds a successor to the vertex.
        The successors predecessor is updates as well."""
        if not other in self.successors:
            log.debug(f"Adding {other} as successor of {self}")
            if other == self:
                log.warning(f"Successor {other} is equal to its predecessor")
            self.successors.add(other)
            return True

        return False

    def del_successor(self, other: "TracerouteVertex"):
        """Deletes a predecessor of the vertex."""
        self.successors.remove(other)

    def flatten(self) -> Generator["TracerouteVertex", None, None]:
        """Return a flattened sequence of vertices with unique ID's."""
        identifiers = set()

        def _flatten(vertex):
            if id(vertex) not in identifiers:
                identifiers.add(id(vertex))
                yield vertex
            for next_vertex in vertex.successors:
                if id(next_vertex) not in identifiers:
                    yield from _flatten(next_vertex)

        yield from _flatten(self)

    def traces(self) -> Generator[list["TracerouteVertex"], None, None]:
        "Return all loop-free paths from start to finish."

        def _traces(vertex, trace=[]):
            trace = list(trace)
            if vertex in trace:
                return

            trace.append(vertex)
            if not vertex.successors:
                yield trace
            for next_vertex in vertex.successors:
                yield from _traces(next_vertex, trace)

        yield from _traces(self)

    def merge(self, other: "TracerouteVertex") -> "TracerouteVertex":
        assert self == other
        log.debug(f"Merging {self} with {other}")

        self.successors.update(other.successors)
        # Due to GRE-Tunneling or Unequal-Cost-Load-Balancing the same vertex
        # may appear in successive hops with equal flows.
        # We get rid of such artefacts by removing self from our own successors,
        # thus breaking the circular link.
        # See: https://community.cisco.com/t5/routing/tracert-show-same-hop-twice/td-p/1502358
        self.successors.discard(self)
        self.flow_set.update(other.flow_set)
        self.shadow_flow_set.update(other.shadow_flow_set)
        self.rtt_list.extend(other.rtt_list)

        return self

    def merge_vertices(self):
        """Merges duplicate vertices encountered in a trace.
        Duplicates vertices can occur in the presence of Unequal-Cost-Load-Balancing."""
        buckets = [list(g) for k, g in groupby(sorted(self.flatten(), key=hash))]
        reduced_buckets = [reduce(lambda a, b: a.merge(b), group) for group in buckets]

        for vertex in reduced_buckets:
            for v in vertex.successors.copy():
                # Rewire all successors to equal objects in the merged list
                vertex.del_successor(v)
                vertex.add_successor(reduced_buckets[reduced_buckets.index(v)])

    def to_dict(self) -> dict:
        return {
            "id": id(self),
            "hash": hash(self),
            "address": self.address,
            "rtt": list(self.rtt_list),
            "flows": list(self.flow_set),
            "successors": list(map(id, self.successors)),
        }

    @property
    def rtt(self) -> float:
        if not self.rtt_list:
            return 0
        return sum(self.rtt_list) / len(self.rtt_list)

    # __eq__ and __hash__ are needed to store instances of TracerouteVertex in sets.
    # A TracerouteVertex is identified only by its address.
    def __eq__(self, other: "TracerouteVertex"):
        if not isinstance(other, TracerouteVertex):
            return False
        return self.address == other.address

    def __hash__(self):
        return hash(self.address)

    def __repr__(self):
        return f"Vertex(address={self.address})"


class BlackHoleVertex(TracerouteVertex):
    """A black hole, which is identified solely by its predecessor.
    Two black holes are hence equal if they share the same predecessor."""

    def __init__(self, predecessor: TracerouteVertex):
        super().__init__("***")
        self.predecessor = predecessor
        predecessor.add_successor(self)
        self.shadow_flow_set.update(predecessor.flow_set)
        self.shadow_flow_set.update(predecessor.shadow_flow_set)

    def __eq__(self, other: TracerouteVertex):
        return isinstance(other, TracerouteVertex) and hash(self) == hash(other)

    def __hash__(self):
        return hash((self.address, self.predecessor))

    def __repr__(self):
        return f"BlackHole(predecessor={self.predecessor})"


class TracerouteHop(HashSet):
    """A custom container for the vertices at a given hop.
    Provides convenience properties and methods for the set of vertices."""

    def __init__(self, ttl, collection=[]):
        super().__init__(collection)
        self.ttl = ttl

    def add_or_update(self, vertex: TracerouteVertex, flow: int, rtt: float):
        if vertex not in self:
            self.add(vertex)
            log.info(f"Added new {vertex} to {self}")

        self[vertex].update(flow, rtt)

    @property
    def flows(self):
        return set(chain(*(v.flows for v in self)))

    @property
    def addresses(self) -> set[str]:
        return set(v.address for v in self)

    def first(self) -> TracerouteVertex:
        return next(iter(self))

    def connectTo(self, other: TracerouteVertex):
        assert isinstance(other, TracerouteHop)
        new_links = 0

        for vertex, next_vertex in product(self, other):
            if not vertex.flows & next_vertex.flows:
                continue
            if vertex.add_successor(next_vertex):
                new_links += 1

        return new_links

    def __repr__(self):
        return f"Hop(ttl={self.ttl}, len={len(self)})"
