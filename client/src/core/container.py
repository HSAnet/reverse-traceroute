import logging
from collections.abc import MutableSet, Mapping
from itertools import groupby
from functools import reduce
from itertools import chain


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
    def __init__(self, address):
        self.address = address
        self.flow_set = set()
        self.rtt_list = list()
        self.successors = set()

    def update(self, flow, rtt):
        """Update the flow identifier and rtt measurements for a vertex."""
        self.flow_set.add(flow)
        self.rtt_list.append(rtt)

    def add_successor(self, other):
        """Adds a successor to the vertex.
        The successors predecessor is updates as well."""
        if not other in self.successors:
            logging.debug(f"Adding {other} as successor of {self}")
            if other == self:
                logging.warning(f"Successor {other} is equal to its predecessor")
            self.successors.add(other)

    def del_successor(self, other):
        """Deletes a predecessor of the vertex."""
        self.successors.remove(other)

    def flatten(self):
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

    def merge(self, other):
        assert self == other
        logging.debug("Merging {self} with {other}")

        self.successors.update(other.successors)
        # Due to GRE-Tunneling or Unequal-Cost-Load-Balancing the same vertex
        # may appear in successive hops with equal flows.
        # We get rid of such artefacts by removing self from our own successors,
        # thus breaking the circular link.
        # See: https://community.cisco.com/t5/routing/tracert-show-same-hop-twice/td-p/1502358
        self.successors.discard(self)
        self.flow_set.update(other.flow_set)
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

    def to_dict(self):
        return {
            "id": id(self),
            "hash": hash(self),
            "address": self.address,
            "rtt": list(self.rtt_list),
            "flows": list(self.flow_set),
            "successors": list(map(id, self.successors)),
        }

    @property
    def rtt(self):
        if not self.rtt_list:
            return 0
        return sum(self.rtt_list) / len(self.rtt_list)

    # __eq__ and __hash__ are needed to store instances of TracerouteVertex in sets.
    # A TracerouteVertex is identified only by its address.
    def __eq__(self, other):
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

    def __init__(self, predecessor):
        super().__init__("***")
        self.predecessor = predecessor
        predecessor.add_successor(self)
        self.flow_set.update(predecessor.flow_set)

    def __eq__(self, other):
        return hash(self) == hash(other)

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

    def add_or_update(self, vertex, flow, rtt):
        if vertex not in self:
            self.add(vertex)
            logging.info(f"Added new {vertex} to {self}")

        self[vertex].update(flow, rtt)

    @property
    def flows(self):
        return set(chain(*(v.flow_set for v in self)))

    @property
    def addresses(self):
        return set(v.address for v in self)

    def first(self):
        return next(iter(self))

    def connectTo(self, other):
        assert isinstance(other, TracerouteHop)

        for vertex in self:
            for next_vertex in other:
                if vertex.flow_set & next_vertex.flow_set:
                    vertex.add_successor(next_vertex)

    def __repr__(self):
        return f"Hop(ttl={self.ttl}, len={len(self)})"
