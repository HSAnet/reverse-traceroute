from collections.abc import MutableSet, Mapping
from box import Box
from itertools import chain
import json

class HashSet(MutableSet, Mapping):
    """A set, which maps an objects hash to the object itself.
    This allows for object lookup without unnecessary looping overhead."""
    def __init__(self):
        super().__init__()

    def __init__(self, collection=[]):
        self.map = { hash(value): value for value in collection }
        super().__init__()

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
        self.predecessors = set()
        # Custom user definable data.
        self.data = Box(default_box=True)

    def update(self, flow, rtt):
        """Update the flow identifier and rtt measurements for a vertex."""
        self.flow_set.add(flow)
        self.rtt_list.append(rtt)

    def add_predecessor(self, other):
        """Adds a predecessor to the vertex.
        The predecessors successor is updates as well."""
        self.predecessors.add(other)
        other.successors.add(self)

    def del_predecessor(self, other):
        """Deletes a predecessor of the vertex."""
        self.predecessors.remove(other)
        other.successors.remove(self)

    def add_successor(self, other):
        """Adds a successor to the vertex.
        The successors predecessor is updates as well."""
        self.successors.add(other)
        other.predecessors.add(self)

    def del_successor(self, other):
        """Deletes a predecessor of the vertex."""
        self.successors.remove(other)
        other.predecessors.remove(self)

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

    def to_dict(self):
        return {
            "hash": hash(self),
            "address": str(self.address),
            "flows": list(self.flow_set),
            "rtts": list(self.rtt_list),
            "predecessors": list(map(hash, self.predecessors)),
            "successors": list(map(hash, self.successors)),
            "data": self.data.to_dict()
        }

    @property
    def rtt(self):
        if not self.rtt_list:
            return 0
        return sum(self.rtt_list) / len(self.rtt_list)

    # __eq__ and __hash__ are needed to store instances of TracerouteVertex in sets.
    # A TracerouteVertex is identified only by its address.
    def __eq__(self, other):
        return self.address == other.address

    def __hash__(self):
        return hash(self.address)

    def __repr__(self):
        return f"TracerouteVertex(address={self.address}, rtt={self.rtt:.2f}, predecessors={[str(p.address) for p in self.predecessors]}, successors={[str(s.address) for s in self.successors]})"


class BlackHoleVertex(TracerouteVertex):
    """A black hole."""
    def __init__(self):
        super().__init__("***")

    def __eq__(self, other):
        return False

    def __hash__(self):
        return id(self)


class TracerouteHop(HashSet):
    """A custom container for the vertices at a given hop.
    Provides convenience properties and methods for the set of vertices."""
    def __init__(self, ttl):
        super().__init__()
        self.ttl = ttl

    def __init__(self, ttl, collection=[]):
        super().__init__(collection)
        self.ttl = ttl

    @property
    def flows(self):
        return set(chain(*(v.flow_set for v in self)))

    @property
    def addresses(self):
        return set(v.address for v in self)

    def first(self):
        return next(iter(self))
