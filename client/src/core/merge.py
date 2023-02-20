from .container import TracerouteVertex, BlackHoleVertex
from ipaddress import IPv4Network, IPv4Address
from itertools import groupby, combinations, pairwise, product, chain
from pprint import pprint
from functools import reduce, cache
import operator


class Apar:
    def __init__(self, forward, reverse):
        self.aliases = []
        self.all_vertices = set(forward.flatten()) | set(reverse.flatten())
        self.forward = forward
        self.reverse = reverse

    def group_subnets(self, vertices, prefix_len):
        return {
            k: list(v) for k,v in groupby(
                vertices,
                lambda v: IPv4Network(f"{v.address}/{prefix_len}", strict=False)
            )
        }

    @cache
    def completeness(self, subnet):
        return sum(
            1 for addr in map(lambda v: IPv4Address(v.address), self.all_vertices)
            if addr in subnet.hosts()
        ) / sum(1 for _ in subnet.hosts())

    def accuracy(self, vertices, trace):
        for a, b in combinations(vertices, r=2):
            if abs(trace.index(a) - trace.index(b)) > 1:
                print(f"Accuracy of {a} and {b} not met")
                print(trace)
                return False
        return True

    def form_subnets(self, trace: list[TracerouteVertex]):
        subnets = [ set() for _ in range(len(trace)) ]
        
        def _form_subnets(prefix_len=24):
            if prefix_len >= 32:
                return

            matches = self.group_subnets(trace, prefix_len)

            for subnet, vertices in matches.items():
                for vertex in vertices:
                    if IPv4Address(vertex.address) not in subnet.hosts():
                        vertices.remove(vertex)

                if not (vertices and self.accuracy(vertices, trace)):
                    continue
                if self.completeness(subnet) < 0.5:
                    continue

                for vertex in vertices:
                    subnets[trace.index(vertex)].add(subnet)

            _form_subnets(prefix_len+1)

        _form_subnets()
        return subnets

    def no_loop(self, aliases):
        for trace in chain(self.forward.traces(), self.reverse.traces()):
            for alias in aliases:
                if aliases - {alias} in trace:
                    return False
        return True
            
    def add_alias(self, vertex_a, vertex_b):
        overlap = {vertex_a, vertex_b}
        existing_sets = [ 
            alias_set for alias_set in self.aliases
            if alias_set & overlap
        ]

        aliases = reduce(
            operator.or_,
            (alias_set for alias_set in self.aliases if alias_set & overlap),
            overlap
        )

        if not self.no_loop(aliases):
            print("No-loop condition not met.")
            return

        for existing_set in existing_sets:
            self.aliases.remove(existing_set)

        self.aliases.append(aliases)
        print(self.aliases)



    def run(self):
        forward_traces = self.forward.traces()
        reverse_traces = self.reverse.traces()
        for f, r in product(forward_traces, reverse_traces):
            f_net_vertices = self.form_subnets(f)
            r_net_vertices = self.form_subnets(r)

            common_subnets = reduce(operator.or_, f_net_vertices) & reduce(operator.or_, r_net_vertices)

            for subnet in reversed(sorted(common_subnets, key=self.completeness)):
                f_indices = [ i for i,nets in enumerate(f_net_vertices) if subnet in nets ]
                r_indices = [ i for i,nets in enumerate(r_net_vertices) if subnet in nets ]

                for f_index, r_index in product(f_indices, r_indices):
                    candidates = f[f_index], r[r_index-1] 
                    
                    shared_subnets = lambda i,j: f_net_vertices[i] & r_net_vertices[j]
                    if shared_subnets(f_index-1, r_index+1) and shared_subnets(f_index+1, r_index-1):
                        print("Shared subnet condition.")
                        self.add_alias(*candidates)
                    elif f_net_vertices[f_index-1] == r_net_vertices[r_index+1]:
                        print("Shared neighbor condition.")
                        self.add_alias(*candidates)
                    elif any({f[f_index-1],r[r_index+1]} & aliases for aliases in self.aliases):
                        self.add_alias(*candidates)
                print(subnet, f_indices, r_indices)

            for subnet in reversed(sorted(common_subnets, key=self.completeness)):
                if subnet.prefixlen < 30:
                    continue

                f_indices = [ i for i,nets in enumerate(f_net_vertices) if subnet in nets ]
                r_indices = [ i for i,nets in enumerate(r_net_vertices) if subnet in nets ]

                for f_index, r_index in product(f_indices, r_indices):
                    print("Second phase") 
                    candidates = f[f_index], r[r_index-1] 
                    self.add_alias(*candidates)
 
            #self.resolve(f, r, f_net_vertices, r_net_vertices)

forward_trace = [
    TracerouteVertex(addr) for addr in [
        "18.7.21.1", "18.168.0.27", "192.5.89.89", "192.5.89.10",
        "198.32.8.85", "192.32.8.65", "192.32.8.33", "206.223.141.69",
        "206.223.131.74"
    ]
]

reverse_trace = [
    TracerouteVertex(addr) for addr in [
        "18.7.21.84", "18.168.0.25", "192.5.89.90", "192.5.89.9",
        "192.32.8.84", "192.32.8.66", "192.32.8.34", "206.223.141.70",
        "206.223.141.73", "129.110.5.1", "129.110.95.1"
    ]
]

for a,b in pairwise(forward_trace):
    a.add_successor(b)

for a,b in pairwise(reversed(reverse_trace)):
    a.add_successor(b)

apar = Apar(forward_trace[0], reverse_trace[-1])
apar.run()
