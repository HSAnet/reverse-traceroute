from .container import TracerouteVertex, BlackHoleVertex
from ipaddress import IPv4Network, IPv4Address
from itertools import groupby, combinations, pairwise, product, chain
from pprint import pprint
from functools import reduce
import operator


def group_subnets(vertices, prefix_len):
    vertices = (v for v in vertices if not isinstance(v, BlackHoleVertex))
    return {
        subnet: {
            v for v in vertices
            if IPv4Address(v.address) in subnet.hosts()
        }
        for subnet, vertices in groupby(
            sorted(vertices, key=lambda v: IPv4Address(v.address)),
            key=lambda v: IPv4Network(f"{v.address}/{prefix_len}", strict=False)
        )
    }


def accuracy(vertices, trace):
    if len(vertices) < 2:
        return True

    for a, b in combinations(vertices, r=2):
        if abs(trace.index(a) - trace.index(b)) > 1:
            print(f"Accuracy of {a} and {b} not met")
            print(trace)
            return False
    return True

def form_subnets(forward, reverse):
    all_vertices = set(forward.flatten()) | set(reverse.flatten())
    completeness = lambda net, vertices: len(vertices) / net.num_addresses
    subnets_to_vertices = {}
    
    def _form_subnets(prefix_len=24):
        if prefix_len >= 32:
            return

        matches = group_subnets(all_vertices, prefix_len)
        for subnet, vertices in matches.items():
            print(f"{subnet=} {vertices=}")
            if completeness(subnet, vertices) < 0.5:
                print(f"Completeness not satisfied.")
                continue
            for trace in chain(forward.traces(), reverse.traces()):
                shared_vertices = set(trace) & vertices
                if not accuracy(shared_vertices, trace):
                    print("Accuracy not satisfied.")
                    break
            else:
                subnets_to_vertices[subnet] = vertices

        _form_subnets(prefix_len+1)

    _form_subnets()
    return sorted(
        subnets_to_vertices.items(),
        key=lambda x: completeness(*x),
        reverse=True
    )
          

def no_loop(forward, reverse, aliases):
    for trace in chain(forward.traces(), reverse.traces()):
        for alias in aliases:
            if aliases - {alias} in trace:
                return False
    return True
        
def add_alias(vertex_pair, graph_pair, aliases):
    vertex_a, vertex_b = vertex_pair
    forward, reverse = graph_pair

    overlap = {vertex_a, vertex_b}
    existing_sets = [ 
        alias_set for alias_set in aliases
        if alias_set & overlap
    ]

    merged_aliases = reduce(
        operator.or_,
        existing_sets,
        overlap
    )

    if not no_loop(forward, reverse, merged_aliases):
        print("No-loop condition not met.")
        return

    for existing_set in existing_sets:
        aliases.remove(existing_set)

    aliases.append(merged_aliases)
    print(f"{aliases=}")


def apar(forward, reverse):
    forward_traces = list(forward.traces())
    reverse_traces = list(reverse.traces())

    seen_subnets = {}
    aliases = []

    for subnet, vertices in form_subnets(forward, reverse):
        print(f"{subnet=}")
        for f_trace, r_trace in product(forward_traces, reverse_traces):
            f_vertices = set(f_trace) & vertices
            r_vertices = set(r_trace) & vertices

            if not (f_vertices and r_vertices):
                continue

            for f_vertex, r_vertex in product(f_vertices, r_vertices):
                f_index = f_trace.index(f_vertex)
                r_index = r_trace.index(r_vertex)

                candidates = f_trace[f_index-1], r_trace[r_index]
                lhs = f_trace[f_index-2], r_trace[r_index+1]

                print()
                print()
                print(f"{f_trace=}")
                print(f"{r_trace=}")
                print(f"Aligned on {f_trace[f_index], r_trace[r_index]}")
                print(f"{candidates=}")
                print(f"{lhs=}")

                shared_neighbor = lambda: lhs[0] == lhs[1]
                resolved_alias = lambda: any(set(lhs) & alias_set for alias_set in aliases)
                common_subnet = lambda: any({lhs[1], candidates[0]} & vertices for vertices in seen_subnets.values())

                print(f"{shared_neighbor()=}")
                print(f"{resolved_alias()=}")
                print(f"{common_subnet()=}")
                if shared_neighbor() or resolved_alias() or common_subnet():
                    add_alias(candidates, (forward, reverse), aliases)


            seen_subnets[subnet] = vertices

    for subnet, vertices in seen_subnets.items():
        if subnet.prefixlen < 30:
            continue
        for f_trace, r_trace in product(forward_traces, reverse_traces):
            f_vertices = set(f_trace) & vertices
            r_vertices = set(r_trace) & vertices

            if not (f_vertices and r_vertices):
                continue

            for f_vertex, r_vertex in product(f_vertices, r_vertices):
                f_index = f_trace.index(f_vertex)
                r_index = r_trace.index(r_vertex)

                candidates = f_trace[f_index-1], r_trace[r_index]
                add_alias(candidates, (forward, reverse), aliases)
     


forward_trace = [
    TracerouteVertex(addr) for addr in [
        "18.7.21.1", "18.168.0.27", "192.5.89.89", "192.5.89.10",
        "198.32.8.85", "192.32.8.65", "192.32.8.33", "206.223.141.69",
        "206.223.131.74"
    ]
]

reverse_trace = [
    TracerouteVertex(addr) for addr in [
        "18.7.21.7", "18.168.0.25", "192.5.89.90", "192.5.89.9",
        "192.32.8.84", "192.32.8.66", "192.32.8.34", "206.223.141.70",
        "206.223.141.73", "129.110.5.1", "129.110.95.1"
    ]
]

for a,b in pairwise(forward_trace):
    a.add_successor(b)

for a,b in pairwise(reversed(reverse_trace)):
    a.add_successor(b)

apar(forward_trace[0], reverse_trace[-1])
