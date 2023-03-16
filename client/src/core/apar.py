import logging
import operator
from ipaddress import IPv4Network, IPv4Address
from itertools import groupby, combinations, pairwise, product, permutations, chain
from functools import reduce, cache
from collections import namedtuple

from .container import TracerouteVertex, BlackHoleVertex


log = logging.getLogger(__name__)


def group_subnets(vertices, prefix_len):
    vertices = (v for v in vertices if not isinstance(v, BlackHoleVertex))
    return {
        subnet: {v for v in vertices if IPv4Address(v.address) in subnet.hosts()}
        for subnet, vertices in groupby(
            sorted(vertices, key=lambda v: IPv4Address(v.address)),
            key=lambda v: IPv4Network(f"{v.address}/{prefix_len}", strict=False),
        )
    }


def accuracy(vertices, trace):
    if len(vertices) < 2:
        return True

    for a, b in combinations(vertices, r=2):
        if abs(trace.index(a) - trace.index(b)) > 1:
            return False
    return True


@cache
def form_subnets(forward, reverse):
    all_vertices = set(forward.flatten()) | set(reverse.flatten())
    completeness = lambda net, vertices: len(vertices) / net.num_addresses
    subnets_to_vertices = {}

    def _form_subnets(prefix_len=24):
        if prefix_len >= 32:
            return

        matches = group_subnets(all_vertices, prefix_len)
        for subnet, vertices in matches.items():
            if completeness(subnet, vertices) < 0.5:
                continue
            for trace in chain(forward.paths(), reverse.paths()):
                shared_vertices = set(trace) & vertices
                if not accuracy(shared_vertices, trace):
                    break
            else:
                subnets_to_vertices[subnet] = vertices

        _form_subnets(prefix_len + 1)

    _form_subnets()
    return sorted(
        subnets_to_vertices.items(), key=lambda x: completeness(*x), reverse=True
    )


def no_loop(forward, reverse, aliases):
    for trace in map(set, chain(forward.paths(), reverse.paths())):
        if len(trace & aliases) > 1:
            return False
    return True


def add_alias(vertex_pair, graph_pair, aliases):
    vertex_a, vertex_b = vertex_pair
    forward, reverse = graph_pair

    assert vertex_a != vertex_b

    overlap = {vertex_a, vertex_b}
    existing_sets = [alias_set for alias_set in aliases if alias_set & overlap]
    merged_aliases = reduce(operator.or_, existing_sets, overlap)

    if not no_loop(forward, reverse, merged_aliases):
        return

    for existing_set in existing_sets:
        aliases.remove(existing_set)

    aliases.append(merged_aliases)


def common_subnet(f_trace, r_trace, f_index, r_index, seen_subnets):
    if f_index < 1 or r_index < 1:
        return False
    candidate_subnet = {f_trace[f_index - 1], r_trace[r_index - 1]}
    return any(candidate_subnet.issubset(net) for net in seen_subnets)


def shared_neighbor(f_trace, r_trace, f_index, r_index):
    if f_index < 2 or r_index < 1:
        return False
    return f_trace[f_index - 2] == r_trace[r_index - 1]


def resolved_alias(f_trace, r_trace, f_index, r_index, aliases):
    if f_index < 2 or r_index < 1:
        return False
    candidate_aliases = {f_trace[f_index - 2], r_trace[r_index - 1]}
    return any(candidate_aliases.issubset(alias_set) for alias_set in aliases)


def resolve_aliases(forward, reverse, p2p, aliases=[]):
    forward_traces = list(forward.paths())
    reverse_traces = list(reverse.paths())

    aliases = list(aliases)
    seen_subnets = {}

    for subnet, vertices in form_subnets(forward, reverse):
        for f_trace, r_trace in permutations(forward_traces + reverse_traces, 2):
            r_trace = list(reversed(r_trace))

            f_vertices = set(f_trace) & vertices
            r_vertices = set(r_trace) & vertices

            for f_vertex, r_vertex in product(f_vertices, r_vertices):
                f_index = f_trace.index(f_vertex)
                r_index = r_trace.index(r_vertex)

                if f_index < 1:
                    continue

                candidates = f_trace[f_index - 1], r_trace[r_index]
                if candidates[0] == candidates[1]:
                    continue

                params = {
                    "f_trace": f_trace,
                    "r_trace": r_trace,
                    "f_index": f_index,
                    "r_index": r_index,
                }

                if (
                    (p2p and subnet.prefixlen >= 30)
                    or common_subnet(**params, seen_subnets=seen_subnets.values())
                    or resolved_alias(**params, aliases=aliases)
                    or shared_neighbor(**params)
                ):
                    add_alias(candidates, (forward, reverse), aliases)

            seen_subnets[subnet] = vertices
    return aliases


def apar(forward, reverse):
    aliases = resolve_aliases(forward, reverse, False)
    aliases = resolve_aliases(forward, reverse, True, aliases)

    with open("traces.txt", "w") as f:
        lines = []
        for trace in chain(forward.paths(), reverse.paths()):
            lines += ["#"] + [ v.address for v in trace ]
        f.writelines("\n".join(lines))

    log.info(f"{aliases=}")
    return aliases
