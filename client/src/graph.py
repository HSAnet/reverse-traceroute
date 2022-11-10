import graphviz
from itertools import groupby
from .container import TracerouteVertex


def _merge_vertices(root):
    """Merges duplicate vertices encountered in a trace.
    Duplicates vertices can occur in the presence of Unequal Multipath-Load Balancing."""
    # TODO: Work on copy so that merge does not affect stored json.
    buckets = [list(g) for k, g in groupby(sorted(root.flatten(), key=hash))]

    for group in buckets:
        if len(group) < 2:
            continue

        joint_vertex = TracerouteVertex(group[0].address)

        for vertex in group:
            for v in vertex.predecessors.copy():
                vertex.del_predecessor(v)
                if v != vertex:
                    joint_vertex.add_predecessor(v)
            for v in vertex.successors.copy():
                vertex.del_successor(v)
                if v != vertex:
                    joint_vertex.add_successor(v)

            for flow, rtt in zip(vertex.flow_set, vertex.rtt_list):
                joint_vertex.update(flow, rtt)


def create_graph(root, node_str_func):
    assert callable(node_str_func)

    _merge_vertices(root)
    nodes = list(root.flatten())

    graph = graphviz.Digraph(strict=True)

    for node in nodes:
        graph.node(str(id(node)), label=node_str_func(node))
    for node in nodes:
        for next_node in node.successors:
            print(f"{node.address} -> {next_node.address}")
            graph.edge(str(id(node)), str(id(next_node)))

    return graph
