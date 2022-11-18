"""Contains graph operations for traceroute vertices."""
from graphviz import Digraph
from .core.container import TracerouteVertex


def create_graph(graph, root, hostnames, merge):
    """Create a digraph from the root vertex."""
    if merge:
        root.merge_vertices()

    nodes = list(root.flatten())

    for node in nodes:
        label = "\n".join(
            (node.address, f"{node.rtt:.2f}", *hostnames.get(node.address, [""]))
        )
        graph.node(str(id(node)), label=label)
    for node in nodes:
        for next_node in node.successors:
            graph.edge(str(id(node)), str(id(next_node)))
