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

from graphviz import Digraph
import networkx as nx
from .core.container import TracerouteVertex


def create_graph(graph: Digraph, root: nx.DiGraph, hostnames: dict[str, str]):
    """Create a digraph from the root vertex."""
    for node in root.nodes:
        label = "\n".join(
            (node.value.address, f"{node.value.rtt:.2f}", *hostnames.get(node.value.address, [""]))
        )
        graph.node(str(node.id), label=label)

    for (node_a, node_b, attr) in root.edges(data=True):
        print(node_a, node_b)
        attr = {
            "color": "black" if attr["strong"] else "orange"
        }
        graph.edge(str(node_a.id), str(node_b.id), **attr)
