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
    for id_n, attr_n in root.nodes(data=True):
        node = attr_n["object"]
        print(node)
        label = "\n".join(
            (node.address, f"{node.rtt:.2f}", *hostnames.get(node.address, [""]))
        )
        graph.node(str(id_n), label=label)

    for (id_a, id_b, attr) in root.edges(data=True):

        attr = {
            "color": "black" if attr["strong"] else "orange"
        }
        graph.edge(str(id_a), str(id_b), **attr)
