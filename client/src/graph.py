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
from .core.container import TracerouteVertex


def create_graph(
    graph: Digraph, root: TracerouteVertex, hostnames: dict[str, str], merge: bool
):
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
            attr = {
                "color": "black" if node.flow_set & next_node.flow_set else "orange"
            }
            graph.edge(str(id(node)), str(id(next_node)), **attr)
