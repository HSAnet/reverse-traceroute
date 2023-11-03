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

from ipaddress import ip_address, ip_network
import random
from signal import SIGINT
from mininet.net import Mininet
from mininet.node import Node
from mininet.topo import Topo
from mininet.log import setLogLevel, info
from mininet.link import TCIntf
from networkx import MultiGraph, all_shortest_paths, multi_source_dijkstra
from itertools import chain, permutations, product, pairwise
from pprint import pprint
from functools import partial


class Router(Node):
    def config(self, **params):
        super(Router, self).config(**params)
        self.cmd("sysctl net.ipv4.ip_forward=1")
        self.cmd("sysctl net.ipv6.ip_forward=1")
        self.cmd("sysctl net.ipv4.fib_multipath_hash_policy=1")
        self.cmd("sysctl net.ipv6.fib_multipath_hash_policy=1")

    def terminate(self):
        self.cmd("sysctl net.ipv4.ip_forward=0")
        self.cmd("sysctl net.ipv6.ip_forward=0")
        self.cmd("sysctl net.ipv4.fib_multipath_hash_policy=0")
        self.cmd("sysctl net.ipv6.fib_multipath_hash_policy=0")
        super(Router, self).terminate()


class DiamondTopo(Topo):

    def build(self):
        x1, x2, u1, u2, l1, l2, l3 = (self.addHost(name, cls=Router) for name in ("x1", "x2", "u1", "u2", "l1", "l2", "l3"))
        client = self.addHost("client")
        server = self.addHost("server")

        self.addLink(x1, u1, weight=2)
        self.addLink(u1, u2)
        self.addLink(u2, x2)

        self.addLink(x1, l1)
        self.addLink(l1, l2)
        self.addLink(l2, l3)
        self.addLink(l3, x2)

        self.addLink(client,x1, weight=1)
        self.addLink(x2,server, weight=1)


def configure_routes(net, start, stop):
    graph = net.topo.convertTo(MultiGraph)

    routes = {}
    paths = list(all_shortest_paths(graph, start, stop, weight="weight"))
    for path in paths:
        for hop, next_hop in pairwise(path):
            print(f"{hop} -> {next_hop}")
            if hop not in routes: routes[hop] = set()
            connections = net[hop].connectionsTo(net[next_hop])
            pprint(connections)
            for con in connections:
                routes[hop].add(con)

    pprint(routes)
    for node, connections in routes.items():
        routes_str = " ".join(f"nexthop via {next_iface.IP()} dev {local_iface.name}" for local_iface, next_iface in connections)
        net[node].cmdPrint(f"ip route add {net[stop].IP()} {routes_str}")



if __name__ == "__main__":
    setLogLevel("info")

    topo = DiamondTopo()
    net = Mininet(topo=topo, intf=partial(TCIntf, delay=f"{random.randint(2,5)}ms", jitter="1ms"))
    net.start()


    try:
        networks = ((f"10.0.{prefix}.1/24", f"10.0.{prefix}.2/24") for prefix in range(255))
        for link in net.links:
            network = next(networks)
            link.intf1.setIP(network[0])
            link.intf2.setIP(network[1])

        configure_routes(net, "client", "server")
        configure_routes(net, "server", "client")
        net.pingFull([net["client"], net["server"]])
        
        net.interact()
    finally:
        net.stop()
