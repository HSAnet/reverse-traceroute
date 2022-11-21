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

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import Node, Host, Controller
from mininet.nodelib import NAT
from mininet.log import setLogLevel
from mininet.cli import CLI
from mininet.util import irange
from mininet.link import Intf, TCIntf
from ipaddress import ip_network
from subprocess import TimeoutExpired

import time
import random
import itertools
import functools


def pairwise(iterable):
    a, b = itertools.tee(iterable)
    next(b, None)
    return zip(a, b)

class TestNode(Node):
    def config(self, **params):
        super().config(**params)
        self.cmd("sysctl net.ipv4.icmp_ratelimit=0")

    def terminate(self):
        self.cmd("sysctl net.ipv4.icmp_ratelimit=1000")
        super().terminate()

# Code from: https://github.com/mininet/mininet/blob/master/examples/linuxrouter.py
class Router(TestNode):
    def config(self, **params):
        super().config(**params)
        self.cmd("sysctl net.ipv4.ip_forward=1")
        self.cmd("sysctl net.ipv4.fib_multipath_hash_policy=1")

    def terminate(self):
        self.cmd("sysctl net.ipv4.ip_forward=0")
        self.cmd("sysctl net.ipv4.fib_multipath_hash_policy=0")
        super().terminate()


class DiamondTopo(Topo):
    def build(self, nrouters, **kwargs):
        assert nrouters > 0

        addRouter = functools.partial(self.addNode, cls=Router, **kwargs)
        addHost = functools.partial(self.addHost, cls=TestNode, **kwargs)

        start_router = addRouter("start", ip=f"10.0.1.1/24")
        end_router = addRouter("end", ip=f"11.0.1.1/24")
        upper_routers = [ addRouter(f"upper{i}", ip=f"12.0.{i+1}.1/24") for i in range(nrouters) ]
        lower_routers = [ addRouter(f"lower{i}", ip=f"13.0.{i+1}.1/24") for i in range(nrouters) ]

        client = addHost(
            "client", ip="10.0.1.100/24", **kwargs
        )
        server = addHost(
            "server", ip=f"11.0.1.100/24", **kwargs
        )

        # Connect client to start.
        self.addLink(client, start_router)
        self.addLink(server, end_router)

        self.addLink(start_router, upper_routers[0], params1={"ip": "12.0.1.2/24"})
        self.addLink(start_router, lower_routers[0], params1={"ip": "13.0.1.2/24"})

        # Upper section.
        for i, (u1, u2) in enumerate(pairwise(upper_routers)):
            self.addLink(u1, u2, params1={"ip": f"12.0.{i+2}.2/24"})

        # Lower section.
        for i, (l1, l2) in enumerate(pairwise(lower_routers)):
            self.addLink(l1, l2, params1={"ip": f"13.0.{i+2}.2/24"})

        self.addLink(end_router, upper_routers[-1],
            params1={"ip": f"12.0.{len(upper_routers)+1}.1/24"},
            params2={"ip": f"12.0.{len(upper_routers)+1}.2/24"},
        )
        self.addLink(end_router, lower_routers[-1],
            params1={"ip": f"13.0.{len(lower_routers)+1}.1/24"},
            params2={"ip": f"13.0.{len(lower_routers)+1}.2/24"},
        )


def connectedTo(intf):
    link = intf.link
    i1, i2 = link.intf1, link.intf2
    return i1 if intf == i2 else i2


def intf_network(intf):
    """Returns the network associated with a given interface."""
    return ip_network(f"{intf.IP()}/{intf.prefixLen}", strict=False)


def node_networks(node):
    """Returns all networks associated with the nodes interfaces."""
    return [ intf_network(i) for i in node.intfList() ]


def intf_routes(intf, excludes=None, current_weight=1):
    """Returns the networks reachable from interface with a given weight.
    The shortest weight is chosen if multiple weights are possible for a given network.
    """
    if excludes is None:
        excludes = set()
    else:
        excludes = set(excludes)
    excludes.add(intf)

    networks = {
        net: current_weight for net in node_networks(intf.node)
    }

    next_node = connectedTo(intf).node

    for intf in set(next_node.intfList()) - excludes:
        next_routes = intf_routes(intf, excludes, current_weight + 1)
        for net, weight in next_routes.items():
            # If a network entry already exists we choose the one with the least weight.
            if net in networks:
                weight = min(networks[net], weight)
            networks[net] = weight
    
    return networks


def node_routes(node):
    """Aggregates the routes for each interface of a node.
    If a network is reachable over multiple interfaces with the same weight,
    a list of those interfaces is returned.
    """
    net_from_intf = {}
    net_to_weight = {}

    local_nets = { intf_network(i) for i in node.intfList() }

    for intf in node.intfList():
        for net, weight in intf_routes(intf, excludes=local_nets).items():
            if net in net_from_intf:
                if weight > net_to_weight[net]:
                    continue
                elif weight == net_to_weight[net]:
                    net_from_intf[net].append(intf)
                    continue

            net_from_intf[net] = [intf]
            net_to_weight[net] = weight

    return net_from_intf


def configure_routes(node, routes):
    """Configures the routing table of a node based on the routes.
    The routes are determined by a call to node_routes.
    """
    node.cmd("ip route flush all")

    for intf in node.intfList():
        node.cmd(f"ip route add {connectedTo(intf).IP()} dev {intf}")
    
    for net, interfaces in routes.items():
        node.cmd(f"ip route add {net} " + 
            " ".join(
                f"nexthop via {connectedTo(intf).IP()}"
                for intf in interfaces
            )
        )


def run():
    topo = DiamondTopo(3)
    net = Mininet(
        topo=topo, waitConnected=True,
    )
    net.start()

    for node in net.values():
        # We skip the controller as we don't use it.
        if isinstance(node, Controller):
            continue
        routes = node_routes(node)
        configure_routes(node, routes)

    open_processes = []
    create_process = lambda node, cmd: open_processes.append(node.popen(cmd))

    try:
        create_process(net["end"], "tcpdump -i any -w end.pcap")

        client, server = net["client"], net["server"]
        create_process(server, "./server/augsburg-traceroute-server -n 50000 -t 1000000000 2")

        client.cmdPrint(f"augsburg-traceroute -l debug -o 'tcp' --inter 0 --timeout 1 --abort 3 two-way tcp multipath --retry -2 {server.IP()}")
        client.cmdPrint(f"augsburg-traceroute -l debug -o 'udp' --inter 0 --timeout 1 --abort 3 two-way udp multipath --retry -2 {server.IP()}")
        client.cmdPrint(f"augsburg-traceroute -l debug -o 'icmp' --inter 0 --timeout 1 --abort 3 two-way icmp multipath --retry -2 {server.IP()}")
    finally:
        for p in open_processes:
            try:
                p.terminate()
                p.wait(timeout=1)
            except TimeoutExpired:
                p.kill()

    net.stop()


if __name__ == "__main__":
    setLogLevel("info")
    run()
