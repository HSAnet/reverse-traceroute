from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import Node, Host, Controller
from mininet.nodelib import NAT
from mininet.log import setLogLevel
from mininet.cli import CLI
from mininet.util import irange
from mininet.link import Intf, TCIntf
from ipaddress import ip_network

import time
import random
import itertools
import functools


def pairwise(iterable):
    a, b = itertools.tee(iterable)
    next(b, None)
    return zip(a, b)


# Code from: https://github.com/mininet/mininet/blob/master/examples/linuxrouter.py
class Router(Node):
    def config(self, **params):
        super(Router, self).config(**params)
        self.cmd("sysctl net.ipv4.ip_forward=1")
        self.cmd("sysctl net.ipv4.fib_multipath_hash_policy=1")

    def terminate(self):
        self.cmd("sysctl net.ipv4.ip_forward=0")
        self.cmd("sysctl net.ipv4.fib_multipath_hash_policy=0")


class DiamondTopo(Topo):
    def build(self, upper, lower, **kwargs):
        addRouter = functools.partial(self.addNode, cls=Router, **kwargs)

        start_router = addRouter("start", ip=f"10.0.1.1/24")
        end_router = addRouter("end", ip=f"11.0.1.1/24")
        upper_routers = [ addRouter(f"upper{i}", ip=f"12.0.{i+1}.1/24") for i in range(upper) ]
        lower_routers = [ addRouter(f"lower{i}", ip=f"13.0.{i+1}.1/24") for i in range(lower) ]

        client = self.addHost(
            "client", ip="10.0.1.100/24", **kwargs
        )
        server = self.addHost(
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
    net_to_weight = {}
    net_from_intf = {}

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
    topo = DiamondTopo(2, 3)
    net = Mininet(
        topo=topo, waitConnected=True,
        intf=functools.partial(
            TCIntf, delay=f"{random.randint(2,5)}ms", jitter="1ms"
        )
    )
    net.start()

    for node in net.values():
        # We skip the controller as we don't use it.
        if isinstance(node, Controller):
            continue
        routes = node_routes(node)
        configure_routes(node, routes)

    net["end"].cmdPrint("ip route delete 10.0.1.0/24")
    net["end"].cmdPrint("ip route add 10.0.1.0/24 nexthop via 12.0.3.2 nexthop via 13.0.4.2")
    net["end"].cmdPrint("ip route show")
    client, server = net["client"], net["server"]
    server.sendCmd(f"./server/src/augsburg-traceroute 2");

    client.cmdPrint(f"augsburg-traceroute {server.IP()} -o tcp -s -r -T --inter 0 --timeout 1 --abort 1")
    client.cmdPrint(f"augsburg-traceroute {server.IP()} -o udp -s -r -U --timeout 1 --abort 1")
    client.cmdPrint(f"augsburg-traceroute {server.IP()} -o icmp -s -r -I --timeout 1 --abort 1")

    server.sendInt()
    server.waitOutput()

    net.stop()


if __name__ == "__main__":
    setLogLevel("info")
    run()
