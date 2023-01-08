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

import time
import sys
from signal import SIGINT
from configparser import ConfigParser
from ipmininet.iptopo import IPTopo
from ipmininet.ipnet import IPNet
from ipmininet.cli import IPCLI


class DiamondTopo(IPTopo):

    def build(self, *args, **kwargs):
        x1, x2, u1, u2, m1, m2, l1, l2 = self.addRouters("x1", "x2", "u1", "u2", "m1", "m2", "l1", "l2")
        client = self.addHost("client")
        server = self.addHost("server")

        self.addLinks((x1,u1),(x1,m1),(x1,l1))
        self.addLinks((u1,u2),(m1,m2),(l1,l2))
        self.addLinks((u2,x2),(m2,x2),(l2,x2))
        self.addLinks((client,x1),(x2,server))

        super().build(*args, **kwargs)


    def post_build(self, net):
        for r in self.routers():
            net[r].cmd("sysctl net.ipv4.fib_multipath_hash_policy=1")
            net[r].cmd("sysctl net.ipv6.fib_multipath_hash_policy=1")

        super().post_build(net)



if __name__ == "__main__":
    assert len(sys.argv) == 2
    cfg_path = sys.argv[1]

    cfg_parser = ConfigParser()
    cfg_parser.read(cfg_path)

    cfg = cfg_parser["TESTLAB"]

    client = cfg["client"]
    server_v4 = cfg["server_v4"]
    server_v6 = cfg["server_v6"]

    net = IPNet(topo=DiamondTopo())
    try:
        net.start()

        popen_v4 = net["server"].popen(server_v4, "server-eth0")
        popen_v6 = net["server"].popen(server_v6, "server-eth0")

        print("Waiting 30 seconds for routes to converge..")
        time.sleep(30)

        for af in ["4","6"]:
            for proto in ["udp", "tcp", "icmp"]:
                print(f"Running test with IPv{af} and protocol {proto}")
                popen_pcap = net["server"].popen("tcpdump", "-i", "server-eth0", "-w", f"{proto}_{af}.pcap")
                net["client"].cmd(f"{client} -o {proto}_{af} -{af} reverse {proto} multipath server")
                popen_pcap.send_signal(SIGINT)
                time.sleep(0.5)

        popen_v4.send_signal(SIGINT)
        popen_v6.send_signal(SIGINT)
    finally:
        net.stop()
