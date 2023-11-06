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
import os
import shutil
from pathlib import Path
from signal import SIGINT
from configparser import ConfigParser
from ipmininet.iptopo import IPTopo
from ipmininet.ipnet import IPNet
from ipmininet.cli import IPCLI


class DiamondTopo(IPTopo):
    def build(self, *args, **kwargs):
        x1, x2, u1, u2, l1, l2, l3 = self.addRouters("x1", "x2", "u1", "u2", "l1", "l2", "l3")
        client = self.addHost("client")
        server = self.addHost("server")

        self.addLink(x1, u1, igp_metric=1)
        self.addLink(u1, u2, igp_metric=1)
        self.addLink(u2, x2, igp_metric=2)

        self.addLink(x1, l1, igp_metric=1)
        self.addLink(l1, l2, igp_metric=1)
        self.addLink(l2, l3, igp_metric=1)
        self.addLink(l3, x2, igp_metric=1)

        self.addLinks((client,x1),(x2,server))

        super().build(*args, **kwargs)


    def post_build(self, net):
        for r in self.routers():
            net[r].cmd("sysctl net.ipv4.fib_multipath_hash_policy=1")
            net[r].cmd("sysctl net.ipv6.fib_multipath_hash_policy=1")

        super().post_build(net)



if __name__ == "__main__":
    net = IPNet(topo=DiamondTopo())
    try:
        net.start()

        print("Waiting 30 seconds for routes to converge..")
        time.sleep(30)

        result_dir = Path(os.getcwd()) / "results"
        shutil.rmtree(result_dir)
        os.mkdir(result_dir)

        for af in ("4", "6"):
            for proto in ("tcp", "udp", "icmp"):
                print(f"Running test with proto {proto} for IPv{af}")

                path = result_dir / f"{proto}-v{af}"
                os.mkdir(path)

                server_log = open(path / "server.txt", "w")
                server = net["server"].popen(f"augsburg-traceroute-server-v{af}", "server-eth0", stdout=server_log, stderr=server_log)
                server_pcap = net["server"].popen(f"tcpdump -w {path / 'server.pcap'}")

                try:
                    client_trace = path / "trace.pdf"
                    client_log = open(path / "client.txt", "w")
                    client_pcap = net["server"].popen(f"tcpdump -w {path / 'client.pcap'}")
                    client = net["client"].popen(f"augsburg-traceroute -{af} -o {client_trace} two-way {proto} multipath server", stdout=client_log, stderr=client_log)
                    try:
                        client.wait()
                    finally:
                        client_pcap.terminate()
                        client_log.close()

                finally:
                    server.terminate()
                    server_pcap.terminate()
                    server_log.close()

    finally:
        net.stop()
