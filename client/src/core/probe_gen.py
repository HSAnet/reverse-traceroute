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

import itertools
import struct
import socket
import os
import functools
from collections import namedtuple
from ipaddress import ip_address, IPv4Address, IPv6Address
from scapy.packet import Packet
from scapy.layers.inet import IP, ICMP, TCP, UDP, in4_chksum, checksum
from scapy.layers.inet6 import IPv6, in6_chksum, ICMPv6EchoRequest, ICMPv6EchoReply
from scapy.sendrecv import send

# Overwrite scapy IPv6 matching behaviour to consider only id and seq fields, not the data
ICMPv6EchoReply.answers = (
    lambda self, other: self.id == other.id and self.seq == other.seq
)

TracerouteResult = namedtuple("TracerouteResult", ["address", "rtt"])

# Port assigned for traceroute use by IANA.
# This is the default outgoing source port for classic probes.
TRACEROUTE_PORT = 33434

class AbstractProbeGen:
    def __init__(self, target: str, protocol: str):
        self.is_ipv4 = isinstance(ip_address(target), IPv4Address)
        self.target = str(target)
        self.protocol = protocol
        self._probe_id = itertools.cycle(range(1, 0xFFFF + 1))

    def create_probe(self, ttl: int, flow: int) -> Packet:
        raise NotImplementedError("Override this method in your subclass")

    def parse_probe_response(
        self, request: Packet, response: Packet
    ) -> TracerouteResult:
        raise NotImplementedError("Override this method in your subclass")


class ClassicProbeGen(AbstractProbeGen):
    """Implements classic traceroute functionality."""

    def __init__(self, target: str, protocol: str):
        super().__init__(target, protocol)
        self.chksum = in4_chksum if self.is_ipv4 else in6_chksum

    def create_probe(self, ttl: int, flow: int) -> Packet:
        probe_id = next(self._probe_id)
        ip = (
            IP(dst=self.target, ttl=ttl)
            if self.is_ipv4
            else IPv6(dst=self.target, hlim=ttl)
        )

        if self.protocol == "icmp":
            if self.is_ipv4:
                l3 = ICMP(
                    type=8,
                    code=0,
                    id=(os.getpid() % 0xFF) + 1,
                    seq=probe_id,
                    chksum=flow,
                ) / struct.pack("!H", 0)
                l3.load = struct.pack("!H", checksum(bytes(l3)))

            else:
                l3 = ICMPv6EchoRequest(
                    code=0, id=(os.getpid() % 0xFF) + 1, seq=probe_id, cksum=flow
                ) / struct.pack("!H", 0)
                l3.load = struct.pack(
                    "!H", self.chksum(socket.IPPROTO_ICMPV6, ip, bytes(l3))
                )

        elif self.protocol == "udp":
            l3 = UDP(dport=flow, sport=TRACEROUTE_PORT, chksum=probe_id) / struct.pack("!H", 0)
            l3.load = struct.pack("!H", self.chksum(socket.IPPROTO_UDP, ip, bytes(l3)))

        elif self.protocol == "tcp":
            l3 = TCP(dport=flow, sport=TRACEROUTE_PORT, seq=probe_id)

        return ip / l3

    def parse_probe_response(
        self, request: Packet, response: Packet
    ) -> TracerouteResult:
        address = response.src
        rtt = (response.time - request.sent_time) * 1000
        return TracerouteResult(address, rtt)


class ReverseProbeGen(AbstractProbeGen):
    """Implements reverse traceroute functionality."""

    class Error(Exception):
        pass

    class NotSupportedException(Error):
        def __str__(self):
            return "The target does not support reverse traceroute"

    class InvalidTtlException(Error):
        def __str__(self):
            return "The target does not support the specified Time-To-Live (TTL)"

    class InvalidFlowException(Error):
        def __str__(self):
            return "The target does not support the specified flow. Try setting it to 0 to let the target choose a suitable value."

    class InvalidProtocolException(Error):
        def __str__(self):
            return "The target does not support the specified protocol. Try setting it to 0 to let the target choose a suitable value."

    STATUS_TO_EXCEPTION = {
        1: InvalidTtlException,
        2: InvalidFlowException,
        3: InvalidProtocolException,
    }

    def __init__(self, target: str, protocol: str):
        super().__init__(target, protocol)
        # Reuse identifiers which were answered by the server.
        # This reduces the number of entries to be maintained by a client-sided NAPT middlebox.
        # By using the last reclaimed identifier first (LIFO), we maximize the likelihood of
        # hitting an active NAPT entry, which eliminates the overhead to create a new one.
        self._reclaimed_identifiers = []

    def create_probe(self, ttl: int, flow: int) -> Packet:
        protocol = {
            "icmp": socket.IPPROTO_ICMP if self.is_ipv4 else socket.IPPROTO_ICMPV6,
            "udp": socket.IPPROTO_UDP,
            "tcp": socket.IPPROTO_TCP,
        }[self.protocol]

        probe_id = (
            self._reclaimed_identifiers.pop()
            if self._reclaimed_identifiers
            else next(self._probe_id)
        )
        header = struct.pack("!BBH", ttl, protocol, flow)
        if self.is_ipv4:
            return (
                IP(dst=self.target) / ICMP(type=8, code=1, id=probe_id, seq=0) / header
            )
        else:
            return (
                IPv6(dst=self.target)
                / ICMPv6EchoRequest(code=1, id=probe_id, seq=0)
                / header
            )

    def parse_probe_response(
        self, request: Packet, response: Packet
    ) -> TracerouteResult:
        icmp = response.getlayer(1)
        response_type = 0 if self.is_ipv4 else 129

        if icmp.type == response_type and icmp.code == 1:
            self._reclaimed_identifiers.append(icmp.id)
            try:
                load = icmp.load if self.is_ipv4 else icmp.data
                status, _ = struct.unpack("BB", load[:2])

                if status == 0x00:
                    address, rtt = struct.unpack("!16sI", load[4:24])
                    address = IPv6Address(address)
                    if self.is_ipv4:
                        address = address.ipv4_mapped
                    return TracerouteResult(str(address), rtt / 1000000)
                if status in self.STATUS_TO_EXCEPTION:
                    raise self.STATUS_TO_EXCEPTION[status]

            # We receive this error when data cannot be unpacked due to a malformed response.
            # We assume a malformed response indicates the absence of a reverse traceroute server at the target.
            except struct.error:
                pass

        raise self.NotSupportedException
