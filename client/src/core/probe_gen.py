import itertools
import socket
import struct
import os
from collections import namedtuple
from scapy.layers.inet import IP, ICMP, TCP, UDP, in4_chksum, checksum
from scapy.sendrecv import send
from ipaddress import IPv4Address
from random import randint

TracerouteResult = namedtuple("TracerouteResult", ["address", "rtt"])


class AbstractProbeGen:
    def __init__(self, target, protocol):
        self.target = target
        self.protocol = protocol
        self._probe_id = itertools.cycle(range(1, 0xFFFF + 1))
        for _ in range(1, randint(1, 0xFFFF)):
            next(self._probe_id)

    def create_probe(self, hop, flows):
        raise NotImplementedError("Override this method in your subclass")

    def parse_probe_response(self, request, response):
        raise NotImplementedError("Override this method in your subclass")


class ClassicTraceroute(AbstractProbeGen):
    """Implements classic traceroute functionality."""

    def __init__(self, target, protocol):
        super().__init__(target, protocol)

    def create_probe(self, hop, flow):
        probe_id = next(self._probe_id)
        ip = IP(dst=self.target, ttl=hop)

        if self.protocol == socket.IPPROTO_ICMP:
            l3 = ICMP(
                type=8, code=0, id=(os.getpid() % 0xFF) + 1, seq=probe_id, chksum=flow
            ) / struct.pack("!H", 0)
            l3.load = struct.pack("!H", checksum(bytes(l3)))

        elif self.protocol == socket.IPPROTO_UDP:
            l3 = UDP(dport=flow, sport=1021, chksum=probe_id) / struct.pack("!H", 0)
            l3.load = struct.pack("!H", in4_chksum(self.protocol, ip, bytes(l3)))

        elif self.protocol == socket.IPPROTO_TCP:
            l3 = TCP(dport=flow, sport=1021, seq=probe_id)

        return ip / l3

    def parse_probe_response(self, request, response):
        address = response.src
        rtt = (response.time - request.sent_time) * 1000

        return TracerouteResult(address, rtt)


class ReverseTraceroute(AbstractProbeGen):
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

    def __init__(self, target, protocol):
        super().__init__(target, protocol)

    def create_probe(self, hop, flow):
        probe_id = next(self._probe_id)
        header = struct.pack("!BBH", hop, self.protocol, flow)
        return IP(dst=self.target) / ICMP(type=8, code=1, id=probe_id, seq=0) / header

    def parse_probe_response(self, request, response):
        if response.type == 0 and response.code == 1:
            try:
                raw_data = response.getlayer("Raw")
                if raw_data:
                    load = raw_data.load
                    status, err_len = struct.unpack("BB", load[:2])

                    if status == 0x00:
                        address, rtt = struct.unpack("!II", load[16:24])
                        return TracerouteResult(
                            str(IPv4Address(address)), rtt / 1000000
                        )
                    else:
                        if status in self.STATUS_TO_EXCEPTION:
                            raise self.STATUS_TO_EXCEPTION[status]

            # We receive this error when data cannot be unpacked due to a malformed response.
            # We assume a malformed response indicates the absence of a reverse traceroute server at the target.
            except struct.error:
                pass

        raise self.NotSupportedException
