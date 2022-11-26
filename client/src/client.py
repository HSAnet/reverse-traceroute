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

import logging
import json
import socket
import argparse
from ipaddress import IPv4Address
from concurrent.futures import ThreadPoolExecutor

from scapy.sendrecv import sr1
from scapy.route import conf
import graphviz

from .core.engine import SinglepathEngine, MultipathEngine
from .core.probe_gen import ClassicTraceroute, ReverseTraceroute
from .core.container import TracerouteVertex, BlackHoleVertex
from .graph import create_graph
from .args import parse_arguments
from .transmit import transmit_measurement


logging.getLogger("graphviz").setLevel(logging.ERROR)
log = logging.getLogger(__name__)


def create_measurement_args(args: argparse.Namespace) -> dict:
    """Creates a fixed mapping of CLI arguments to measurement parameters.
    Should the CLI change in the future, it is the job of this function
    to keep the measurement data coherent."""
    return {
        "target": args.target,
        "protocol": args.protocol,
        "min_ttl": args.min_ttl,
        "max_ttl": args.max_ttl,
        args.engine: {
            "flow": args.flow,
            "probes": args.probes,
        }
        if args.engine == "singlepath"
        else {
            "confidence": args.confidence,
            "retry": args.retry,
            "min_burst": args.min_burst,
            "max_burst": args.max_burst,
            "single_vertex_probe_opt": args.opt_single_vertex_hop,
        },
        "inter": args.inter,
        "timeout": args.timeout,
        "abort": args.abort,
    }


def resolve_hostnames(root: TracerouteVertex) -> dict[str, str]:
    """Map IP addresses to hostnames for a root vertex and its children."""

    def resolve(address):
        import socket

        try:
            addr, aliases, _ = socket.gethostbyaddr(address)
            return True, [addr] + aliases
        except:
            return False, None

    resolve_table = {}
    nodes = set(v for v in root.flatten() if not isinstance(v, BlackHoleVertex))
    # Perform DNS lookup for IP addresses by concurrently calling
    # the resolve function.

    with ThreadPoolExecutor() as resolver:
        node_addresses = [node.address for node in nodes]
        hostnames = resolver.map(resolve, node_addresses)
        for node, (valid, hostname) in zip(nodes, hostnames):
            if valid:
                resolve_table[node.address] = hostname

    return resolve_table


def prompt_confirm(prompt):
    """Prints a prompt to stdout and asks for user confirmation [Yes/No]"""
    choice = input(prompt + "\nDo you want to proceed [Yes/No]: ").lower()
    return choice == "y" or choice == "yes"


def main():
    args = parse_arguments()
    logging.basicConfig(
        level={
            "info": logging.INFO,
            "debug": logging.DEBUG,
            "warning": logging.WARNING,
        }[args.log_level]
    )
    proto = {
        "tcp": socket.IPPROTO_TCP,
        "udp": socket.IPPROTO_UDP,
        "icmp": socket.IPPROTO_ICMP,
    }[args.protocol]

    try:
        target = str(IPv4Address(args.target))
    except:
        target = socket.gethostbyname(args.target)

    cls_args = {
        "inter": args.inter,
        "timeout": args.timeout,
        "abort": args.abort,
    }
    if args.engine == "multipath":
        merge = not args.no_merge
        traceroute = MultipathEngine(
            args.confidence,
            args.retry,
            args.min_burst,
            args.max_burst,
            args.opt_single_vertex_hop,
            **cls_args,
        )
    else:
        merge = False
        traceroute = SinglepathEngine(args.flow, args.probes, **cls_args)

    traces = {}

    outgoing_ip = conf.route.route(target)[1]
    if args.direction == "two-way" or args.direction == "forward":
        probe_gen = ClassicTraceroute(target, proto)
        first_hop = outgoing_ip
        destination = target
        root = traceroute.discover(
            probe_gen, args.min_ttl, args.max_ttl, first_hop, destination
        )
        traces["forward"] = root

    if args.direction == "two-way" or args.direction == "reverse":
        probe_gen = ReverseTraceroute(target, proto)

        # By requesting a probe with a TTL of 0 an error condition is created.
        # A reverse traceroute server will reply with a status code 1,
        # which is encoded into the same offset as the 0 TTL of the request.
        # Should the target not run reverse traceroute, a regular Echo response
        # with a matching code (0) will be received, triggering an exception.
        req = probe_gen.create_probe(0, 0)
        resp = sr1(req, retry=3, timeout=args.timeout, verbose=0)
        if not resp:
            log.error("The target did not respond to the reverse traceroute probe.")
            exit()
        try:
            probe_gen.parse_probe_response(req, resp)
        except ReverseTraceroute.InvalidTtlException:
            pass
        except Exception as e:
            logging.error(e)
            exit()

        first_hop = target
        destination = outgoing_ip
        root = traceroute.discover(
            probe_gen, args.min_ttl, args.max_ttl, first_hop, destination
        )
        traces["reverse"] = root

    hostnames = {}
    if not args.no_resolve:
        for trace in traces.values():
            hostnames.update(resolve_hostnames(trace))

    measurement = {
        **create_measurement_args(args),
        "traces": {
            # Store the measurement raw (not merged).
            # Should the merge logic change in the future, past measurements remain valid.
            direction: [v.to_dict() for v in trace.flatten()]
            for direction, trace in traces.items()
        },
        "hostnames": hostnames,
    }

    parent = graphviz.Digraph(strict=True)
    for direction, trace in traces.items():
        with parent.subgraph(name=f"cluster_{direction}") as g:
            g.node_attr.update(style="filled")
            g.attr(label=direction.upper())
            create_graph(g, trace, hostnames, merge)
    parent.render(args.output, cleanup=True)

    if args.store_json:
        with open(f"{args.output}.json", "w") as writer:
            json.dump(measurement, writer, indent=4)

    if args.transmit:
        transmit = args.assume_yes or prompt_confirm(
            "Due to the --transmit flag, "
            + "your data will be uploaded to the HSA-Net group."
        )

        if transmit:
            try:
                transmit_measurement(measurement)
            except Exception as e:
                print("Failed to submit measurement data!")
                print(e)
            else:
                print(
                    "Successfully transmitted your data!"
                    + " Thank you for contributing to our measurement study."
                )
        else:
            print("Aborting transmission!")
