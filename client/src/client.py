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
import argparse
import json
import socket
from itertools import compress
from ipaddress import ip_address, IPv4Address, IPv6Address
from concurrent.futures import ThreadPoolExecutor

from scapy.sendrecv import sr1
from scapy.route import conf as route_conf
from scapy.config import conf as scapy_conf
import graphviz

from .core.engine import AbstractEngine, SinglepathEngine, MultipathEngine
from .core.probe_gen import AbstractProbeGen, ClassicProbeGen, ReverseProbeGen
from .core.container import TracerouteVertex, BlackHoleVertex
from .graph import create_graph
from .args import parse_arguments
from .transmit import transmit_measurement

from .core.apar import apar


logging.getLogger("graphviz").setLevel(logging.ERROR)

# Issue each warning exactly once
scapy_conf.warning_threshold = float("inf")
# Do not propagate any scapy logs to the root logger to avoid duplicates
if logging.getLogger("scapy").hasHandlers():
    logging.getLogger("scapy").propagate = False
# Filter all scapy messages starting with "more"
logging.getLogger("scapy.runtime").addFilter(
    lambda record: 0 if record.msg.startswith("more") else 1
)

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


def create_measurement(
    args: argparse.Namespace,
    traces: dict[str, TracerouteVertex],
    hostnames: dict[str, str],
):
    return {
        **create_measurement_args(args),
        "traces": {
            # Store the measurement raw (not merged).
            # Should the merge logic change in the future, past measurements remain valid.
            direction: [v.to_dict() for v in trace.flatten()]
            for direction, trace in traces.items()
        },
        "hostnames": hostnames,
    }


def resolve_hostnames(root: TracerouteVertex) -> dict[str, str]:
    """Map IP addresses to hostnames for a root vertex and its children."""

    def resolve(address: str):
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


def prompt_confirm(prompt: str):
    """Prints a prompt to stdout and asks for user confirmation [Yes/No]"""
    choice = input(prompt + "\nDo you want to proceed [Yes/No]: ").lower()
    return choice == "y" or choice == "yes"


def create_probing_engine(args: argparse.Namespace):
    cls_args = {
        "inter": args.inter,
        "timeout": args.timeout,
        "abort": args.abort,
    }
    if args.engine == "multipath":
        return MultipathEngine(
            args.confidence,
            args.retry,
            args.min_burst,
            args.max_burst,
            args.opt_single_vertex_hop,
            **cls_args,
        )
    else:
        return SinglepathEngine(args.flow, args.probes, **cls_args)


def discover(
    engine: AbstractEngine,
    probe_generator: AbstractProbeGen,
    remote_addr: str,
    min_ttl: int,
    max_ttl: int,
) -> TracerouteVertex:
    if isinstance(ip_address(remote_addr), IPv4Address):
        route = route_conf.route.route
    else:
        route = route_conf.route6.route
    local_addr = route(remote_addr)[1]

    if isinstance(probe_generator, ClassicProbeGen):
        first_hop = local_addr
        destination = remote_addr
    else:
        first_hop = remote_addr
        destination = local_addr

    return engine.discover(probe_generator, min_ttl, max_ttl, first_hop, destination)


def render_graph(
    traces: dict[str, TracerouteVertex],
    hostnames: dict[str, str],
    output: str,
    merge: bool,
):
    parent = graphviz.Digraph(strict=True)
    for direction, trace in traces.items():
        with parent.subgraph(name=f"cluster_{direction}") as g:
            if merge:
                trace.merge()
            g.node_attr.update(style="filled")
            g.attr(label=direction.upper())
            create_graph(g, trace, hostnames)
    parent.render(output, cleanup=True)


def try_getaddrinfo(target: str, family: int) -> tuple[bool, tuple]:
    try:
        return True, socket.getaddrinfo(target, None, family)[0]
    except:
        return False, None


def try_find_target(target: str, is_v4_v6: tuple[bool, bool]) -> tuple[bool, str]:
    try:
        return str(ip_address(args.target))
    except:
        af_families = [socket.AF_INET, socket.AF_INET6]
        selectors = list(is_v4_v6) if any(is_v4_v6) else [True, True]

        for af in compress(af_families, selectors):
            valid, result = try_getaddrinfo(target, af)
            if valid:
                *_, sockaddr = result
                return True, sockaddr[0]

        return False, None


def main():
    args = parse_arguments()

    logging.basicConfig(
        level={
            "info": logging.INFO,
            "debug": logging.DEBUG,
            "warning": logging.WARNING,
        }[args.log_level]
    )

    valid, target = try_find_target(args.target, (args.ipv4, args.ipv6))
    if not valid:
        log.error(f"Failed to resolve '{args.target}'")
        exit()
    else:
        log.info(f"Determined traceroute target: {target}")

    engine = create_probing_engine(args)
    traces = {}

    if args.direction in ("two-way", "forward"):
        probe_gen = ClassicProbeGen(target, args.protocol)
        root = discover(engine, probe_gen, target, args.min_ttl, args.max_ttl)
        traces["forward"] = root
    if args.direction in ("two-way", "reverse"):
        probe_gen = ReverseProbeGen(target, args.protocol)

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
        except ReverseProbeGen.InvalidTtlException:
            pass
        except Exception as e:
            logging.error(e)
            exit()

        root = discover(engine, probe_gen, target, args.min_ttl, args.max_ttl)
        traces["reverse"] = root

    # Resolve hostnames
    hostnames = {}
    if not args.no_resolve:
        for trace in traces.values():
            hostnames.update(resolve_hostnames(trace))

    # Resolve aliases
    if args.resolve_aliases:
        if args.direction == "two-way" and isinstance(ip_address(target), IPv4Address):
            alias_buckets = apar(traces["forward"], traces["reverse"])
            with open(f"{args.output}" + ".aliases", "w") as f:
                f.write(
                    "\n".join(
                        ",".join(v.address for v in alias_set)
                        for alias_set in alias_buckets
                    )
                )
        else:
            log.warn(
                "Ignoring the '--resolve-aliases' flag as alias resolution is only supported for two-way IPv4 traces."
            )

    # Create the measurement before merging the graph.
    # Should the merging algorithm change, the measurements
    # still remain valid and unchanged.
    measurement = create_measurement(args, traces, hostnames)
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

    # Finally, render the graph.
    render_graph(traces, hostnames, args.output, not args.no_merge)
