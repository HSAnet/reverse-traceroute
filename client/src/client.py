import logging
import json
import functools
import socket
from ipaddress import IPv4Address
from concurrent.futures import ThreadPoolExecutor

from scapy.sendrecv import sr1
from scapy.route import conf
import graphviz

from .core.engine import SinglepathEngine, MultipathEngine
from .core.probe_gen import ClassicTraceroute, ReverseTraceroute
from .core.container import BlackHoleVertex

from .graph import create_graph

from .args import parse_arguments
from .transmit import transmit_measurement


def create_measurement_args(args):
    return {
        "target": args.target,
        "protocol": args.protocol,

        "min_ttl": args.min_ttl,
        "max_ttl": args.max_ttl,

        args.engine: {
            "flow": args.flow,
            "probes": args.probes,
        } if args.engine == "singlepath" else {
            "confidence": args.confidence,
            "retry": args.retry,
        },

        "inter": args.inter,
        "timeout": args.timeout,
        "abort": args.abort
    }



def resolve_hostnames(root):
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


def main():
    args = parse_arguments()
    logging.basicConfig(level=
        {
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
        traceroute = MultipathEngine(confidence=args.confidence, retry=args.retry, **cls_args)
    else:
        merge = False
        traceroute = SinglepathEngine(
            flow=args.flow, probes_per_hop=args.probes, **cls_args
        )

    traces = {}

    outgoing_ip = conf.route.route(target)[1]
    if args.direction == "two-way" or args.direction == "forward":
        probe_gen = ClassicTraceroute(target, proto)
        first_hop = outgoing_ip
        destination = target
        root = traceroute.discover(probe_gen, args.min_ttl, args.max_ttl, first_hop, destination)
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
            logging.error("The target did not respond to the reverse traceroute probe.")
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
        root = traceroute.discover(probe_gen, args.min_ttl, args.max_ttl, first_hop, destination)
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
            g.attr(style="filled", color="orange")
            g.node_attr.update(style="filled")
            g.attr(label=direction.upper())
            create_graph(g, trace, hostnames, merge) 

    parent.render(args.output, cleanup=True)

    if args.store_json:
        with open(f"{args.output}.json", "w") as writer:
            json.dump(measurement, writer, indent=4)

    if args.transmit:
        choice = input(
            "Due to the --transmit flag, your data will be uploaded to the HSA-Net group.\n"
            + "Do you want to proceed [Yes/No]: "
        )
        if choice.lower() == "yes":
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
