import argparse
import json
from .traceroute import *
from .miner import *
from .graph import *


def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Sends a reverse-traceroute request to a target"
    )
    parser.add_argument("target")
    parser.add_argument(
        "--timeout",
        type=float,
        default=2,
        help="The maximum time to wait for probe response.",
    )
    parser.add_argument(
        "--inter",
        type=float,
        default=0.1,
        help="The time to wait between sending any two packets.",
    )
    parser.add_argument(
        "--retry",
        type=int,
        default=3,
        help="The maximum number of times to send a probe if no answer was received.",
    )
    parser.add_argument(
        "--min-ttl", type=int, default=1, help="The TTL of the first hop to probe."
    )
    parser.add_argument(
        "--max-ttl", type=int, default=15, help="The TTL of the last hop to probe."
    )
    parser.add_argument(
        "--abort",
        type=int,
        default=3,
        help="The maximum number of unresponsive hops in a row, after which to abort.",
    )

    parser.add_argument(
        "-c",
        "--confidence",
        type=float,
        default=0.05,
        help="The confidence in discovering vertices. Must be between 0 and 1, smaller numbers signify a higher confidence.",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=str,
        default="trace",
        help="The base name of the output files, to which suffixes are appended.",
    )

    stats_group = parser.add_argument_group()
    stats_group.add_argument(
        "-s",
        "--statistics",
        action="store_true",
        help="Store statistics as json on the local file system.",
    )
    stats_group.add_argument(
        "-t",
        "--transmit",
        action="store_true",
        help="Submit the statistics to HSA-Net as test data.",
    )

    direction_group = parser.add_argument_group()
    direction_group.add_argument(
        "-r",
        "--reverse",
        action="store_true",
        help="Trace in the reverse direction. Requires the target to run the augsburg-traceroute server.",
    )
    direction_group.add_argument(
        "-f", "--forward", action="store_true", help="Trace in the forward direction."
    )

    protocol_group = parser.add_mutually_exclusive_group(required=False)
    protocol_group.add_argument("-I", "--icmp", action="store_true")
    protocol_group.add_argument("-U", "--udp", action="store_true")
    protocol_group.add_argument("-T", "--tcp", action="store_true")

    args = parser.parse_args()
    return args


def resolve_hostnames(root):
    def resolve(address):
        import socket

        try:
            return True, socket.gethostbyaddr(address)[0]
        except:
            return False, None

    resolve_table = {}
    nodes = set(v for v in root.flatten() if not isinstance(v, BlackHoleVertex))
    # Perform DNS lookup for IP addresses by concurrently calling
    # the resolve function.
    from concurrent.futures import ThreadPoolExecutor

    with ThreadPoolExecutor() as resolver:
        node_addresses = [node.address for node in nodes]
        hostnames = resolver.map(resolve, node_addresses)
        for node, (valid, hostname) in zip(nodes, hostnames):
            if valid:
                resolve_table[node] = hostname

    return resolve_table


def main():
    args = parse_arguments()
    if not args.forward and not args.reverse:
        print("You need to specify at least one trace direction [-r/-f].")
        exit()

    if args.icmp:
        proto = socket.IPPROTO_ICMP
    elif args.tcp:
        proto = socket.IPPROTO_TCP
    else:
        proto = socket.IPPROTO_UDP

    try:
        from ipaddress import IPv4Address

        target = str(IPv4Address(args.target))
    except:
        target = socket.gethostbyname(args.target)

    discover = lambda trace, first_hop, target: DiamondMiner(
        trace,
        args.inter,
        args.timeout,
        args.retry,
        args.abort,
    ).discover(args.confidence, first_hop, args.min_ttl, args.max_ttl, target)

    if args.transmit:
        measurement = {
            "confidence": args.confidence,
            "min_ttl": args.min_ttl,
            "protocol": proto,
            "inter": args.inter,
            "timeout": args.timeout,
            "retry": args.retry,
            "abort": args.abort,
            "target": target,
            "traces": {},
        }

    hostnames = {}
    node_str = lambda n: "\n".join((n.address, f"{n.rtt:.2f}", hostnames.get(n, "")))

    trace_args = (target, proto)

    if args.forward:
        root = discover(ClassicTraceroute(*trace_args), "127.0.0.1", target)
        hostnames.update(resolve_hostnames(root))

        if args.transmit:
            measurement["traces"]["forward"] = [x.to_dict() for x in root.flatten()]

        create_graph(root, node_str).render(args.output + "_fwd", cleanup=True)
    if args.reverse:
        from scapy.sendrecv import sr1

        trace = ReverseTraceroute(*trace_args)

        # Check for the presence of a reverse traceroute server
        req = trace.create_probe(0, 0)
        resp = sr1(req, retry=args.retry, timeout=args.timeout, verbose=0)
        if not resp:
            print("The target did not respond to the reverse traceroute probe.")
            exit()
        try:
            trace.parse_probe_response(req, resp)
        except ReverseTraceroute.InvalidTtlException:
            pass
        except Exception as e:
            print(e)
            exit()

        root = discover(ReverseTraceroute(*trace_args), target, None)
        hostnames.update(resolve_hostnames(root))

        if args.transmit:
            measurement["traces"]["reverse"] = [x.to_dict() for x in root.flatten()]

        create_graph(root, node_str).render(args.output + "_rev", cleanup=True)

    if args.transmit:
        measurement["hostnames"] = {k.address: v for k, v in hostnames.items()}
        print(json.dumps(measurement, indent=4))

        choice = input(
            "Due to the --transmit flag, your data will be uploaded to the HSA-Net group.\n"
            + "Do you want to proceed [Yes/No]: "
        )
        if choice.lower() == "yes":
            try:
                import requests

                requests.post(
                    "http://playground.net.hs-augsburg.de:9999/post_trace",
                    json=measurement,
                )
            except:
                print("Failed to submit measurement data!")
            else:
                print(
                    "Successfully transmitted your data! Thank you for contributing to our measurement study."
                )
