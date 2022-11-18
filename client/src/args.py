"""Provides command line argument parsing functionality."""
import argparse


def parse_arguments() -> argparse.Namespace:
    """Parses the programs argument."""
    parser = argparse.ArgumentParser(
        description="A traceroute client able to trace in both the forward and reverse direction.",
        formatter_class=argparse.RawTextHelpFormatter,
    )

    probing_group = parser.add_argument_group("probing options")
    probing_group.add_argument(
        "--timeout",
        type=float,
        default=2,
        help="The maximum time to wait for probe response.",
    )
    probing_group.add_argument(
        "--inter",
        type=float,
        default=0.1,
        help="The time to wait between sending any two packets.",
    )
    probing_group.add_argument(
        "--abort",
        type=int,
        default=3,
        help="The number of successive black holes and/or vertices after which to abort.",
    )
    probing_group.add_argument(
        "--min-ttl", type=int, default=1, help="The TTL of the first hop to probe."
    )
    probing_group.add_argument(
        "--max-ttl", type=int, default=15, help="The TTL of the last hop to probe."
    )

    parser.add_argument(
        "-n",
        "--no-resolve",
        action="store_true",
        help="Do not perform a reverse DNS lookup on the IP addresses.",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=str,
        default="trace",
        help="The base name of the output files.",
    )
    parser.add_argument(
        "-l",
        "--log-level",
        choices=("debug", "info", "warning"),
        default="info",
    )

    stats_group = parser.add_argument_group("statistics")
    stats_group.add_argument(
        "-s",
        "--store-json",
        action="store_true",
        help="Store statistics as a json file.",
    )
    stats_group.add_argument(
        "--transmit",
        action="store_true",
        help="Submit the statistics to HSA-Net for their measurement study.",
    )

    direction_group = parser.add_argument_group("direction")
    parser.add_argument(
        "direction",
        choices=("two-way", "forward", "reverse"),
    )

    parser.add_argument(
        "protocol",
        choices=("tcp", "udp", "icmp"),
    )

    algo_parsers = parser.add_subparsers(dest="engine", required=True)
    multipath_parser = algo_parsers.add_parser(
        "multipath", help="Detect multiple paths."
    )
    multipath_parser.add_argument(
        "--retry",
        type=int,
        default=3,
        help="If positive: The maximum count of retransmissons for unresponsive probes.\n"
        + "If negative: The maximum count of successive unresponsive probe retransmissions.",
    )
    multipath_parser.add_argument(
        "--confidence",
        type=float,
        default=0.05,
        help="The probability of failing to detect all vertices for a hop."
    )
    multipath_parser.add_argument(
        "--no-merge",
        action="store_true",
        help="Do not merge the vertices before printing the graph.",
    )
    singlepath_parser = algo_parsers.add_parser(
        "singlepath", help="Illuminate a single path."
    )
    singlepath_parser.add_argument(
        "--flow",
        type=int,
        help="The flow to use in order to impact load-balancing.",
        required=True,
    )
    singlepath_parser.add_argument(
        "--probes",
        type=int,
        default=3,
        help="The number of probes to send for each hop.",
    )
    parser.add_argument(
        "target", type=str, help="The traceroute target to traceroute to/from."
    )

    args = parser.parse_args()
    return args
