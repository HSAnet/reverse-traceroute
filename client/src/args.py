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

import argparse


def parse_arguments() -> argparse.Namespace:
    """Parses the programs argument."""
    parser = argparse.ArgumentParser(
        description="A traceroute client able to trace in both the forward and reverse direction.",
    )

    af_group = parser.add_mutually_exclusive_group()
    af_group.add_argument(
        "-4",
        "--ipv4",
        action="store_true",
        help="Resolve the target hostname to an IPv4 address",
    )
    af_group.add_argument(
        "-6",
        "--ipv6",
        action="store_true",
        help="Resolve the target hostname to an IPv6 address",
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
        "-y",
        "--assume-yes",
        action="store_true",
        help="Skip confirmation prompts and run the program in batch mode.",
    )
    parser.add_argument(
        "-n",
        "--no-resolve",
        action="store_true",
        help="Do not perform a reverse DNS lookup on the IP addresses.",
    )
    parser.add_argument(
        "--no-merge",
        action="store_true",
        help="Do not merge the vertices before printing the graph.",
    ),
    parser.add_argument(
        "--resolve-aliases",
        action="store_true",
        help="Resolve router level aliases.",
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
    parser.add_argument(
        "-f",
        "--format",
        choices=("dot", "gif", "jpg", "pdf", "png", "ps", "svg"),
        dest="format",
        default="pdf",
        help="output filetype",
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
        help="The maximum count of retransmissons for unresponsive probes.",
    )
    multipath_parser.add_argument(
        "--confidence",
        type=float,
        default=0.05,
        help="The probability of failing to detect all vertices for a hop.",
    )
    multipath_parser.add_argument(
        "--opt-single-vertex-hop",
        action="store_true",
        help="Do not send probes to a previous hop if it only contains a single vertex.",
    )
    multipath_parser.add_argument(
        "--min-burst",
        type=int,
        default=20,
        help="The minimum burst size to send to a hop.",
    )
    multipath_parser.add_argument(
        "--max-burst",
        type=int,
        default=500,
        help="The maximum burst size to send to a hop.",
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
