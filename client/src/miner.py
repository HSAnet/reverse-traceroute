from scapy.sendrecv import sr
from itertools import groupby
import random
import math

from .container import TracerouteVertex, BlackHoleVertex, TracerouteHop
from .stats import probes_for_vertex


class DiamondMiner:
    """A hop-by-hop variation of the existing diamond miner algorithm."""
    def __init__(self, traceroute, inter, timeout, retry, abort):
        self.traceroute = traceroute
        self.inter = inter
        assert self.inter >= 0
        self.timeout = timeout
        assert self.timeout >= 0
        self.retry = retry
        self.abort = abort
        assert self.abort >= 0

    def _next_flow(self):
        """Generates a pseudo-random uniform flow identifier in the range
        between 10000 and 65535."""
        return int(random.uniform(10000, 65535))

    def _generate_flows(self, hop):
        """Generates flow identifiers to be used for the current hop.
        First all previously used identifiers are returned vertex by vertex.
        If they are exhausted, new identifiers are generated."""
        prev_flows = hop.flows
        yield from prev_flows
        while True:
            flow = self._next_flow()
            if flow not in prev_flows:
                prev_flows.add(flow)
                yield flow

    def _send_probes_to_hop(self, hop, flows):
        """Sends probes with a given ttl and flows."""
        ttl = hop.ttl

        unresp_counter = 0
        unresp_flows = set(flows)
        while unresp_flows:
            flow_list = list(unresp_flows)
            probes = [self.traceroute.create_probe(ttl, flow) for flow in flow_list]

            ans, unans = sr(
                probes, inter=self.inter, timeout=self.timeout#, verbose=0
            )

            for req, resp in ans:
                flow = flow_list[probes.index(req)]
                address, rtt = self.traceroute.parse_probe_response(req, resp)
                vertex = TracerouteVertex(address)
        
                if vertex not in hop:
                    hop.add(vertex)
                hop[vertex].update(flow, rtt)
                unresp_flows.discard(flow)

            if unresp_counter >= abs(self.retry):
                break

            if not ans and self.retry < 0:
                unresp_counter = 0
            else:
                unresp_counter += 1

    def _probe_and_update(self, hop, next_hop, flows):
        """Sends probes with a given ttl and flows and updates the vertices
        with relevant information, such as rtt and responding flows."""
        if len(hop) > 1:
            self._send_probes_to_hop(hop, flows - hop.flows)
        self._send_probes_to_hop(next_hop, flows)

        # We can connect the vertices forward if a single vertex
        # is present at the current hop.
        # Backwards is not possible because the vertex discovery may not yet be completed.
        if len(hop) == 1:
            vertex = hop.first()
            for next_vertex in next_hop:
                vertex.add_successor(next_vertex)
        else:
            for vertex in hop:
                for next_vertex in next_hop:
                    if vertex.flow_set & next_vertex.flow_set:
                        vertex.add_successor(next_vertex)

    def _nprobes(self, alpha, hop):
        """Computes the number of flows needed for the next hop depending
        on the certainty alpha and the current set of vertices."""
        probes = lambda v: probes_for_vertex(max(1, len(v.successors))+1, alpha)

        total_flows = len(hop.flows)
        max_probes = 0
        for vertex in hop:
            denominator = len(vertex.flow_set) / total_flows if vertex.flow_set else 1
            result = math.ceil(probes(vertex) / denominator)
            if result > max_probes:
                max_probes = result
        return max_probes

    def _merge_vertices(self, root):
        """Merges duplicate vertices encountered in a trace.
        Duplicates vertices can occur in the presence of Unequal Multipath-Load Balancing."""
        buckets = [list(g) for _, g in groupby(sorted(root.flatten(), key=hash))]

        for group in buckets:
            if len(group) < 2:
                continue

            joint_vertex = TracerouteVertex(group[0].address)
            print(f"Merging {group[0].address}")

            for vertex in group:
                for v in vertex.predecessors.copy():
                    vertex.del_predecessor(v)
                    joint_vertex.add_predecessor(v)
                for v in vertex.successors.copy():
                    vertex.del_successor(v)
                    joint_vertex.add_successor(v)

                for flow, rtt in zip(vertex.flow_set, vertex.rtt_list):
                    joint_vertex.update(flow, rtt)


    def discover(self, alpha, first_hop, min_ttl, max_ttl, target=None):
        assert alpha > 0 and alpha < 1
        assert min_ttl > 0 and max_ttl >= min_ttl

        root = TracerouteVertex(first_hop)
        addresses = lambda hop: set(v.address for v in hop)
        hop = TracerouteHop(0, [root])

        last_known_vertex = None

        unresponsive = 0
        for ttl in range(min_ttl, max_ttl + 1):
            print(f"Probing TTL {ttl}...")
            next_hop = TracerouteHop(ttl)
            iter_flows = self._generate_flows(hop)

            start = 0
            stop = self._nprobes(alpha, hop)
            while stop > start:
                flows = set(next(iter_flows) for _ in range(start, stop))
                self._probe_and_update(hop, next_hop, flows)

                # We assume that all probes received responses.
                # Should this not be the case, then possibly due to rate limiting.
                # In that case it does not make sense to send even more packets,
                # so we just have to work with the assumption that all probes were answered.
                start += len(flows)
                stop = self._nprobes(alpha, hop)

            if not next_hop:
                black_hole = BlackHoleVertex()
                next_hop.add(black_hole)
                # As a black hole does not contain a set of flow identifiers,
                # no connections could be made. Thus we manually reconnect
                # the predecessors to the black hole.
                for vertex in hop:
                    vertex.add_successor(black_hole)

            if len(next_hop) == 1:
                next_vertex = next_hop.first()
                if target and next_vertex.address == target:
                    break

                is_last_vertex = last_known_vertex and last_known_vertex == next_vertex
                is_black_hole = isinstance(next_vertex, BlackHoleVertex)

                if is_last_vertex or is_black_hole:
                    unresponsive += 1
                else:
                    unresponsive = 0

                if not (is_last_vertex or is_black_hole):
                    last_known_vertex = next_vertex
            else:
                last_known_vertex = None
                unresponsive = 0

            if unresponsive >= self.abort:
                break
            hop = next_hop

        if last_known_vertex is not None:
            for v in last_known_vertex.predecessors.copy():
                last_known_vertex.del_predecessor(v)

        self._merge_vertices(root)
        return root


