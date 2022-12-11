/*
Copyright 2022 University of Applied Sciences Augsburg

This file is part of Augsburg-Traceroute.

Augsburg-Traceroute is free software: you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the Free
Software Foundation, either version 3 of the License, or (at your option) any
later version.

Augsburg-Traceroute is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
details.

You should have received a copy of the GNU General Public License along with
Augsburg-Traceroute. If not, see <https://www.gnu.org/licenses/>.
*/

#include "response.h"
#include "csum.h"
#include "proto.h"
#include "resize.h"
#include "session.h"
#include "swap_addr.h"
#include <linux/icmpv6.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ipv6.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>


static __be32 pseudo_header(struct ipv6hdr *ip, __u16 probe_len, __u8 protocol)
{
    __be32 pseudo_hdr = bpf_htons(probe_len);

    for (int i = 0; i < 8; i++) {
        pseudo_hdr += ip->daddr.in6_u.u6_addr16[i];
        pseudo_hdr += ip->saddr.in6_u.u6_addr16[i];
    }
    pseudo_hdr += bpf_htons(protocol);

    return pseudo_hdr;
}
static void response_init_eth_ip(struct ethhdr *eth, struct ipv6hdr *ip,
                                 struct in6_addr from, struct in6_addr to)
{
    swap_addr_ethhdr(eth);

    ip->saddr = from;
    ip->daddr = to;

    ip->nexthdr = IPPROTO_ICMPV6;
    ip->hop_limit = 64;
}

static void response_init_icmp(struct session_key *session,
                               struct icmp6hdr *icmp, union trhdr *tr,
                               struct trhdr_payload *payload ,probe_error error)
{
    icmp->icmp6_type = ICMPV6_ECHO_REPLY;
    icmp->icmp6_code = 1;
    icmp->icmp6_dataun.u_echo.identifier = session->identifier;
    icmp->icmp6_dataun.u_echo.sequence = 0;

    tr->response.state = error;
    tr->response.err_msg_len = 0;
    tr->response.reserved = 0;

    __u16 payload_len = sizeof(*icmp) + sizeof(*tr);
    if (payload)
        payload_len += sizeof(*payload);

}

INTERNAL int response_create_err(struct cursor *cursor,
                                 struct session_key *session, probe_error error,
                                 struct ethhdr **eth, struct ipv6hdr **ip)
{
    struct icmp6hdr *icmp;
    union trhdr *tr;

    struct in6_addr dest_addr = session->addr;
    struct in6_addr source_addr = (**ip).daddr;

    __u16 payload_len = sizeof(*icmp) + sizeof(*tr);

    if (resize_l3hdr(cursor, payload_len, eth, ip) < 0)
        return -1;

    if (PARSE(cursor, &icmp) < 0)
        return -1;
    if (PARSE(cursor, &tr) < 0)
        return -1;

    response_init_eth_ip(*eth, *ip, source_addr, dest_addr);
    response_init_icmp(session, icmp, tr, NULL, error);

    icmp->icmp6_cksum = 0;
    icmp->icmp6_cksum = csum(icmp, payload_len, pseudo_header(*ip, payload_len, IPPROTO_ICMPV6));

    return 0;
}

INTERNAL int response_create(struct cursor *cursor, struct session_key *session,
                             struct session_state *state, struct ethhdr **eth,
                             struct ipv6hdr **ip)
{
    struct icmp6hdr *icmp;
    union trhdr *tr;
    struct trhdr_payload *payload;
    __u64 timespan_ns;

    struct in6_addr dest_addr = session->addr;
    struct in6_addr source_addr = (**ip).daddr;
    struct in6_addr from_addr = (**ip).saddr;

    __u16 payload_len = sizeof(*icmp) + sizeof(*tr) + sizeof(*payload);

    if (resize_l3hdr(cursor, payload_len, eth, ip) < 0)
        return -1;

    if (PARSE(cursor, &icmp) < 0)
        return -1;
    if (PARSE(cursor, &tr) < 0)
        return -1;

    if (PARSE(cursor, &payload) < 0)
        return -1;

    payload->addr = from_addr;

    // Calculate timestamp.
    timespan_ns = bpf_ktime_get_ns() - state->timestamp_ns;
    payload->timespan_ns = bpf_htonl(timespan_ns);

    response_init_eth_ip(*eth, *ip, source_addr, dest_addr);
    response_init_icmp(session, icmp, tr, payload, 0);

    icmp->icmp6_cksum = 0;
    icmp->icmp6_cksum = csum(icmp, payload_len, pseudo_header(*ip, payload_len, IPPROTO_ICMPV6));
    return 0;
}
