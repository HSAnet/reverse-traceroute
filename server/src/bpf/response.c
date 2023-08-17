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
#include "cursor.h"
#include "csum.h"
#include "proto.h"
#include "resize.h"
#include "session.h"
#include "swap_addr.h"
#include "ip_generic.h"
#include <linux/types.h>
#include <linux/if_ether.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

static void response_init_eth_ip(struct ethhdr *eth, iphdr_t *ip, ipaddr_t from,
                                 ipaddr_t to)
{
    swap_addr_ethhdr(eth);

    ip->saddr = from;
    ip->daddr = to;

    G_IP_NEXTHDR(*ip) = G_PROTO_ICMP;
    G_IP_TTL(*ip) = 64;

    G_IP_CSUM_COMPUTE(*ip);
}

static void response_init_icmp(__u16 session_id,
                               struct icmphdr *icmp, union trhdr *tr,
                               tr_error error, __be16 value)
{
    icmp->type = G_ICMP_ECHO_REPLY;
    icmp->code = 1;
    icmp->un.echo.id = session_id;
    icmp->un.echo.sequence = 0;

    tr->response.state = error;
    tr->response.err_msg_len = 0;
    tr->response.reserved = value;
}

INTERNAL int response_create_err(struct cursor *cursor,
                                 struct response_args *args,
                                 struct response_err_args *err_args,
                                 struct ethhdr **eth, iphdr_t **ip)
{
    struct icmphdr *icmp;
    union trhdr *tr;

    const __u16 payload_len = sizeof(*icmp) + sizeof(*tr);
    if (resize_l3hdr(cursor, payload_len, eth, ip) < 0)
        return -1;

    if (PARSE(cursor, &icmp) < 0)
        return -1;
    if (PARSE(cursor, &tr) < 0)
        return -1;

    response_init_eth_ip(*eth, *ip, (**ip).daddr, args->origin);
    response_init_icmp(args->session_id, icmp, tr, err_args->error, err_args->value);

    icmp->checksum = 0;
    icmp->checksum = csum(icmp, payload_len, G_ICMP_PSEUDOHDR(**ip, payload_len));

    return 0;
}

INTERNAL int response_create(struct cursor *cursor,
                             struct response_args *args,
                             struct response_payload_args *payload_args,
                             struct ethhdr **eth, iphdr_t **ip)
{
    struct icmphdr *icmp;
    union trhdr *tr;
    struct trhdr_payload *payload;

    const __u16 payload_len = sizeof(*icmp) + sizeof(*tr) + sizeof(*payload);
    if (resize_l3hdr(cursor, payload_len, eth, ip) < 0)
        return -1;

    if (PARSE(cursor, &icmp) < 0)
        return -1;
    if (PARSE(cursor, &tr) < 0)
        return -1;

    if (PARSE(cursor, &payload) < 0)
        return -1;

    response_init_eth_ip(*eth, *ip, (**ip).daddr, args->origin);
    response_init_icmp(args->session_id, icmp, tr, 0, 0);

#if defined(TRACEROUTE_V4)
    for (int i = 0; i < 5; i++)
        payload->addr.in6_u.u6_addr16[i] = 0;

    payload->addr.in6_u.u6_addr16[5] = 0xffff;
    payload->addr.in6_u.u6_addr32[3] = payload_args->hop;
#elif defined(TRACEROUTE_V6)
    payload->addr = payload_args->hop;
#endif

    // Set the timestamp
    payload->timespan_ns = bpf_htonl(payload_args->timespan_ns);

    icmp->checksum = 0;
    icmp->checksum = csum(icmp, payload_len, G_ICMP_PSEUDOHDR(**ip, payload_len));

    return 0;
}
