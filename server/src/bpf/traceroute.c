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

#include "logging.h"
#include "probe.h"
#include "proto.h"
#include "response.h"
#include "session.h"
#include "ip_generic.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/pkt_cls.h>

/*
 * Parses the reverse traceroute request header.
 * On a valid configuration state is created and a traceroute probe sent back to
 * the originator. Otherwise a response notifying the originator about the
 * invalid configuration is dispatched.
 */
static int handle_request(struct cursor *cursor, struct ethhdr **eth,
                          iphdr_t **ip, struct icmphdr **icmp)
{
    int err;
    union trhdr *tr;
    struct probe_args probe_args;

    struct session_key session = {.padding = 0};
    struct session_state state = {.timestamp_ns = bpf_ktime_get_ns()};

    if (PARSE(cursor, &tr) < 0)
        return TC_ACT_UNSPEC;

    session.addr = (*ip)->saddr;
    session.identifier = (*icmp)->un.echo.id;

    probe_args.ttl = tr->request.ttl;
    probe_args.proto = tr->request.proto;
    probe_args.probe.flow = tr->request.flow;
    probe_args.probe.identifier = (*icmp)->un.echo.id;

    if ((err = probe_create(cursor, &probe_args, eth, ip)) < 0)
        return TC_ACT_SHOT;

    if (err == ERR_NONE) {
        if (session_add(&session, &state) < 0)
            return TC_ACT_SHOT;
    } else {
        if (response_create_err(cursor, &session, err, eth, ip) < 0)
            return TC_ACT_SHOT;
    }

    return bpf_redirect(cursor->skb->ifindex, 0);
}

static int skb_copy_to_ingress(struct cursor *cursor, struct ethhdr **eth,
                               iphdr_t **ip)
{
    if (bpf_clone_redirect(cursor->skb, cursor->skb->ifindex, BPF_F_INGRESS) <
        0)
        return -1;

    cursor_reset(cursor);
    if (PARSE(cursor, eth) < 0)
        return -1;
    if (PARSE_IP(cursor, ip) < 0)
        return -1;

    return 0;
}

/*
 * Parses IPv4 packets and checks if the packet is either
 * a reverse traceroute request or an answer to a previously
 * sent traceroute probe.
 * In the latter case, an answer to the originator is created
 * and associated state cleaned up.
 */
static int handle(struct cursor *cursor)
{
    int ret;
    __u8 proto;
    __u8 is_request;

    struct session_key session = {.padding = 0};
    struct session_state *state;

    struct cursor l3_cursor;

    struct ethhdr *eth;
    iphdr_t *ip;

    if (PARSE(cursor, &eth) < 0)
        goto no_match;
    if (PARSE_IP(cursor, &ip) < 0)
        goto no_match;

    // Initialize variables to default values.
    // These will be overwritten if a nested ICMP-packet is received.
    is_request = 0;
    session.addr = ip->saddr;
    proto = IP_NEXTHDR(*ip);

    if (proto == G_PROTO_ICMP) {
        struct icmphdr *icmp;

        // Clone the cursor before parsing the ICMP-header.
        // It may be reset to this position later.
        cursor_clone(cursor, &l3_cursor);

        if (PARSE(cursor, &icmp) < 0)
            goto no_match;

        if (icmp->type == G_ICMP_ECHO_REQUEST && icmp->code == 1) {
            return handle_request(cursor, &eth, &ip, &icmp);
        } else if ((icmp->type == G_ICMP_TIME_EXCEEDED && icmp->code == 0) || icmp->type == G_ICMP_DEST_UNREACH) {
            iphdr_t *inner_ip;
            if ((ret = PARSE_IP(cursor, &inner_ip)) < 0)
                goto no_match;

            proto = IP_NEXTHDR(*inner_ip);
            session.addr = inner_ip->daddr;
            is_request = 1;
        } else {
            // Reset cursor in front of the ICMP header, so it can be properly
            // parsed.
            cursor = &l3_cursor;
        }
    }

    // Check if the packet could be an answer to a probe.
    if ((ret = probe_match(cursor, proto, is_request)) < 0)
        goto no_match;
    session.identifier = ret;

    state = session_find(&session);
    if (!state)
        goto no_match;

    log_message(SESSION_PROBE_ANSWERED, &session);
    session_delete(&session);

    // When a direct TCP response was received that matched a session entry,
    // just pass a copy to the ingress path of our associated interface after
    // deleting the session entry.
    // The next time the packet will be seen by this program it will
    // not find an associated session and pass it on to the kernel.
    // The kernel having never seen an associated packet will issue an RST.
    if (proto == IPPROTO_TCP && !is_request)
        if (skb_copy_to_ingress(cursor, &eth, &ip) < 0)
            goto exit;

    // Remove the session from our table and respond to the original requestor.
    // Note: It is safe to access map elements after a delete call as execution
    // takes places under an RCU read lock.
    // Data associated with the deleted map entry will be reclaimed after
    // program execution ends.
    ret = response_create(cursor, &session, state, &eth, &ip);
    if (ret < 0)
        goto exit;
    return bpf_redirect(cursor->skb->ifindex, 0);

// Jump here if packet has not been changed.
no_match:
    return TC_ACT_UNSPEC;
// Jump here if packet has been changed.
exit:
    return TC_ACT_SHOT;
}

/*
 * The entry point of the eBPF program.
 * Only handles IPv4 packets addressed to this host.
 */
SEC("tc")
int prog(struct __sk_buff *skb)
{
    if (skb->pkt_type != PACKET_HOST)
        return 0;

    struct cursor cursor;
    cursor_init(&cursor, skb);

    if (bpf_ntohs(skb->protocol) == G_ETH_P_IP)
        return handle(&cursor);

    return TC_ACT_UNSPEC;
}

char __license[] SEC("license") = "GPL";
