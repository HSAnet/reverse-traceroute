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

#include "cursor.h"
#include "config.h"
#include "logging.h"
#include "probe.h"
#include "proto.h"
#include "response.h"
#include "session.h"
#include "source.h"
#include "ip_generic.h"
#include "tr_error.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>
#include <linux/icmp.h>
#include <linux/if_packet.h>
#include <linux/pkt_cls.h>

typedef int tc_action;

static int parse_mp_hdr(struct cursor *cursor)
{
    struct icmp_ext_hdr *multipart_hdr;

    if (PARSE(cursor, &multipart_hdr) == 0 && multipart_hdr->version == 2)
        return 0;
    return -1;
}

/*
 * Parses the reverse traceroute request header.
 * On a valid configuration state is created and a traceroute probe sent back to
 * the originator. Otherwise a response notifying the originator about the
 * invalid configuration is dispatched.
 */
static tc_action handle_request(struct cursor *cursor, struct ethhdr **eth,
                                iphdr_t **ip, struct icmphdr **icmp)
{
    ipaddr_t origin = (**ip).saddr;
    if (source_allowed(&origin) < 0)
        return TC_ACT_SHOT;

    union trhdr *tr;
    if (PARSE(cursor, &tr) < 0)
        return TC_ACT_SHOT;

    // Set on error condition
    struct response_err_args err_args = {.padding = 0, .error = 0, .value = 0};
    __be16 session_id = (*icmp)->un.echo.id;
    ipaddr_t target = origin;

    if (parse_mp_hdr(cursor) == 0) {
        struct icmp_extobj_hdr *obj;
        if (PARSE(cursor, &obj) < 0)
            return TC_ACT_SHOT;

        if (CONFIG_INDIRECT_TRACE_ENABLED &&
            source_allowed_multipart(&origin) == 0 &&
            bpf_ntohs(obj->length) == 16 && obj->class_num == 5 &&
            obj->class_type == 0) {
            struct in6_addr *addr;
            if (PARSE(cursor, &addr) < 0)
                return TC_ACT_SHOT;

#if defined(TRACEROUTE_V4)
            target = addr->in6_u.u6_addr32[3];
#elif defined(TRACEROUTE_V6)
            target = *addr;
#endif
        } else {
            err_args.error = ERR_MULTIPART_NOT_SUPPORTED;
            err_args.value =
                bpf_htons((__u16)(obj->class_num) << 8 | obj->class_type);
            goto error;
        }
    }

    struct probe_args args = {
        .ttl = tr->request.ttl,
        .proto = tr->request.proto,
        .probe.flow = tr->request.flow,
        .probe.identifier = session_id,
    };

    if ((err_args.error = probe_create(cursor, &args, eth, ip, &target)) < 0)
        return TC_ACT_SHOT;

    if (err_args.error == ERR_NONE) {
        struct session_key session = SESSION_NEW_KEY(target, session_id);
        struct session_state state =
            SESSION_NEW_STATE(bpf_ktime_get_ns(), origin);
        if (session_add(&session, &state) < 0)
            return TC_ACT_SHOT;
        goto redirect;
    }

error:;
    struct response_args resp_args = {
        .session_id = session_id,
        .origin = origin,
    };
    if (response_create_err(cursor, &resp_args, &err_args, eth, ip) < 0)
        return TC_ACT_SHOT;
redirect:
    return bpf_redirect(cursor->skb->ifindex, 0);
}

static int skb_copy_to_ingress(struct cursor *cursor, struct ethhdr **eth,
                               iphdr_t **ip)
{
    __u8 dummy;

    if (bpf_clone_redirect(cursor->skb, cursor->skb->ifindex, BPF_F_INGRESS) <
        0)
        return -1;

    cursor_reset(cursor);
    if (PARSE(cursor, eth) < 0)
        return -1;
    if (PARSE_IP(cursor, ip, &dummy) < 0)
        return -1;

    return 0;
}

/*
 * Parses IP packets and checks if the packet is either
 * a reverse traceroute request or an answer to a previously
 * sent traceroute probe.
 * In the latter case, an answer to the originator is created
 * and associated state cleaned up.
 */
static tc_action handle(struct cursor *cursor)
{
    struct ethhdr *eth;
    iphdr_t *ip;
    __u8 proto;

    if (PARSE(cursor, &eth) < 0)
        goto pass;
    if (PARSE_IP(cursor, &ip, &proto) < 0)
        goto pass;

    // Initialize variables to default values.
    // These will be overwritten if a nested ICMP-packet is received.
    __u8 is_request = 0;
    ipaddr_t target = ip->saddr;

    if (proto == G_PROTO_ICMP) {
        struct icmphdr *icmp;

        // Clone the cursor before parsing the ICMP-header.
        // It may be reset to this position later.
        struct cursor l3_cursor;
        cursor_clone(cursor, &l3_cursor);

        if (PARSE(cursor, &icmp) < 0)
            goto pass;

        if (icmp->type == G_ICMP_ECHO_REQUEST && icmp->code == 1) {
            return handle_request(cursor, &eth, &ip, &icmp);
        } else if ((icmp->type == G_ICMP_TIME_EXCEEDED && icmp->code == 0) ||
                   icmp->type == G_ICMP_DEST_UNREACH) {
            iphdr_t *inner_ip;
            if (PARSE_IP(cursor, &inner_ip, &proto) < 0)
                goto pass;

            target = inner_ip->daddr;
            is_request = 1;
        } else {
            // Reset cursor in front of the ICMP header, so it can be properly
            // parsed.
            *cursor = l3_cursor;
        }
    }

    // Check if the packet could be an answer to a probe.
    __u32 identifier;
    if (probe_match(cursor, proto, is_request, &identifier) < 0)
        goto pass;

    struct session_key session = SESSION_NEW_KEY(target, identifier);
    struct session_state *state = session_find(&session);
    if (!state)
        goto drop;

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
            goto drop;

    struct response_args args = {
        .session_id = session.identifier,
        .origin = state->origin,
    };
    struct response_payload_args payload_args = {
        .timespan_ns = bpf_ktime_get_ns() - state->timestamp_ns,
        .hop = ip->saddr,
    };
    // Remove the session from our table and respond to the original requestor.
    // Note: It is safe to access map elements after a delete call as execution
    // takes places under an RCU read lock.
    // Data associated with the deleted map entry will be reclaimed after
    // program execution ends.
    if (response_create(cursor, &args, &payload_args, &eth, &ip) < 0)
        goto drop;
    return bpf_redirect(cursor->skb->ifindex, 0);

// Jump here to allow the packet to proceed.
pass:
    return TC_ACT_UNSPEC;
// Jump here to drop the packet.
drop:
    return TC_ACT_SHOT;
}

/*
 * The entry point of the eBPF program.
 * Only handles IP packets addressed to this host.
 */
SEC("tc")
tc_action prog(struct __sk_buff *skb)
{
    if (skb->pkt_type != PACKET_HOST)
        return TC_ACT_UNSPEC;

    struct cursor cursor;
    cursor_init(&cursor, skb);

    if (bpf_ntohs(skb->protocol) == G_ETH_P_IP)
        return handle(&cursor);

    return TC_ACT_UNSPEC;
}

char __license[] SEC("license") = "GPL";
