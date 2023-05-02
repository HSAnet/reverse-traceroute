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

#include "probe.h"
#include "cursor.h"
#include "csum.h"
#include "resize.h"
#include "swap_addr.h"
#include <linux/bpf.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/if_ether.h>
#include <bpf/bpf_endian.h>

/*
 * Checks if the ICMP packet MAY be an answer to a probe.
 * In that case, the possible session identifier is returned.
 * Otherwise a negative value is returned.
 * If the is_request flag is set, the original l3 header is encapsulated
 * inside an ICMP error message, thus only the first eight bytes of the original
 * header are parsed.
 */
static int probe_match_icmp(struct cursor *cursor, __u8 is_request)
{
    struct icmphdr *icmp;

    if (PARSE(cursor, &icmp) < 0)
        return -1;
    if (icmp->un.echo.sequence != ICMP_PROBE_SEQ)
        return -1;

    if (is_request) {
        if (!(icmp->type == G_ICMP_ECHO_REQUEST && icmp->code == 0))
            return -1;
    } else {
        if (!(icmp->type == G_ICMP_ECHO_REPLY && icmp->code == 0))
            return -1;
    }

    return icmp->un.echo.id;
}

/*
 * Checks if the UDP packet MAY be an answer to a probe.
 * In that case, the possible session identifier is returned.
 * Otherwise a negative value is returned.
 * If the is_request flag is set, the original l3 header is encapsulated
 * inside an ICMP error message, thus only the first eight bytes of the original
 * header are parsed.
 */
static int probe_match_udp(struct cursor *cursor, __u8 is_request)
{
    struct udphdr *udp;
    if (PARSE(cursor, &udp) < 0)
        return -1;

    // We can only match a UDP header inside an ICMP error message
    // as the identifier is encoded into the checksum.
    // A direct response from the target will most likely alter the
    // checksum of the response and render the identifier useless.
    if (is_request) {
        if (udp->source != SOURCE_PORT)
            return -1;
    } else
        return -1;

    return udp->check;
}

/*
 * Checks if the TCP packet MAY be an answer to a probe.
 * In that case, the possible session identifier is returned.
 * Otherwise a negative value is returned.
 * If the is_request flag is set, the original l3 header is encapsulated
 * inside an ICMP error message, thus only the first eight bytes of the original
 * header are parsed.
 */
static int probe_match_tcp(struct cursor *cursor, __u8 is_request)
{
    struct tcphdr *tcp;

    if (is_request) {
        if (PARSE(cursor, (__be64 **)&tcp) < 0)
            return -1;
        if (tcp->source != SOURCE_PORT)
            return -1;

        return bpf_htonl(tcp->seq);
    } else {
        if (PARSE(cursor, &tcp) < 0)
            return -1;
        if (tcp->dest != SOURCE_PORT)
            return -1;
        if (!tcp->rst && !(tcp->syn && tcp->ack))
            return -1;

        return bpf_ntohl(tcp->ack_seq) - 1;
    }
}

/*
 * Creates an ICMP probe packet with given probe arguments, e.g. flow and probe
 * identifier. Returns a negative value on failure, 0 on success and positive
 * values on an invalid configuration.
 */
static probe_error probe_set_icmp(struct cursor *cursor, struct probe *probe,
                                  struct ethhdr **eth, iphdr_t **ip)
{
    struct icmphdr *icmp;
    union {
        __be32 i32[2];
        __be16 i16[4];
    } *payload;

    if (resize_l3hdr(cursor, sizeof(*icmp) + sizeof(*payload), eth, ip) < 0)
        return -1;
    if (PARSE(cursor, &icmp) < 0)
        return -1;
    if (PARSE(cursor, &payload) < 0)
        return -1;

    icmp->type = G_ICMP_ECHO_REQUEST;
    icmp->code = 0;
    icmp->checksum = probe->flow ? probe->flow : bpf_htons(0xbeaf);
    icmp->un.echo.id = probe->identifier;
    icmp->un.echo.sequence = ICMP_PROBE_SEQ;

#if defined(TRACEROUTE_V4)
    __be32 seed = 0;
#elif defined(TRACEROUTE_V6)
    __be32 seed =
        pseudo_header(*ip, sizeof(*icmp) + sizeof(*payload), G_PROTO_ICMP);
#endif

    payload->i32[0] = bpf_get_prandom_u32();
    payload->i32[1] = bpf_get_prandom_u32();
    payload->i16[3] = 0;
    payload->i16[3] = csum(icmp, sizeof(*icmp) + sizeof(*payload), seed);

    return ERR_NONE;
}

/*
 * Creates a UDP probe packet with given probe arguments, e.g. flow and probe
 * identifier. Returns a negative value on failure, 0 on success and positive
 * values on an invalid configuration.
 */
static probe_error probe_set_udp(struct cursor *cursor, struct probe *probe,
                                 struct ethhdr **eth, iphdr_t **ip)
{
    struct udphdr *udp;
    __be32 pseudo_hdr;
    union {
        __be32 i32[2];
        __be16 i16[4];
    } *payload;

    if (resize_l3hdr(cursor, sizeof(*udp) + sizeof(*payload), eth, ip) < 0)
        return -1;
    if (PARSE(cursor, &udp) < 0)
        return -1;
    if (PARSE(cursor, &payload) < 0)
        return -1;

    pseudo_hdr =
        pseudo_header(*ip, sizeof(*udp) + sizeof(*payload), IPPROTO_UDP);
    udp->dest = probe->flow ? probe->flow : bpf_htons(53);
    udp->source = SOURCE_PORT;
    udp->check = probe->identifier;
    udp->len = bpf_htons(sizeof(*udp) + sizeof(*payload));

    payload->i32[0] = bpf_get_prandom_u32();
    payload->i32[1] = bpf_get_prandom_u32();
    payload->i16[3] = 0;
    payload->i16[3] = csum(udp, sizeof(*udp) + sizeof(*payload), pseudo_hdr);

    return ERR_NONE;
}

/*
 * Creates a TCP probe packet with given probe arguments, e.g. flow and probe
 * identifier. Returns a negative value on failure, 0 on success and positive
 * values on an invalid configuration.
 */
static probe_error probe_set_tcp(struct cursor *cursor, struct probe *probe,
                                 struct ethhdr **eth, iphdr_t **ip)
{
    struct tcphdr *tcp;
    struct {
        __u8 kind;
        __u8 len;
        __u16 value;
    } * mss_option;
    __be32 pseudo_hdr;

    if (resize_l3hdr(cursor, sizeof(*tcp) + sizeof(*mss_option), eth, ip) < 0)
        return -1;
    if (PARSE(cursor, &tcp) < 0)
        return -1;
    if (PARSE(cursor, &mss_option) < 0)
        return -1;

    pseudo_hdr =
        pseudo_header(*ip, sizeof(*tcp) + sizeof(*mss_option), IPPROTO_TCP);
    // Zero out tcp fields.
    *((__be32 *)tcp + 1) = 0;
    *((__be32 *)tcp + 2) = 0;
    *((__be32 *)tcp + 3) = 0;
    *((__be32 *)tcp + 4) = 0;

    tcp->dest = probe->flow ? probe->flow : bpf_htons(80);
    tcp->source = SOURCE_PORT;
    tcp->seq = bpf_htonl(probe->identifier);

    tcp->syn = 1;
    tcp->doff = 6;

    tcp->window = bpf_htons(1024);

    mss_option->kind = 2;
    mss_option->len = 4;
    mss_option->value = bpf_htons(1460);

    tcp->check = 0;
    tcp->check = csum(tcp, sizeof(*tcp) + sizeof(*mss_option), pseudo_hdr);

    return ERR_NONE;
}

/*
 * Attempts to match a packet as a possible probe response.
 * Returns a negative value on no match and a positive value for the possible
 * probe identifier.
 */
INTERNAL int probe_match(struct cursor *cursor, __u8 proto, __u8 is_request)
{
    switch (proto) {
    case IPPROTO_TCP:
        return probe_match_tcp(cursor, is_request);
    case IPPROTO_UDP:
        return probe_match_udp(cursor, is_request);
    case G_PROTO_ICMP:
        return probe_match_icmp(cursor, is_request);
    default:
        return -1;
    }
}

/*
 * Resizes the packet, creates the probe and adjusts the ip header to reflect
 * the changes. A negative value is returned on failure, 0 on success and a
 * positive value on an invalid probe configuration.
 */
INTERNAL int probe_create(struct cursor *cursor, struct probe_args *args,
                          struct ethhdr **eth, iphdr_t **ip)
{
    int ret;
    struct probe *probe = &args->probe;

    if (args->ttl == 0)
        return ERR_TTL;
    if (args->proto == 0)
        args->proto = G_PROTO_ICMP;

    switch (args->proto) {
    // In case of 0 we MUST use a suitable default value.
    case G_PROTO_ICMP:
        ret = probe_set_icmp(cursor, probe, eth, ip);
        break;
    case IPPROTO_UDP:
        ret = probe_set_udp(cursor, probe, eth, ip);
        break;
    case IPPROTO_TCP:
        ret = probe_set_tcp(cursor, probe, eth, ip);
        break;
    default:
        ret = ERR_PROTO;
    }

    if (ret != ERR_NONE)
        return ret;

#if defined(TRACEROUTE_V4)
    (**ip).protocol = args->proto;
    (**ip).ttl = args->ttl;
    (**ip).check = 0;
    (**ip).check = csum(*ip, sizeof(**ip), 0);
#elif defined(TRACEROUTE_V6)
    (**ip).nexthdr = args->proto;
    (**ip).hop_limit = args->ttl;
#endif
    // Swap addresses.
    swap_addr(*eth, *ip);

    // Packet is ready to be sent.
    return ERR_NONE;
}
