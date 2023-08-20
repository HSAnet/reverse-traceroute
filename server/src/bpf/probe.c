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
#include "config.h"
#include "csum.h"
#include "resize.h"
#include "tr_error.h"
#include "swap_addr.h"
#include <linux/bpf.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/if_ether.h>
#include <bpf/bpf_endian.h>

union tcp_payload {
    struct {
        __u8 kind;
        __u8 len;
        __u16 value;
    }  mss_option;
    __be32 data;
};


/*
 * Checks if the ICMP packet MAY be an answer to a probe.
 * In that case, the possible session identifier is returned.
 * Otherwise a negative value is returned.
 * If the is_request flag is set, the original l3 header is encapsulated
 * inside an ICMP error message, thus only the first eight bytes of the original
 * header are parsed.
 */
static int probe_match_icmp(struct cursor *cursor, __u8 is_request,
                            __u32 *const identifier)
{
    struct icmphdr *icmp;

    if (PARSE(cursor, &icmp) < 0)
        return -1;
    if (icmp->un.echo.sequence != ICMP_PROBE_SEQ)
        return -1;

    if (is_request) {
        if (icmp->type == G_ICMP_ECHO_REQUEST && icmp->code == 0)
            goto ok;
    } else {
        if (icmp->type == G_ICMP_ECHO_REPLY && icmp->code == 0)
            goto ok;
    }
    return -1;

ok:
    *identifier = icmp->un.echo.id;
    return 0;
}

/*
 * Checks if the UDP packet MAY be an answer to a probe.
 * In that case, the possible session identifier is returned.
 * Otherwise a negative value is returned.
 * If the is_request flag is set, the original l3 header is encapsulated
 * inside an ICMP error message, thus only the first eight bytes of the original
 * header are parsed.
 */
static int probe_match_udp(struct cursor *cursor, __u8 is_request,
                           __u32 *const identifier)
{
    struct udphdr *udp;
    if (PARSE(cursor, &udp) < 0)
        return -1;

    // We can only match a UDP header inside an ICMP error message
    // as the identifier is encoded into the checksum.
    // A direct response from the target will most likely alter the
    // checksum of the response and render the identifier useless.
    if (is_request && udp->source == SOURCE_PORT) {
        *identifier = udp->check;
        return 0;
    }
    return -1;
}

/*
 * Checks if the TCP packet MAY be an answer to a probe.
 * In that case, the possible session identifier is returned.
 * Otherwise a negative value is returned.
 * If the is_request flag is set, the original l3 header is encapsulated
 * inside an ICMP error message, thus only the first eight bytes of the original
 * header are parsed.
 */
static int probe_match_tcp(struct cursor *cursor, __u8 is_request,
                           __u32 *const identifier)
{
    struct tcphdr *tcp;

    if (is_request) {
        if (PARSE(cursor, (__be64 **)&tcp) < 0)
            return -1;

        if (tcp->source == SOURCE_PORT) {
            *identifier = bpf_htonl(tcp->seq);
            return 0;
        }   
    } else {
        if (PARSE(cursor, &tcp) < 0)
            return -1;
        if (tcp->dest != SOURCE_PORT)
            return -1;

        // Make sure the ACK flag is set, as only in that
        // case can we evaluate the ack-number, which contains our identifier.
        // We expect only SYN or RST packets, depending on whether the port was open.
        // Any other traffic can not created by traceroute probes.
        // In order to parse the packet, the ACK flag MUST be present, otherwise
        // the acknowledgement number carries no meaning.
        // We rely on the ack-number to carry back the original sequence
        if ((tcp->ack && tcp->rst) || (tcp->ack && CONFIG_TCP_SYN_ENABLED && tcp->syn)) {
            *identifier = bpf_ntohl(tcp->ack_seq);
            // An RST-ACK to a non-syn packet carries the previous sequence.
            // An ACK packet triggered by a SYN carries the incremented sequence.
            if (CONFIG_TCP_SYN_ENABLED) *identifier -= 1;
            else *identifier -= sizeof(union tcp_payload);
            return 0;
        }
    }
    return -1;
}

static tr_error probe_check_icmp(const struct probe *probe)
{
    return ERR_NONE;
}

static tr_error probe_check_udp(const struct probe *probe)
{
    return ERR_NONE;
}

static tr_error probe_check_tcp(const struct probe *probe)
{
    return ERR_NONE;
}

/*
 * Creates an ICMP probe packet with given probe arguments, e.g. flow and probe
 * identifier. Returns a negative value on failure, 0 on success and positive
 * values on an invalid configuration.
 */
static int probe_set_icmp(struct cursor *cursor, struct probe *probe,
                          struct ethhdr **eth, iphdr_t **ip)
{
    struct icmphdr *icmp;
    union {
        __be32 i32[2];
        __be16 i16[4];
    } * payload;

    const __u16 payload_len = sizeof(*icmp) + sizeof(*payload);

    if (resize_l3hdr(cursor, payload_len, eth, ip) < 0)
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

    __be32 seed = G_ICMP_PSEUDOHDR(**ip, payload_len);

    payload->i32[0] = bpf_get_prandom_u32();
    payload->i32[1] = bpf_get_prandom_u32();
    payload->i16[3] = 0;
    payload->i16[3] = csum(icmp, payload_len, seed);

    return 0;
}

/*
 * Creates a UDP probe packet with given probe arguments, e.g. flow and probe
 * identifier. Returns a negative value on failure, 0 on success and positive
 * values on an invalid configuration.
 */
static int probe_set_udp(struct cursor *cursor, struct probe *probe,
                         struct ethhdr **eth, iphdr_t **ip)
{
    struct udphdr *udp;
    __be32 pseudo_hdr;
    union {
        __be32 i32[2];
        __be16 i16[4];
    } * payload;

    const __u16 payload_len = sizeof(*udp) + sizeof(*payload);

    if (resize_l3hdr(cursor, payload_len, eth, ip) < 0)
        return -1;
    if (PARSE(cursor, &udp) < 0)
        return -1;
    if (PARSE(cursor, &payload) < 0)
        return -1;

    pseudo_hdr =
        pseudo_header(*ip, payload_len, IPPROTO_UDP);
    udp->dest = probe->flow ? probe->flow : bpf_htons(53);
    udp->source = SOURCE_PORT;
    udp->check = probe->identifier;
    udp->len = bpf_htons(payload_len);

    payload->i32[0] = bpf_get_prandom_u32();
    payload->i32[1] = bpf_get_prandom_u32();
    payload->i16[3] = 0;
    payload->i16[3] = csum(udp, payload_len, pseudo_hdr);

    return 0;
}

/*
 * Creates a TCP probe packet with given probe arguments, e.g. flow and probe
 * identifier. Returns a negative value on failure, 0 on success and positive
 * values on an invalid configuration.
 */
static int probe_set_tcp(struct cursor *cursor, struct probe *probe,
                         struct ethhdr **eth, iphdr_t **ip)
{
    struct tcphdr *tcp;
    __be32 pseudo_hdr;
    union tcp_payload *payload;

    const __u16 payload_len = sizeof(*tcp) + sizeof(*payload);

    if (resize_l3hdr(cursor, payload_len, eth, ip) < 0)
        return -1;
    if (PARSE(cursor, &tcp) < 0)
        return -1;
    if (PARSE(cursor, &payload) < 0)
        return -1;

    pseudo_hdr =
        pseudo_header(*ip, payload_len, IPPROTO_TCP);
    // Zero out tcp fields.
    *((__be32 *)tcp + 1) = 0;
    *((__be32 *)tcp + 2) = 0;
    *((__be32 *)tcp + 3) = 0;
    *((__be32 *)tcp + 4) = 0;

    tcp->dest = probe->flow ? probe->flow : bpf_htons(80);
    tcp->source = SOURCE_PORT;
    tcp->seq = bpf_htonl(probe->identifier);
    tcp->window = bpf_htons(1024);

    if (CONFIG_TCP_SYN_ENABLED) {
        tcp->syn = 1;
        tcp->doff = 6;
        payload->mss_option.kind = 2;
        payload->mss_option.len = 4;
        payload->mss_option.value = bpf_htons(1460);
    } else {
        tcp->doff = 5;
        payload->data = bpf_get_prandom_u32();
    }


    tcp->check = 0;
    tcp->check = csum(tcp, payload_len, pseudo_hdr);

    return 0;
}

static tr_error probe_check(const struct probe_args *args)
{
    if (args->ttl == 0)
        return ERR_TTL;

    switch (args->proto) {
    case G_PROTO_ICMP:
        return probe_check_icmp(&args->probe);
    case IPPROTO_UDP:
        return probe_check_udp(&args->probe);
    case IPPROTO_TCP:
        return probe_check_tcp(&args->probe);
    default:
        return ERR_PROTO;
    }

    return ERR_NONE;
}
/*
 * Attempts to match a packet as a possible probe response.
 * Returns a negative value on no match and a positive value for the possible
 * probe identifier.
 */
INTERNAL int probe_match(struct cursor *cursor, __u8 proto, __u8 is_request,
                         __u32 *const identifier)
{
    switch (proto) {
    case IPPROTO_TCP:
        return probe_match_tcp(cursor, is_request, identifier);
    case IPPROTO_UDP:
        return probe_match_udp(cursor, is_request, identifier);
    case G_PROTO_ICMP:
        return probe_match_icmp(cursor, is_request, identifier);
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
                          struct ethhdr **eth, iphdr_t **ip,
                          const ipaddr_t *target)
{
    int ret;
    struct probe *probe = &args->probe;

    // Set the default protocol if not specified (proto == 0).
    if (args->proto == 0)
        args->proto = G_PROTO_ICMP;

    if ((ret = probe_check(args)) != ERR_NONE)
        return ret;

    // Swap addresses.
    swap_addr(*eth, *ip, target);
    G_IP_NEXTHDR(**ip) = args->proto;
    G_IP_TTL(**ip) = args->ttl;

    switch (args->proto) {
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
        // Should already be handled by probe_check(...)
        return ERR_PROTO;
    }

    if (ret < 0)
        return ret;

    // Compute the checksum after setting the probe,
    // as the the packet is resized in the process (changing the ip->len field).
    G_IP_CSUM_COMPUTE(**ip);
    return 0;
}
