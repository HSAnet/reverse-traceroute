#include "response.h"
#include "csum.h"
#include "proto.h"
#include "resize.h"
#include "session.h"
#include "swap_addr.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <linux/icmp.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/types.h>

/*
 * Creates and sends a response to the originator.
 * If the session state is NULL, an invalid configuration was specified in a reverse traceroute request.
 * In that case a suitable error code is encoded in the response arguments.
 * If the session state is not NULL, a valid probe response was received.
 * In that case the error code signals SUCCESS.
 *
 * A negative value is returned on failure, 0 on success.
 */
INTERNAL int response_create(struct cursor *cursor, struct response_args *args, struct ethhdr **eth, struct iphdr **ip)
{
    struct icmphdr *icmp;
    union trhdr *tr;
    struct trhdr_payload *payload;
    __u64 timespan_ns;

    __be32 dest_addr = args->session->addr;
    __be32 source_addr = (**ip).daddr;
    __be32 from_addr = (**ip).saddr;

    __u16 payload_len = sizeof(*icmp) + sizeof(*tr);
    if (args->error == ERR_NONE && args->state)
        payload_len += sizeof(*payload);

    if (resize_l3hdr(cursor, payload_len, eth, ip) < 0)
        return -1;

    if (PARSE(cursor, &icmp) < 0)
        return -1;
    if (PARSE(cursor, &tr) < 0)
        return -1;

    if (args->error == ERR_NONE && args->state)
    {
        if (PARSE(cursor, &payload) < 0)
            return -1;

        // Set IPv4-mapped IPv6 address.
        for (int i = 0; i < 5; i++)
            payload->addr.in6_u.u6_addr16[i] = 0;

        payload->addr.in6_u.u6_addr16[5] = 0xffff;
        payload->addr.in6_u.u6_addr32[3] = from_addr;

        // Calculate timestamp.
        timespan_ns = cursor->skb->tstamp - args->state->timestamp_ns;
        payload->timespan_ns = bpf_htonl(timespan_ns);
    }

    swap_addr_ethhdr(*eth);

    (**ip).saddr = source_addr;
    (**ip).daddr = dest_addr;

    (**ip).protocol = IPPROTO_ICMP;
    (**ip).ttl = 64;
    (**ip).check = 0;
    (**ip).check = csum(*ip, sizeof(**ip), 0);

    icmp->type = 0;
    icmp->code = 1;
    icmp->un.echo.id = args->session->identifier;
    icmp->un.echo.sequence = 0;

    tr->response.state = args->error;
    tr->response.err_msg_len = 0;
    tr->response.reserved = 0;

    icmp->checksum = 0;
    icmp->checksum = csum(icmp, payload_len, 0);

    return 0;
}
