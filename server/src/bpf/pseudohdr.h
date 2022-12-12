#ifndef PSEUDOHDR_H
#define PSEUDOHDR_H

#include "ip_generic.h"
#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/*
 * Computes the pseudo header checksum for IPv4 based on the packet length and
 * protocol.
 */
static __be32 pseudo_header(iphdr_t *ip, __u16 probe_len, __u8 protocol)
{
    __be32 pseudo_hdr = bpf_htons(probe_len);

#if defined(TRACEROUTE_V4)
    pseudo_hdr += (__be16)(ip->saddr) + (__be16)(ip->saddr >> 16);
    pseudo_hdr += (__be16)(ip->daddr) + (__be16)(ip->daddr >> 16);
#elif defined(TRACEROUTE_V6)
    for (int i = 0; i < 8; i++) {
        pseudo_hdr += ip->daddr.in6_u.u6_addr16[i];    
        pseudo_hdr += ip->saddr.in6_u.u6_addr16[i];    
    }
#endif

    pseudo_hdr += bpf_htons(protocol);
    return pseudo_hdr;
}

#endif
