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

#include "csum.h"
#include <linux/types.h>
#include <bpf/bpf_endian.h>

INTERNAL __sum16 csum(const void *cursor, __u16 len, __be32 seed)
{
    __be32 sum = seed;
    const __be16 *pos = cursor;

    while (len > 1) {
        sum += *(pos++);
        len -= 2;
    }

    if (len > 0)
        sum += *pos;

    // Fold the recorded carry-outs back into the 16-bit sum.
    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);

    return (__sum16)~sum;
}

INTERNAL __be32 pseudo_header(const iphdr_t *ip, __u16 probe_len, __u8 protocol)
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
