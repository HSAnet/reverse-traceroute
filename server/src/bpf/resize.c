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

#include "resize.h"
#include "cursor.h"
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

/*
 * Resizes the packet to be able to hold the specified length on top of the IP
 * header, all options are truncated.
 */
INTERNAL int resize_l3hdr(struct cursor *cursor, __u16 probe_len,
                          struct ethhdr **eth, iphdr_t **ip)
{
    int ret = bpf_skb_change_tail(cursor->skb,
                                  sizeof(**eth) + sizeof(**ip) + probe_len, 0);

    if (ret < 0)
        return -1;

    cursor_reset(cursor);
    if (PARSE(cursor, eth) < 0)
        return -1;
    if (PARSE(cursor, ip) < 0)
        return -1;

#if defined(TRACEROUTE_V4)
    (**ip).ihl = 5;
    (**ip).tot_len = bpf_htons(cursor->skb->len - sizeof(**eth));
#elif defined(TRACEROUTE_V6)
    (**ip).payload_len = bpf_htons(probe_len);
#endif

    return 0;
}
