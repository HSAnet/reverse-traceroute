/*
Copyright 2022 University of Applied Sciences Augsburg

This file is part of Augsburg-Traceroute.

Augsburg-Traceroute is free software: you can redistribute it and/or modify it under the terms
of the GNU General Public License as published by the Free Software Foundation,
either version 3 of the License, or (at your option) any later version.

Augsburg-Traceroute is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with Augsburg-Traceroute.
If not, see <https://www.gnu.org/licenses/>.
*/

#include "resize.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/types.h>

/*
 * Resizes the packet to be able to hold the specified length on top of the IPv4
 * header.
 */
INTERNAL int resize_l3hdr(struct cursor *cursor, __u16 probe_len,
                          struct ethhdr **eth, struct iphdr **ip) {
  int ret = bpf_skb_change_tail(cursor->skb,
                                sizeof(**eth) + sizeof(**ip) + probe_len, 0);

  if (ret < 0)
    return -1;

  cursor_reset(cursor);
  if (PARSE(cursor, eth) < 0)
    return -1;
  if (PARSE(cursor, ip) < 0)
    return -1;

  (**ip).tot_len = bpf_htons(cursor->skb->len - sizeof(**eth));

  return 0;
}
