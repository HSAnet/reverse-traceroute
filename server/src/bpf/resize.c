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
