#ifndef RESIZE_H
#define RESIZE_H

#include "cursor.h"
#include "internal.h"
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/types.h>

INTERNAL int resize_l3hdr(struct cursor *cursor, __u16 probe_len, struct ethhdr **eth, struct iphdr **ip);

#endif
