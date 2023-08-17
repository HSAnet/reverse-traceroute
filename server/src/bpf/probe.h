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

#ifndef PROBE_H
#define PROBE_H

#include "internal.h"
#include "ip_generic.h"
#include <linux/types.h>

struct cursor;
struct ethhdr;

#define SOURCE_PORT    bpf_htons(1021)
#define ICMP_PROBE_SEQ 0xffff

struct probe {
    __be16 flow;
    __be16 identifier;
};

struct probe_args {
    __u8 ttl;
    __u8 proto;

    struct probe probe;
};

INTERNAL int probe_create(struct cursor *cursor, struct probe_args *args,
                          struct ethhdr **eth, iphdr_t **ip,
                          const ipaddr_t *target);
INTERNAL int probe_match(struct cursor *cursor, __u8 proto, __u8 is_request,
                         __u32 *const identifier);

#endif
