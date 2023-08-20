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

#ifndef BPF_CSUM_H
#define BPF_CSUM_H

#include "internal.h"
#include "ip_generic.h"
#include <linux/types.h>

// Computes the checksum. See RFC1071 for details.
INTERNAL __sum16 csum(const void *cursor, __u16 len, __be32 seed);
INTERNAL __be32 pseudo_header(const iphdr_t *ip, __u16 probe_len,
                              __u8 protocol);

#endif
