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

#ifndef PROTO_H
#define PROTO_H

#include <linux/ipv6.h>
#include <linux/types.h>

union trhdr {
  struct {
    __u8 ttl;
    __u8 proto;
    __be16 flow;
  } request;
  struct {
    __u8 state;
    __u8 err_msg_len;
    __be16 reserved;
  } response;
} __attribute__((packed));

struct trhdr_payload {
  struct in6_addr addr;
  __u64 timespan_ns;
} __attribute__((packed));

#endif
