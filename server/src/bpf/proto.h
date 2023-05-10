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

#ifndef PROTO_H
#define PROTO_H

#include <linux/ipv6.h>
#include <linux/types.h>
#include <asm/byteorder.h>

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

struct icmp_multipart_hdr {
#if defined(__LITTLE_ENDIAN_BITFIELD)
    __u16 reserved : 12, version : 4;
#elif defined(__BIG_ENDIAN_BITFIELD)
    __u16 version : 4, reserved : 12;
#else
#error "Expected defines in <asm/byteorder.h>."
#endif

    __be16 checksum;
} __attribute__((packed));

struct icmp_multipart_extension {
    __be16 length;
    __u8 class_num;
    __u8 class_type;
} __attribute__((packed));

#endif
