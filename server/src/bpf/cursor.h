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

#ifndef BPF_CURSOR_H
#define BPF_CURSOR_H

#include "ip_generic.h"
#include <linux/bpf.h>

struct cursor {
    struct __sk_buff *skb;
    void *pos;
};

#define PARSE(cursor, hdr)                                                     \
    ({                                                                         \
        int __ret = -1;                                                        \
        typeof(*(hdr)) __tmp = (cursor)->pos;                                  \
        if ((long)(cursor)->pos + sizeof(*__tmp) <= cursor_end(cursor)) {      \
            (cursor)->pos = __tmp + 1;                                         \
            *(hdr) = __tmp;                                                    \
            __ret = 0;                                                         \
        }                                                                      \
        __ret;                                                                 \
    })

static __inline long cursor_start(const struct cursor *cursor)
{
    return cursor->skb->data;
}

static __inline long cursor_end(const struct cursor *cursor)
{
    return cursor->skb->data_end;
}

static __inline void cursor_reset(struct cursor *cursor)
{
    cursor->pos = (void *)cursor_start(cursor);
}

static __inline void cursor_init(struct cursor *cursor, struct __sk_buff *skb)
{
    cursor->skb = skb;
    cursor_reset(cursor);
}

static __inline void cursor_clone(const struct cursor *original, struct cursor *clone)
{
    *clone = *original;
}

static __inline int PARSE_IP(struct cursor *cursor, iphdr_t **hdr, __u8 *const proto)
{
    if (PARSE(cursor, hdr) < 0)
        return -1;

#if defined(TRACEROUTE_V4)
    long new_pos = (long)(*hdr) + (**hdr).ihl * 4;
    if (new_pos > cursor_end(cursor))
        return -1;

    cursor->pos = (void *)new_pos;
    *proto = (**hdr).protocol;
    return 0;

#elif defined(TRACEROUTE_V6)
    struct ipv6_opt_hdr *ext_hdr;
    __u8 next_hdr = (**hdr).nexthdr;

    for (int i = 0; i < 10; i++) {
        switch (next_hdr) {
        case 0:
        case 43:
        case 44:
        case 51:
        case 50:
        case 60:
        case 135:
        case 139:
        case 140:
        case 253:
        case 254:
            if (PARSE(cursor, &ext_hdr) < 0)
                return -1;

            long new_pos = (long)(ext_hdr) + ((ext_hdr->hdrlen + 1) * 8);
            if (new_pos > cursor_end(cursor))
                return -1;

            cursor->pos = (void *)new_pos;
            next_hdr = ext_hdr->nexthdr;
            continue;
        default:
            break;
        }
    }

    *proto = next_hdr;
    return 0;
#endif
}

#endif
