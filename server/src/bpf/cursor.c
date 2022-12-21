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

#include "cursor.h"
#include <linux/bpf.h>


INTERNAL long cursor_start(struct cursor *cursor)
{
    return cursor->skb->data;
}

INTERNAL long cursor_end(struct cursor *cursor)
{
    return cursor->skb->data_end;
}

INTERNAL void cursor_reset(struct cursor *cursor)
{
    cursor->pos = (void *)cursor_start(cursor);
}

INTERNAL void cursor_init(struct cursor *cursor, struct __sk_buff *skb)
{
    cursor->skb = skb;
    cursor_reset(cursor);
}

INTERNAL void cursor_clone(struct cursor *original, struct cursor *clone)
{
    *clone = *original;
}


INTERNAL int PARSE_IP(struct cursor *cursor, iphdr_t **hdr)
{
    if (PARSE(cursor, hdr) < 0)
        return -1;

#if defined(TRACEROUTE_V4)
    long new_pos = (long)(*hdr) + (**hdr).ihl * 4;
    if (new_pos <= cursor_end(cursor)) {
        cursor->pos = (void *)new_pos;
        return 0;
    }

    return -1;
#elif defined(TRACEROUTE_V6)
    return 0;
#endif
}
