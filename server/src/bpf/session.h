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

#ifndef SESSION_H
#define SESSION_H

#include "internal.h"
#include "ip_generic.h"
#include <linux/types.h>

struct session_key {
    ipaddr_t target;
    __be16 identifier;
    __u16 padding;
};

struct session_state {
    __u64 timestamp_ns;
    ipaddr_t origin;
#if defined(TRACEROUTE_V4)
    __u32 padding;
#endif
};


#define SESSION_NEW_KEY(x, y)                                                  \
    {                                                                          \
        .padding = 0, .target = (x), .identifier = (y)                           \
    }

#if defined(TRACEROUTE_V4)
#define SESSION_NEW_STATE(x, y)                                                \
    {                                                                          \
        .padding = 0, .timestamp_ns = (x), .origin = (y)                       \
    }
#elif defined(TRACEROUTE_V6)
#define SESSION_NEW_STATE(x, y)                                                \
    {                                                                          \
        .timestamp_ns = (x), .origin = (y)                                     \
    }
#endif

INTERNAL int session_delete(const struct session_key *session);
INTERNAL struct session_state *session_find(const struct session_key *key);
INTERNAL int session_add(const struct session_key *session,
                         const struct session_state *state);

#endif
