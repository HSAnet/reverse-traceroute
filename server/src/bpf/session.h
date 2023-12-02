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

#ifndef BPF_SESSION_H
#define BPF_SESSION_H

#include "internal.h"
#include "ip_generic.h"
#include <linux/types.h>

struct session_key {
    ipaddr_t target;
    __u16 identifier;
    __u16 padding;
};

struct session_state {
#if defined(TRACEROUTE_V4)
    __u64 timestamp_ns;
    ipaddr_t origin;
    __be16 local_identifier;
    struct {
        __u16 pad_1;
    } padding;
#elif defined(TRACEROUTE_V6)
    ipaddr_t origin;
    __u64 timestamp_ns;
    __be16 local_identifier;
    struct {
        __u16 pad_1;
        __u16 pad_2;
        __u16 pad_3;
    } padding;
#endif
};

#define SESSION_NEW_KEY(x, y)                                                  \
    {                                                                          \
        .padding = 0, .target = (x), .identifier = (y)                         \
    }

#define SESSION_NEW_STATE(x, y, z)                                             \
    {                                                                          \
        .padding = {0}, .timestamp_ns = (x), .origin = (y),                    \
        .local_identifier = (z)                                                \
    }

INTERNAL int session_find_target_id(const ipaddr_t *target, __u16 *out_id);
INTERNAL void session_return_id(__u16 id);
INTERNAL struct session_state *session_find_delete(const struct session_key *key);
INTERNAL int session_add(const struct session_key *session,
                         const struct session_state *state);

#endif