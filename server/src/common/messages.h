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

#ifndef MESSAGES_H
#define MESSAGES_H

#include <linux/ipv6.h>
#include <linux/types.h>
#include <sys/socket.h>

enum message_type {
    SESSION_EXISTS,
    SESSION_CREATED,
    SESSION_DELETED,
    SESSION_TIMEOUT,
    SESSION_BUFFER_FULL,
    SESSION_PROBE_ANSWERED,
};

struct message {
    enum message_type type;
    struct {
#if defined(TRACEROUTE_V4)
        __be32 address;
#elif defined(TRACEROUTE_V6)
        struct in6_addr address;
#endif
        __be32 probe_id;
    } data;
};

#endif
