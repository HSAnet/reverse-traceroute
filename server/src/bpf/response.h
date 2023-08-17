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

#ifndef RESPONSE_H
#define RESPONSE_H

#include "internal.h"
#include "probe.h"
#include "session.h"
#include "ip_generic.h"
#include "tr_error.h"
#include <linux/if_ether.h>

struct response_args {
    __u16 session_id;
    ipaddr_t origin;
};

struct response_err_args {
    tr_error error;
    __be16 value;
    __be16 padding;
};

struct response_payload_args {
    ipaddr_t hop;
    __u64 timespan_ns;
};

INTERNAL int response_create_err(struct cursor *cursor,
                                 struct response_args *args,
                                 struct response_err_args *err_args,
                                 struct ethhdr **eth, iphdr_t **ip);

INTERNAL int response_create(struct cursor *cursor, struct response_args *args,
                             struct response_payload_args *payload_args,
                             struct ethhdr **eth, iphdr_t **ip);

#endif
