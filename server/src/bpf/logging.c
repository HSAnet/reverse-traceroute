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

#include "logging.h"
#include "session.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <linux/types.h>
#include <linux/bpf.h>

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 128 * 1024);
} log_buf SEC(".maps");

INTERNAL void log_message(enum message_type type, const struct session_key *key)
{
    struct message *msg =
        bpf_ringbuf_reserve(&log_buf, sizeof(struct message), 0);

    if (!msg)
        return;

    msg->type = type;
    msg->data.probe_id = bpf_ntohs(key->identifier);
    msg->data.address = key->addr;

    bpf_ringbuf_submit(msg, 0);
}
