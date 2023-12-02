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

#include "session.h"
#include "config.h"
#include "logging.h"
#include <linux/bpf.h>
#include <time.h>
#include <bpf/bpf_helpers.h>
#include <asm-generic/errno-base.h>

// The internally used state consists of the usual state and a timer.
// The timer should not be exposed as part of the regular state.
struct __session_state {
    struct bpf_timer timer;
    struct session_state state;
};

// Dictionary of sessions and associated times.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, DEFAULT_MAX_ELEM);
    __type(key, struct session_key);
    __type(value, struct __session_state);
} sessions SEC(".maps");

// Contains currently usable session ids, at start
// populated by userspace.
struct {
    __uint(type, BPF_MAP_TYPE_QUEUE);
    __uint(max_entries, DEFAULT_MAX_ELEM);
    __type(value, __u16);
} session_ids SEC(".maps");

static int session_delete(const struct session_key *key) {
    if (bpf_map_delete_elem(&sessions, key) == 0) {
        session_return_id(key->identifier);
        log_message(SESSION_DELETED, key);
        return 0;
    }
    return -1;
}

static int session_timeout_callback(void *map, const struct session_key *key,
                                    struct __session_state *state)
{
    log_message(SESSION_TIMEOUT, key);
    session_delete(key);
    return 0;
}

static struct __session_state *__session_find(const struct session_key *key)
{
    return bpf_map_lookup_elem(&sessions, key);
}

INTERNAL struct session_state *session_find_delete(const struct session_key *key)
{
    struct __session_state *__state = __session_find(key);

    if (!__state || session_delete(key) < 0)
        return NULL;

    return &__state->state;
}

INTERNAL int session_add(const struct session_key *session,
                         const struct session_state *state)
{
    int ret;
    struct __session_state __state = {.state = *state}, *state_ptr;

    ret = bpf_map_update_elem(&sessions, session, &__state, BPF_NOEXIST);
    if (ret < 0) {
        // These conditions below will not be met as the pop operation
        // on the session_ids will return an error before we get here.
        // This code will become relevant once we return to a target-specific
        // ID mapping with bpf_loop.

        /*
        switch(-ret) {
            case EEXIST:
                // We get here in a race condition between session lookup and update
                // Return a code that indicates said condition, caller can then loop until a session is found.
                break;
            case E2BIG:
                log_message(SESSION_BUFFER_FULL, session);
                break;
        }
        */

        goto err;
    }

    state_ptr = __session_find(session);
    if (!state_ptr)
        goto err;

    if (bpf_timer_init(&state_ptr->timer, &sessions, CLOCK_MONOTONIC) < 0)
        goto err;
    if (bpf_timer_set_callback(&state_ptr->timer, session_timeout_callback) < 0)
        goto err;
    if (bpf_timer_start(&state_ptr->timer, CONFIG_TIMEOUT_NS, 0) < 0)
        goto err;

    log_message(SESSION_CREATED, session);
    return 0;

err:
    return -1;
}

INTERNAL int session_find_target_id(const ipaddr_t *target, __u16 *out_id)
{
    if (bpf_map_pop_elem(&session_ids, out_id) < 0) {
        struct session_key key = SESSION_NEW_KEY(*target, NONE_ID);
        log_message(SESSION_ID_POP, &key);
        return -1;
    }
    return 0;
}

INTERNAL void session_return_id(__u16 id)
{
    if (bpf_map_push_elem(&session_ids, &id, 0) < 0) {
        ipaddr_t addr = NONE_ADDR;
        struct session_key key = SESSION_NEW_KEY(addr, id);
        log_message(SESSION_ID_PUSH, &key);
    }
}