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

#include "session.h"
#include "config.h"
#include "logging.h"
#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>
#include <time.h>

volatile const __u64 TIMEOUT_NS = DEFAULT_TIMEOUT_NS;

// The internally used state consists of the usual state and a timer.
// The timer should not be exposed as part of the regular state.
struct __session_state {
  struct session_state state;
  __u16 padding;
  struct bpf_timer timer;
};

// Dictionary of sessions and associated times.
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, DEFAULT_MAX_ELEM);
  __type(key, struct session_key);
  __type(value, struct __session_state);
} map_sessions SEC(".maps");

static int session_timeout_callback(void *map, struct session_key *key,
                                    struct __session_state *state) {
  log_message(SESSION_TIMEOUT, key);
  session_delete(key);
  return 0;
}

static struct __session_state *__session_find(struct session_key *key) {
  return bpf_map_lookup_elem(&map_sessions, key);
}

INTERNAL int session_delete(struct session_key *session) {
  log_message(SESSION_DELETED, session);
  return bpf_map_delete_elem(&map_sessions, session);
}

INTERNAL struct session_state *session_find(struct session_key *key) {
  struct __session_state *__state = __session_find(key);

  if (!__state)
    return NULL;
  return &__state->state;
}

INTERNAL int session_add(struct session_key *session,
                         struct session_state *state) {
  struct __session_state __state = {.state = *state, .padding = 0}, *state_ptr;

  state_ptr = __session_find(session);
  if (state_ptr)
    return -1;

  if (bpf_map_update_elem(&map_sessions, session, &__state, BPF_NOEXIST) == -1)
    return -1;

  state_ptr = __session_find(session);
  if (!state_ptr) {
    log_message(SESSION_BUFFER_FULL, session);
    return -1;
  }

  if (bpf_timer_init(&state_ptr->timer, &map_sessions, CLOCK_MONOTONIC) == -1)
    return -1;
  if (bpf_timer_set_callback(&state_ptr->timer, session_timeout_callback) == -1)
    return -1;
  if (bpf_timer_start(&state_ptr->timer, TIMEOUT_NS, 0) == -1)
    return -1;

  log_message(SESSION_CREATED, session);
  return 0;
}
