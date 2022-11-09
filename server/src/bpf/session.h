#ifndef SESSION_H
#define SESSION_H

#include "internal.h"
#include <linux/bpf.h>
#include <linux/types.h>

// IMPORTANT: These are the main configuration values for state maintenance.

struct session_key {
  __be32 addr;
  __u16 identifier;
  __u16 padding;
};

struct session_state {
  __u64 timestamp_ns;
};

INTERNAL int session_delete(struct session_key *session);
INTERNAL struct session_state *session_find(struct session_key *key);
INTERNAL int session_add(struct session_key *session,
                         struct session_state *state);

#endif
