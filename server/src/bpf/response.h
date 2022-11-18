#ifndef RESPONSE_H
#define RESPONSE_H

#include "internal.h"
#include "probe.h"
#include "session.h"
#include <linux/if_ether.h>
#include <linux/ip.h>

INTERNAL int response_create_err(struct cursor *cursor,
                                 struct session_key *session, probe_error error,
                                 struct ethhdr **eth, struct iphdr **ip);
INTERNAL int response_create(struct cursor *cursor, struct session_key *session,
                             struct session_state *state, struct ethhdr **eth,
                             struct iphdr **ip);

#endif
