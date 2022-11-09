#ifndef RESPONSE_H
#define RESPONSE_H

#include "internal.h"
#include "probe.h"
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>

struct response_args {
  struct session_key *session;
  struct session_state *state;
  probe_error error;
};

INTERNAL int response_create(struct cursor *cursor, struct response_args *args,
                             struct ethhdr **eth, struct iphdr **ip);

#endif
