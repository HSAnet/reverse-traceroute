#ifndef PROBE_H
#define PROBE_H

#include "cursor.h"
#include "internal.h"
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/types.h>

#define PAYLOAD_LEN 4
#define SOURCE_PORT bpf_htons(4420)

struct probe {
  __be16 flow;
  __be16 identifier;
};

struct probe_args {
  __u8 ttl;
  __u8 proto;

  struct probe probe;
};

typedef enum {
  ERR_NONE = 0x00,
  ERR_TTL = 0x01,
  ERR_PROTO = 0x02,
  ERR_FLOW = 0x03,
} probe_error;

INTERNAL int probe_create(struct cursor *cursor, struct probe_args *args,
                          struct ethhdr **eth, struct iphdr **ip);
INTERNAL int probe_match(struct cursor *cursor, __u8 proto, __u8 is_request);

#endif
