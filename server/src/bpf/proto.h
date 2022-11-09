#ifndef PROTO_H
#define PROTO_H

#include <linux/ipv6.h>
#include <linux/types.h>

union trhdr {
  struct {
    __u8 ttl;
    __u8 proto;
    __be16 flow;
  } request;
  struct {
    __u8 state;
    __u8 err_msg_len;
    __be16 reserved;
  } response;
} __attribute__((packed));

struct trhdr_payload {
  struct in6_addr addr;
  __u64 timespan_ns;
} __attribute__((packed));

#endif
