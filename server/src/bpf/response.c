#include "response.h"
#include "csum.h"
#include "proto.h"
#include "resize.h"
#include "session.h"
#include "swap_addr.h"
#include <linux/icmp.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/types.h>
#include <bpf/bpf_endian.h>

static void response_init_eth_ip(struct ethhdr *eth, struct iphdr *ip,
                                 __be32 from, __be32 to) {
  swap_addr_ethhdr(eth);

  ip->saddr = from;
  ip->daddr = to;

  ip->protocol = IPPROTO_ICMP;
  ip->ttl = 64;
  ip->check = 0;
  ip->check = csum(ip, sizeof(*ip), 0);
}

static void response_init_icmp(struct session_key *session,
                               struct icmphdr *icmp, union trhdr *tr,
                               struct trhdr_payload *payload,
                               probe_error error) {
  icmp->type = 0;
  icmp->code = 1;
  icmp->un.echo.id = session->identifier;
  icmp->un.echo.sequence = 0;

  tr->response.state = error;
  tr->response.err_msg_len = 0;
  tr->response.reserved = 0;

  __u16 payload_len = sizeof(*icmp) + sizeof(*tr);
  if (payload)
    payload_len += sizeof(*payload);

  icmp->checksum = 0;
  icmp->checksum = csum(icmp, payload_len, 0);
}

INTERNAL int response_create_err(struct cursor *cursor,
                                 struct session_key *session, probe_error error,
                                 struct ethhdr **eth, struct iphdr **ip) {
  struct icmphdr *icmp;
  union trhdr *tr;

  __be32 dest_addr = session->addr;
  __be32 source_addr = (**ip).daddr;

  __u16 payload_len = sizeof(*icmp) + sizeof(*tr);

  if (resize_l3hdr(cursor, payload_len, eth, ip) < 0)
    return -1;

  if (PARSE(cursor, &icmp) < 0)
    return -1;
  if (PARSE(cursor, &tr) < 0)
    return -1;

  response_init_eth_ip(*eth, *ip, source_addr, dest_addr);
  response_init_icmp(session, icmp, tr, NULL, error);

  return 0;
}

INTERNAL int response_create(struct cursor *cursor, struct session_key *session,
                             struct session_state *state, struct ethhdr **eth,
                             struct iphdr **ip) {
  struct icmphdr *icmp;
  union trhdr *tr;
  struct trhdr_payload *payload;
  __u64 timespan_ns;

  __be32 dest_addr = session->addr;
  __be32 source_addr = (**ip).daddr;
  __be32 from_addr = (**ip).saddr;

  __u16 payload_len = sizeof(*icmp) + sizeof(*tr) + sizeof(*payload);

  if (resize_l3hdr(cursor, payload_len, eth, ip) < 0)
    return -1;

  if (PARSE(cursor, &icmp) < 0)
    return -1;
  if (PARSE(cursor, &tr) < 0)
    return -1;

  if (PARSE(cursor, &payload) < 0)
    return -1;

  // Set IPv4-mapped IPv6 address.
  for (int i = 0; i < 5; i++)
    payload->addr.in6_u.u6_addr16[i] = 0;

  payload->addr.in6_u.u6_addr16[5] = 0xffff;
  payload->addr.in6_u.u6_addr32[3] = from_addr;

  // Calculate timestamp.
  timespan_ns = cursor->skb->tstamp - state->timestamp_ns;
  payload->timespan_ns = bpf_htonl(timespan_ns);

  response_init_eth_ip(*eth, *ip, source_addr, dest_addr);
  response_init_icmp(session, icmp, tr, payload, 0);

  return 0;
}
