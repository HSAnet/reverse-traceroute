#include "logging.h"
#include "probe.h"
#include "proto.h"
#include "response.h"
#include "session.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>
#include <linux/icmp.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/pkt_cls.h>

/*
 * Parses the reverse traceroute request header.
 * On a valid configuration state is created and a traceroute probe sent back to
 * the originator. Otherwise a response notifying the originator about the
 * invalid configuration is dispatched.
 */
static int handle_request(struct cursor *cursor, struct ethhdr **eth,
                          struct iphdr **ip, struct icmphdr **icmp) {
  int err;
  union trhdr *tr;
  struct probe_args probe_args;

  struct session_key session = {.padding = 0};
  struct session_state state = {.timestamp_ns = cursor->skb->tstamp};

  if (PARSE(cursor, &tr) < 0)
    return TC_ACT_UNSPEC;

  session.addr = (*ip)->saddr;
  session.identifier = (*icmp)->un.echo.id;

  probe_args.ttl = tr->request.ttl;
  probe_args.proto = tr->request.proto ?: IPPROTO_ICMP;
  probe_args.probe.flow = tr->request.flow;
  probe_args.probe.identifier = (*icmp)->un.echo.id;

  if ((err = probe_create(cursor, &probe_args, eth, ip)) < 0)
    return TC_ACT_SHOT;

  if (err == ERR_NONE) {
    if (session_add(&session, &state) < 0)
      return TC_ACT_SHOT;
  } else {
    struct response_args resp_args = {
        .session = &session,
        .state = NULL,
        .error = err,
    };
    // Here we are in a probe error condition.
    if (response_create(cursor, &resp_args, eth, ip) < 0)
      return TC_ACT_SHOT;
  }

  return bpf_redirect(cursor->skb->ifindex, 0);
}

/*
 * Parses IPv4 packets and checks if the packet is either
 * a reverse traceroute request or an answer to a previously
 * sent traceroute probe.
 * In the latter case, an answer to the originator is created
 * and associated state cleaned up.
 */
static int handle(struct cursor *cursor) {
  int ret;
  __u8 proto;
  __u8 is_request;

  struct session_key session = {.padding = 0};
  struct session_state *state;

  struct cursor l3_cursor;

  struct ethhdr *eth;
  struct iphdr *ip;

  if (PARSE(cursor, &eth) < 0)
    goto no_match;
  if (PARSE(cursor, &ip) < 0)
    goto no_match;

  // Initialize variables to default values.
  // These will be overwritten if a nested ICMP-packet is received.
  is_request = 0;
  session.addr = ip->saddr;
  proto = ip->protocol;

  if (proto == IPPROTO_ICMP) {
    struct icmphdr *icmp;

    // Clone the cursor before parsing the ICMP-header.
    // It may be reset to this position later.
    cursor_clone(cursor, &l3_cursor);
    if (PARSE(cursor, &icmp) < 0)
      goto no_match;

    if (icmp->type == 8 && icmp->code == 1) {
      return handle_request(cursor, &eth, &ip, &icmp);
    } else if ((icmp->type == 11 && icmp->code == 0) || icmp->type == 3) {
      struct iphdr *inner_ip;
      if ((ret = PARSE(cursor, &inner_ip)) < 0)
        goto no_match;

      proto = inner_ip->protocol;
      session.addr = inner_ip->daddr;
      is_request = 1;
    } else {
      // Reset cursor in front of the ICMP header, so it can be properly parsed.
      cursor = &l3_cursor;
    }
  }

  // Check if the packet could be an answer to a probe.
  if ((ret = probe_match(cursor, proto, is_request)) < 0)
    goto no_match;
  session.identifier = ret;

  state = session_find(&session);
  if (!state)
    goto no_match;

  log_message(SESSION_PROBE_ANSWERED, &session);

  struct response_args args = {
      .session = &session,
      .state = state,
      .error = ERR_NONE,
  };

  // Remove the session from our table and respond to the original requestor.
  ret = response_create(cursor, &args, &eth, &ip);
  session_delete(&session);

  if (ret < 0)
    goto exit;
  return bpf_redirect(cursor->skb->ifindex, 0);

// Jump here if packet has not been changed.
no_match:
  return TC_ACT_UNSPEC;
// Jump here if packet has been changed.
exit:
  return TC_ACT_SHOT;
}

/*
 * The entry point of the eBPF program.
 * Only handles IPv4 packets addressed to this host.
 */
SEC("tc")
int prog(struct __sk_buff *skb) {
  if (skb->pkt_type != PACKET_HOST)
    return 0;

  struct cursor cursor;
  cursor_init(&cursor, skb);

  if (bpf_ntohs(skb->protocol) == ETH_P_IP)
    return handle(&cursor);

  return TC_ACT_UNSPEC;
}

char __license[] SEC("license") = "GPL";
