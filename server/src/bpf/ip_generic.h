#ifndef BPF_IP_GENERIC_H
#define BPF_IP_GENERIC_H

#include "../ipaddr.h"
#include <linux/in.h>
#include <linux/icmp.h>
#include <linux/if_ether.h>

#if defined(TRACEROUTE_V4)
typedef struct iphdr iphdr_t;

#define G_ETH_P_IP             ETH_P_IP
#define G_PROTO_ICMP           IPPROTO_ICMP
#define G_ICMP_ECHO_REQUEST    ICMP_ECHO
#define G_ICMP_ECHO_REPLY      ICMP_ECHOREPLY
#define G_ICMP_TIME_EXCEEDED   ICMP_TIME_EXCEEDED
#define G_ICMP_DEST_UNREACH    ICMP_DEST_UNREACH

#define G_ICMP_PSEUDOHDR(x, y) 0

#define G_IP_NEXTHDR(x)        (x).protocol
#define G_IP_TTL(x)            (x).ttl

#define G_IP_CSUM_COMPUTE(x)                                                   \
    {                                                                          \
        (x).check = 0;                                                         \
        (x).check = csum(&(x), sizeof(x), 0);                                  \
    }

#elif defined(TRACEROUTE_V6)
typedef struct ipv6hdr iphdr_t;

#include <linux/icmpv6.h>
#define G_ETH_P_IP             ETH_P_IPV6
#define G_PROTO_ICMP           IPPROTO_ICMPV6
#define G_ICMP_ECHO_REQUEST    ICMPV6_ECHO_REQUEST
#define G_ICMP_ECHO_REPLY      ICMPV6_ECHO_REPLY
#define G_ICMP_TIME_EXCEEDED   ICMPV6_TIME_EXCEED
#define G_ICMP_DEST_UNREACH    ICMPV6_DEST_UNREACH

#define G_ICMP_PSEUDOHDR(x, y) pseudo_header(&(x), (y), G_PROTO_ICMP)

#define G_IP_NEXTHDR(x)        (x).nexthdr
#define G_IP_TTL(x)            (x).hop_limit

#define G_IP_CSUM_COMPUTE(x)                                                   \
    {                                                                          \
    }
#endif

#endif
