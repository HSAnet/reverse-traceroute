#ifndef IP_GENERIC_H
#define IP_GENERIC_H

#include <linux/in.h>
#include <linux/icmp.h>
#include <linux/if_ether.h>

#if defined(TRACEROUTE_V4)

#include <linux/ip.h>
typedef struct iphdr iphdr_t;
typedef __be32 ipaddr_t;

#define G_ETH_P_IP              ETH_P_IP
#define G_PROTO_ICMP            IPPROTO_ICMP
#define G_ICMP_ECHO_REQUEST     ICMP_ECHO
#define G_ICMP_ECHO_REPLY       ICMP_ECHOREPLY
#define G_ICMP_TIME_EXCEEDED    ICMP_TIME_EXCEEDED
#define G_ICMP_DEST_UNREACH     ICMP_DEST_UNREACH

#define IP_NEXTHDR(x) (x).protocol

#elif defined(TRACEROUTE_V6)

#include <linux/ipv6.h>
typedef struct ipv6hdr iphdr_t;
typedef struct in6_addr ipaddr_t;

#include <linux/icmpv6.h>
#define G_ETH_P_IP              ETH_P_IPV6
#define G_PROTO_ICMP            IPPROTO_ICMPV6
#define G_ICMP_ECHO_REQUEST     ICMPV6_ECHO_REQUEST
#define G_ICMP_ECHO_REPLY       ICMPV6_ECHO_REPLY
#define G_ICMP_TIME_EXCEEDED    ICMPV6_TIME_EXCEED
#define G_ICMP_DEST_UNREACH     ICMPV6_DEST_UNREACH

#define IP_NEXTHDR(x) (x).nexthdr

#else
#error "No address family defined. Specify TRACEROUTE_V4|TRACEROUTE_V6."
#endif

#endif
