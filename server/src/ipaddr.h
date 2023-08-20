#ifndef IPADDR_H
#define IPADDR_H

#if defined(TRACEROUTE_V4)
#include <linux/ip.h>
typedef __be32 ipaddr_t;
#elif defined(TRACEROUTE_V6)
#include <linux/ipv6.h>
typedef struct in6_addr ipaddr_t;
#else
#error "No address family defined. Specify TRACEROUTE_V4|TRACEROUTE_V6."
#endif

#endif
