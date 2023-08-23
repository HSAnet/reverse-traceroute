#ifndef SOURCE_H
#define SOURCE_H

#include "ipaddr.h"
#include <linux/types.h>

typedef __u32 net_index;

struct network {
    ipaddr_t address;
    ipaddr_t netmask;
};


static inline int net_contains(struct network *net, ipaddr_t *addr) {
    __be32 *source_chunk = (__be32 *)addr;
    __be32 *netaddr_chunk = (__be32 *)&net->address;
    __be32 *netmask_chunk = (__be32 *)&net->netmask;

    for (int i = 0; i < sizeof(ipaddr_t) / sizeof(__be32); i++)
        if ((source_chunk[i] & netmask_chunk[i]) != netaddr_chunk[i])
            return -1;

    return 0;
}

#endif