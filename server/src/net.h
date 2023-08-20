#ifndef SOURCE_H
#define SOURCE_H

#include "ipaddr.h"
#include <linux/types.h>

typedef __u32 net_index;

struct net_entry {
    ipaddr_t address;
    ipaddr_t netmask;
};

#endif