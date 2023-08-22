#ifndef CIDR_H
#define CIDR_H

#include "ipaddr.h"
#include "net.h"
#include <linux/types.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>

#include <stdio.h>

enum cidr_parse_error {
    CIDR_ERR_FORMAT = 1,
    CIDR_ERR_PREFIX = 2,
    CIDR_ERR_PREFIXLEN = 3,
    CIDR_ERR_ADDRESS = 4,
    CIDR_ERR_HOSTBITS = 5,
};


static int parse_cidr(int addr_family, const char *str, struct net_entry *net)
{
    char *cidr = strdup(str);

    char *address_start = strtok(cidr, "/");
    char *prefixlen_start = strtok(NULL, "/");

    if (!prefixlen_start) {
        //PARSE_ERROR("expected a network in CIDR notation");
        free(cidr);
        return -CIDR_ERR_FORMAT;
    }

    char *endptr;
    unsigned long prefixlen = strtoul(prefixlen_start, &endptr, 0);
    if (*endptr != '\0' || endptr == prefixlen_start) {
        //PARSE_ERROR("invalid prefix length");
        free(cidr);
        return -CIDR_ERR_PREFIX;
    }

    if (prefixlen > sizeof(ipaddr_t) * 8) {
        free(cidr);
        return -CIDR_ERR_PREFIXLEN;
    }

    ipaddr_t address; 
    if (inet_pton(addr_family, address_start, &address) == 0) {
        free(cidr);
        return -CIDR_ERR_ADDRESS;
    }
    free(cidr);

    ipaddr_t netmask;
    for (int i = 0; i < sizeof(netmask); i++) {
        __u8 *netmask_bytes = (__u8 *)&netmask;
        __u8 *address_bytes = (__u8 *)&address;

        int nbits = (prefixlen < 8) ? prefixlen : 8;
        netmask_bytes[i] = (__u16)0xff << (8 - nbits);
        prefixlen -= nbits;

        if ((address_bytes[i] & netmask_bytes[i]) != address_bytes[i])
            return -CIDR_ERR_HOSTBITS;
    }

    net->address = address;
    net->netmask = netmask;
    return 0;
}

#endif