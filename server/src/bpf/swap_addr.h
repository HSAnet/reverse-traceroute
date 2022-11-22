/*
Copyright 2022 University of Applied Sciences Augsburg

This file is part of Augsburg-Traceroute.

Augsburg-Traceroute is free software: you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the Free
Software Foundation, either version 3 of the License, or (at your option) any
later version.

Augsburg-Traceroute is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
details.

You should have received a copy of the GNU General Public License along with
Augsburg-Traceroute. If not, see <https://www.gnu.org/licenses/>.
*/

#ifndef SWAP_ADDR_H
#define SWAP_ADDR_H

#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/types.h>

static void swap_addr_ethhdr(struct ethhdr *ethhdr)
{
    for (int i = 0; i < ETH_ALEN; i++) {
        __u8 byte = ethhdr->h_dest[i];
        ethhdr->h_dest[i] = ethhdr->h_source[i];
        ethhdr->h_source[i] = byte;
    }
}

static void swap_addr_iphdr(struct iphdr *iphdr)
{
    __be32 tmp_ip = iphdr->saddr;
    iphdr->saddr = iphdr->daddr;
    iphdr->daddr = tmp_ip;
}

static void swap_addr(struct ethhdr *eth, struct iphdr *ip)
{
    swap_addr_ethhdr(eth);
    swap_addr_iphdr(ip);
}

#endif
