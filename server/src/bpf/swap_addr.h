#ifndef SWAP_ADDR_H
#define SWAP_ADDR_H

#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/types.h>

static inline __attribute__((always_inline)) void
swap_addr_ethhdr(struct ethhdr *ethhdr) {
#pragma unroll
  for (int i = 0; i < ETH_ALEN; i++) {
    __u8 byte = ethhdr->h_dest[i];
    ethhdr->h_dest[i] = ethhdr->h_source[i];
    ethhdr->h_source[i] = byte;
  }
}

static void swap_addr_iphdr(struct iphdr *iphdr) {
  __be32 tmp_ip = iphdr->saddr;
  iphdr->saddr = iphdr->daddr;
  iphdr->daddr = tmp_ip;
}

static void swap_addr(struct ethhdr *eth, struct iphdr *ip) {
  swap_addr_ethhdr(eth);
  swap_addr_iphdr(ip);
}

#endif
