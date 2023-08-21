#include "../net.h"
#include "source.h"
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, net_index);
    __type(value, struct net_entry);
} allowed_sources SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, net_index);
    __type(value, struct net_entry);
} allowed_sources_multipart SEC(".maps");


struct match_context {
    ipaddr_t *addr;
    int match_found;
};

static int match_subnet(void *map, const void *key, const void *value, void *context)
{
    struct net_entry *entry = (struct net_entry *) value;
    struct match_context *ctx = (struct match_context *) context;

    __be32 *source_chunk = (__be32 *) ctx->addr;
    __be32 *netaddr_chunk = (__be32 *)&entry->address;
    __be32 *netmask_chunk = (__be32 *)&entry->netmask;

    ctx->match_found = 0;

    for (int i = 0; i < sizeof(ipaddr_t) / sizeof(__be32); i++) {
        if ((source_chunk[i] & netmask_chunk[i]) != netaddr_chunk[i])
            return 0;
    }

    ctx->match_found = 1;
    return 1;
}

static int match_subnet_in(void *map, const ipaddr_t *address)
{
    struct match_context ctx = {
        .addr = (ipaddr_t *)address,
    };
    // In case the allowed sources map is not updated by the loader only a single
    // entry exists, which is initialized to zero by default.
    // Thus, it is equivalent to the 0.0.0.0/0 network, which matches all addresses.
    bpf_for_each_map_elem(map, match_subnet, &ctx, 0);
    if (ctx.match_found)
        return 0;
    return -1;
}

INTERNAL int source_allowed(const ipaddr_t *address)
{
    return match_subnet_in(&allowed_sources, address);
}

INTERNAL int source_allowed_multipart(const ipaddr_t *address)
{
    return match_subnet_in(&allowed_sources_multipart, address);
}