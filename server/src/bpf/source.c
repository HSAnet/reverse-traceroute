
#include "source.h"
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, ipaddr_t);
} map_allowed_sources SEC(".maps");


struct match_context {
    ipaddr_t *addr;
    int match_found;
};

static int match_subnet(void *map, const void *key, const void *value, void *context)
{
    __be32 *netmask = (__be32 *) key;
    struct match_context *ctx = (struct match_context *) context;
    __be32 *address = (__be32 *) ctx->addr;

    ctx->match_found = 0;

    for (int i = 0; i < sizeof(ipaddr_t) / sizeof(__be32); i++) {
        if (netmask[0] == 0)
            break;
        if ((netmask[0] & address[0]) != address[0])
            return 0;
    }

    ctx->match_found = 1;
    return 1;
}

INTERNAL int source_allowed(const ipaddr_t *address)
{
    struct match_context ctx = {
        .addr = (ipaddr_t *)address,
        .match_found = 0,
    };
    // In case the allowed sources map is not updated by the loader only a single
    // entry exists, which is initialized to zero by default.
    // Thus, it is equivalent to the 0.0.0.0/0 network, which matches all addresses.
    bpf_for_each_map_elem(&map_allowed_sources, match_subnet, &ctx, 0);
    if (ctx.match_found)
        return 0;
    return -1;
}