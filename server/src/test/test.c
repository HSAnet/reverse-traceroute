#include "utest.h"
#include "../cidr.h"

UTEST_MAIN();

UTEST(cidr, parse_cidr)
{
    struct str_to_res {
        char *str;
        int err;
        struct network res;
    };

    struct str_to_res cases[] = {
#if defined(TRACEROUTE_V4)
        { "0.0.0.0/0", 0, {0, 0}},
        { "192.168.178.0/24", 0, {htonl(0xc0a8b200), htonl(0xffffff00)}},
        { "192.168.178.1/32", 0, {htonl(0xc0a8b201), 0xffffffff}},
        { "192.168.178.1/24", -CIDR_ERR_HOSTBITS },
        { "192.168.178.1/-1", -CIDR_ERR_PREFIXLEN },
        { "192.168.178.1/33", -CIDR_ERR_PREFIXLEN },
        { "192.168.178.1/abc", -CIDR_ERR_PREFIX },
        { "192.168.178.1", -CIDR_ERR_FORMAT},
        { "192.168.178.1/32/32", -CIDR_ERR_FORMAT},
        { "::ff:ff:ff:ff/20", -CIDR_ERR_ADDRESS },
#elif defined(TRACEROUTE_V6)
        { "::/0", 0, {}}
#endif
        { NULL, 0}
    };

    struct network res;
    for (struct str_to_res *entry = cases; memcmp(entry, &(struct str_to_res){NULL, 0}, sizeof(*entry) != 0); entry++) {
        ASSERT_EQ(parse_cidr(AF_INET, entry->str, &res), entry->err);
        if (entry->err == 0) {
            ASSERT_EQ(entry->res.address, res.address);
            ASSERT_EQ(entry->res.netmask, res.netmask);
        }
    }
}
