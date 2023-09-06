#include "utest.h"
#include "../cidr.h"
#include "string.h"

#if defined(TRACEROUTE_V4)
#define AF AF_INET
#elif defined(TRACEROUTE_V6)
#define AF AF_INET6
#endif

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
        {"0.0.0.0/0", 0, {0, 0}},
        {"192.168.178.0/24", 0, {htonl(0xc0a8b200), htonl(0xffffff00)}},
        {"192.168.178.1/32", 0, {htonl(0xc0a8b201), 0xffffffff}},
        {"192.168.178.1/24", -CIDR_ERR_HOSTBITS},
        {"192.168.178.1/-1", -CIDR_ERR_PREFIXLEN},
        {"192.168.178.1/33", -CIDR_ERR_PREFIXLEN},
        {"192.168.178.1/abc", -CIDR_ERR_PREFIX},
        {"192.168.178.1", -CIDR_ERR_FORMAT},
        {"192.168.178.1/32/32", -CIDR_ERR_FORMAT},
        {"2001:0db8::/32", -CIDR_ERR_ADDRESS},
#elif defined(TRACEROUTE_V6)
        {"::/0",
         0,
         {.address.s6_addr32 = {0, 0, 0, 0},
          .netmask.s6_addr32 = {0, 0, 0, 0}}},
        {"2001:0db8:ac10:fe01::/64",
         0,
         {.address.s6_addr = {0x20, 0x01, 0x0d, 0xb8, 0xac, 0x10, 0xfe, 0x01},
          .netmask.s6_addr32 = {0xffffffff, 0xffffffff, 0, 0}}},
        {"2001:0db8::ac10:fe01/128",
         0,
         {.address.s6_addr = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0,
                              0xac, 0x10, 0xfe, 0x01},
          .netmask.s6_addr32 = {0xffffffff, 0xffffffff, 0xffffffff,
                                0xffffffff}}},
        {"2001:0db8:ac10:fe01::1/64", -CIDR_ERR_HOSTBITS},
        {"2001:0db8:ac10:fe01::1/-1", -CIDR_ERR_PREFIXLEN},
        {"2001:0db8:ac10:fe01::1/129", -CIDR_ERR_PREFIXLEN},
        {"2001:0db8:ac10:fe01::1/abc", -CIDR_ERR_PREFIX},
        {"2001:0db8:ac10:fe01::1", -CIDR_ERR_FORMAT},
        {"2001:0db8:ac10:fe01::1/128/128", -CIDR_ERR_FORMAT},
        {"192.168.178.0/24", -CIDR_ERR_ADDRESS},
#endif
        {NULL, 0}
    };

    struct network res;
    for (struct str_to_res *entry = cases;
         memcmp(entry, &(struct str_to_res){NULL, 0}, sizeof(*entry) != 0);
         entry++) {
        ASSERT_EQ(parse_cidr(AF, entry->str, &res), entry->err);
        if (entry->err == 0) {
            int addr_eq =
                !memcmp(&entry->res.address, &res.address, sizeof(ipaddr_t));
            ASSERT_TRUE(addr_eq);

            int mask_eq =
                !memcmp(&entry->res.netmask, &res.netmask, sizeof(ipaddr_t));
            ASSERT_TRUE(mask_eq);
        }
    }
}
