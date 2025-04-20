#include "utest.h"
#include "../cidr.h"
#include "../netlist.h"
#include "net.h"
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
         memcmp(entry, &(struct str_to_res){NULL, 0}, sizeof(*entry)) != 0;
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

UTEST(net, net_contains)
{
    struct test_params {
        ipaddr_t dut;
        struct network container;
        int expected;
    };

    struct test_params cases[] = {
#if defined(TRACEROUTE_V4)
        {htonl(0xaabb0001), {0, 0}, 0},
        {htonl(0xaabb0001), {htonl(0xaa000000), htonl(0xff000000)}, 0},
        {htonl(0xaabb0001), {htonl(0xaabb0000), htonl(0xffff0000)}, 0},
        {htonl(0xaabb0001), {htonl(0xaabb0000), htonl(0xffffff00)}, 0},
        {htonl(0xaabb0001), {htonl(0xaabb0001), htonl(0xffffffff)}, 0},
        {htonl(0xa0bb0001), {htonl(0xaabb0001), htonl(0xffffffff)}, -1},
        {htonl(0xaabb0001), {htonl(0xaabb1000), htonl(0xfffff000)}, -1},
#elif defined(TRACEROUTE_V6)
        {.dut.s6_addr32 = {htonl(0xabcdef12)},
         {.address.s6_addr32 = {0}, .netmask.s6_addr32 = {0}},
         0},
        {.dut.s6_addr32 = {htonl(0xabcdef12)},
         {.address.s6_addr32 = {htonl(0xab000000)},
          .netmask.s6_addr32 = {htonl(0xff000000)}},
         0},
        {.dut.s6_addr32 = {htonl(0xabcdef12)},
         {.address.s6_addr32 = {htonl(0xabcd0000)},
          .netmask.s6_addr32 = {htonl(0xffff0000)}},
         0},
        {.dut.s6_addr32 = {htonl(0xabcdef12)},
         {.address.s6_addr32 = {htonl(0xabcdef00)},
          .netmask.s6_addr32 = {htonl(0xffffff00)}},
         0},
        {.dut.s6_addr32 = {htonl(0xabcdef12)},
         {.address.s6_addr32 = {htonl(0xabcdef00)},
          .netmask.s6_addr32 = {htonl(0xffffff00)}},
         0},
        {.dut.s6_addr32 = {htonl(0xabcdef12)},
         {.address.s6_addr32 = {htonl(0xabcdef12)},
          .netmask.s6_addr32 = {htonl(0xffffffff)}},
         0},
        {.dut.s6_addr32 = {htonl(0xabcdef10)},
         {.address.s6_addr32 = {htonl(0xabcdef12)},
          .netmask.s6_addr32 = {htonl(0xffffffff)}},
         -1},
        {.dut.s6_addr32 = {htonl(0xabcdef12)},
         {.address.s6_addr32 = {htonl(0xabcdef00)},
          .netmask.s6_addr32 = {htonl(0xfffffff0)}},
         -1},

        {.dut.s6_addr32 = {htonl(0xabcdef12)},
         {.address.s6_addr32 = {0}, .netmask.s6_addr32 = {0}},
         0},
        {.dut.s6_addr32 = {htonl(0xffbbaadd), htonl(0xabcdef12)},
         {.address.s6_addr32 = {htonl(0xffb00000)},
          .netmask.s6_addr32 = {htonl(0xfff00000)}},
         0},
        {.dut.s6_addr32 = {htonl(0xffbbaadd), htonl(0xabcdef12)},
         {.address.s6_addr32 = {htonl(0xffbbaadd), htonl(0xabcd0000)},
          .netmask.s6_addr32 = {htonl(0xffffffff), htonl(0xffff0000)}},
         0},
        {.dut.s6_addr32 = {htonl(0xffbbaadd), htonl(0xabcdef12)},
         {.address.s6_addr32 = {htonl(0xffbbaadd), htonl(0xabcd0000)},
          .netmask.s6_addr32 = {htonl(0xffffffff), htonl(0xffff0000)}},
         0},
        {.dut.s6_addr32 = {htonl(0xffbbaadd), htonl(0xabcdef12)},
         {.address.s6_addr32 = {htonl(0xffbbaad0), htonl(0xabcd0000)},
          .netmask.s6_addr32 = {htonl(0xffffffff), htonl(0xffff0000)}},
         -1},
        {.dut.s6_addr32 = {htonl(0xffbbaadd), htonl(0xabcdef12)},
         {.address.s6_addr32 = {htonl(0xffbbaadd), htonl(0xab0d0000)},
          .netmask.s6_addr32 = {htonl(0xffffffff), htonl(0xffff0000)}},
         -1},
        {.dut.s6_addr32 = {htonl(0xffbbaadd), htonl(0xabcdef12)},
         {.address.s6_addr32 = {htonl(0xffbbaadd), htonl(0xabcd0000)},
          .netmask.s6_addr32 = {htonl(0xffffffff), htonl(0xfffff000)}},
         -1},
#endif
        {0, 0, 0}
    };

    for (struct test_params *entry = cases;
         memcmp(entry, &(struct test_params){0, 0, 0}, sizeof(*entry)) != 0;
         entry++) {
        int ret = net_contains(&entry->container, &entry->dut);
        ASSERT_EQ(ret, entry->expected);
    }
}

static struct netlist list = NETLIST_INIT;

UTEST(netlist, netlist_push_back)
{
    for (int i = 1; i <= 10; i++) {
        struct network dummy = {};
        memset(&dummy, i, 1);

        netlist_push_back(&list, &dummy);
        ASSERT_EQ(list.len, i);
    }
}

UTEST(netlist, netlist_loop)
{
    int counter = 0;
    struct netlist_elem *elem;

    NETLIST_LOOP(&list, elem)
    {
        counter++;
        ASSERT_EQ(*(char *)elem, counter);
    }

    ASSERT_EQ(list.len, counter);
}

UTEST(netlist, netlist_pop_front)
{
    ASSERT_GT(list.len, 0);

    struct network out;

    int expected = 1;
    for (int i = list.len - 1; i >= 0; i--) {
        netlist_pop_front(&list, &out);
        ASSERT_EQ(list.len, i);
        ASSERT_EQ(*(char *)&out, expected++);
    }

    int is_reset = !memcmp(&list, &NETLIST_INIT, sizeof(list));
    ASSERT_TRUE(is_reset);
}
