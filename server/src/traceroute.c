#include "traceroute.skel.h"
#include <bpf/libbpf.h>
#include <getopt.h>
#include <linux/types.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <unistd.h>

struct args
{
    int ifindex;      // Always specified by the user.
    __u64 TIMEOUT_NS; // 0 if not specified.
    __u32 MAX_ELEM;   // 0 if not specified.
};

const char *fmt_help_message = "Usage: %s [-t TIMEOUT_NS] [-n MAX_ENTRIES] if_index\n"
                               "\t-t: The time after which a session expires, in nanoseconds.\n"
                               "\t-n: The maximum number of sessions the server can handle.\n";

static int parse_args(int argc, char **argv, struct args *args)
{
    memset(args, 0, sizeof(*args));

    char *endptr;
    int option;
    while ((option = getopt(argc, argv, "t:n:h")) != -1)
    {
        switch (option)
        {
        case 't':
            args->TIMEOUT_NS = strtoull(optarg, &endptr, 0);
            if (*endptr != '\0')
            {
                fprintf(stderr, "Invalid number specified.\n");
                goto help;
            }
            break;
        case 'n':
            args->MAX_ELEM = strtoul(optarg, &endptr, 0);
            if (*endptr != '\0')
            {
                fprintf(stderr, "Invalid number specified.\n");
                goto help;
            }
            break;
        default:
            goto help;
        };
    }

    if (optind == argc - 1)
    {
        args->ifindex = atoi(argv[optind]);
        return 0;
    }
    else if (optind == argc)
    {
        fprintf(stderr, "Required argument interface index is missing!\n");
    }
    else
    {
        fprintf(stderr, "Too many arguments specified!\n");
    }

help:
    fprintf(stderr, fmt_help_message, argv[0]);
    return -1;
}

static int traceroute_init(struct traceroute **tr, struct args *args)
{
    struct traceroute *traceroute = traceroute__open();
    *tr = traceroute;

    if (!traceroute)
    {
        fprintf(stderr, "Failed to open the eBPF program.\n");
        return -1;
    }

    if (args->TIMEOUT_NS > 0)
    {
        traceroute->rodata->TIMEOUT_NS = args->TIMEOUT_NS;
        fprintf(stderr, "Setting user defined timeout value: ");
    }
    else
    {
        fprintf(stderr, "Defaulting to timeout value: ");
    }
    fprintf(stderr, "%llu\n", traceroute->rodata->TIMEOUT_NS);

    if (args->MAX_ELEM > 0)
    {
        if (bpf_map__set_max_entries(traceroute->maps.map_sessions, args->MAX_ELEM) < 0)
        {
            printf("Failed to set maximum number of elements to %u\n", args->MAX_ELEM);
            return -1;
        }
        printf("Setting user defined map size: ");
    }
    else
    {
        printf("Defaulting to map size: ");
    }
    printf("%u\n", bpf_map__max_entries(traceroute->maps.map_sessions));

    if (traceroute__load(traceroute) < 0)
    {
        printf("Failed to load the program.\n");
        return -1;
    }

    return 0;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    return level != LIBBPF_INFO ? vfprintf(stderr, format, args) : 0;
}

int main(int argc, char **argv)
{
    int ret;
    struct args args;
    struct traceroute *tr;
    sigset_t set;

    if (parse_args(argc, argv, &args) < 0)
        return -1;

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    /* Set up libbpf errors and debug info callback */
    libbpf_set_print(libbpf_print_fn);

    if (traceroute_init(&tr, &args) < 0)
    {
        if (tr)
            traceroute__destroy(tr);
        return -1;
    }

    DECLARE_LIBBPF_OPTS(bpf_tc_hook, hook, .ifindex = args.ifindex, .attach_point = BPF_TC_INGRESS);
    DECLARE_LIBBPF_OPTS(bpf_tc_opts, opts, .handle = 1, .priority = 1, .prog_fd = bpf_program__fd(tr->progs.prog));

    if (bpf_tc_hook_create(&hook) < 0)
        goto exit;
    if (bpf_tc_attach(&hook, &opts) < 0)
        goto destroy;

    sigemptyset(&set);
    sigaddset(&set, SIGINT);
    sigprocmask(SIG_BLOCK, &set, NULL);

    while (sigwait(&set, &ret))
        ;

    opts.flags = opts.prog_fd = opts.prog_id = 0;
    bpf_tc_detach(&hook, &opts);
destroy:
    hook.attach_point = BPF_TC_INGRESS | BPF_TC_EGRESS;
    bpf_tc_hook_destroy(&hook);
exit:
    traceroute__destroy(tr);
    return 0;
}
