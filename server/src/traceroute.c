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

#include "messages.h"
#include "traceroute.skel.h"
#include <arpa/inet.h>
#include <bpf/libbpf.h>
#include <getopt.h>
#include <linux/types.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <getopt.h>
#include <net/if.h>
#include <fcntl.h>

#if defined(TRACEROUTE_V4)
#define FILTER_HANDLE 0xbeaf4
#define ADDRSTRLEN    INET_ADDRSTRLEN
#define ADDR_FAMILY   AF_INET
#elif defined(TRACEROUTE_V6)
#define FILTER_HANDLE 0xbeaf6
#define ADDRSTRLEN    INET6_ADDRSTRLEN
#define ADDR_FAMILY   AF_INET6
#endif
#define FILTER_PRIO 1
struct args {
    int ifindex;            // Always specified by the user
    int indirect_enabled;   // Optional, 0 if not specified
    __u64 TIMEOUT_NS;       // Optional, 0 if not specified
    __u32 MAX_ELEM;         // Optional, 0 if not specified
};

const char *fmt_help_message =
    "Usage: %s [-t TIMEOUT_NS] [-n MAX_ENTRIES] [--indirect] ifname\n"
    "\t-t: The time after which a session expires, in nanoseconds.\n"
    "\t-n: The maximum number of sessions the server can handle.\n"
    "\t--indirect: Allow the client to specify the trace target.\n";

static int parse_args(int argc, char **argv, struct args *args)
{
    memset(args, 0, sizeof(*args));

    struct option long_opts[] = {
        {"indirect", no_argument, &args->indirect_enabled, 1},
        {0, 0, 0, 0}
    };

    char *endptr;
    int option_id, option_index = 0;
    while ((option_id = getopt_long(argc, argv, "t:n:h", long_opts, &option_index)) != -1) {
        switch (option_id) {
        // Long option encountered
        case 0:
            continue;
        case 't':
            args->TIMEOUT_NS = strtoull(optarg, &endptr, 0);
            if (*endptr != '\0') {
                fprintf(stderr, "Invalid number specified.\n");
                goto help;
            }
            break;
        case 'n':
            args->MAX_ELEM = strtoul(optarg, &endptr, 0);
            if (*endptr != '\0') {
                fprintf(stderr, "Invalid number specified.\n");
                goto help;
            }
            break;
        default:
            goto help;
        };
    }

    if (optind == argc - 1) {
        int index = if_nametoindex(argv[optind]);
        if (!index) {
            fprintf(stderr, "The specified interface does not exist!\n");
            return -1;
        }
        args->ifindex = index;
        return 0;
    } else if (optind == argc) {
        fprintf(stderr, "Required argument interface index is missing!\n");
    } else {
        fprintf(stderr, "Too many arguments specified!\n");
    }

help:
    fprintf(stderr, fmt_help_message, argv[0]);
    return -1;
}

static struct traceroute *traceroute_init(const struct args *args)
{
    struct rlimit mem_limit = {
        .rlim_cur = RLIM_INFINITY,
        .rlim_max = RLIM_INFINITY,
    };

    if (setrlimit(RLIMIT_MEMLOCK, &mem_limit) < 0)
        fprintf(stderr, "Failed to remove the memlock limit.\n");

    struct traceroute *traceroute = traceroute__open();

    if (!traceroute) {
        fprintf(stderr, "Failed to open the eBPF program.\n");
        goto err;
    }

    if (args->indirect_enabled)
        traceroute->rodata->INDIRECT_TRACE_ENABLED = 1;

    if (args->TIMEOUT_NS)
        traceroute->rodata->TIMEOUT_NS = args->TIMEOUT_NS;

    if (args->MAX_ELEM) {
        if (bpf_map__set_max_entries(traceroute->maps.map_sessions,
                                     args->MAX_ELEM) < 0) {
            fprintf(stderr, "Failed to set maximum number of elements to %u\n",
                    args->MAX_ELEM);
            goto cleanup;
        }
    }

    if (traceroute__load(traceroute) < 0) {
        fprintf(stderr, "Failed to load the program.\n");
        goto cleanup;
    }

    return traceroute;
cleanup:
    traceroute__destroy(traceroute);
err:
    return NULL;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
                           va_list args)
{
    return vfprintf(stderr, format, args);
}

static int log_message(void *ctx, void *data, size_t size)
{
    const struct message *msg = data;

    char address[ADDRSTRLEN];
    if (!inet_ntop(ADDR_FAMILY, &msg->data.address, address, sizeof(address)))
        return 0;

    printf("[%*s, %5u] | ", ADDRSTRLEN, address, msg->data.probe_id);
    switch (msg->type) {
    case SESSION_EXISTS:
        printf("session exists.\n");
        break;
    case SESSION_CREATED:
        printf("session created.\n");
        break;
    case SESSION_DELETED:
        printf("session deleted.\n");
        break;
    case SESSION_TIMEOUT:
        printf("session timed out.\n");
        break;
    case SESSION_BUFFER_FULL:
        printf("session buffer full.\n");
        break;
    case SESSION_PROBE_ANSWERED:
        printf("probe answer received.\n");
        break;
    }

    fflush(stdout);
    return 0;
}

static volatile bool exiting = false;

static void sig_handler(int signum)
{
    exiting = true;
}

int main(int argc, char **argv)
{
    int ret = EXIT_FAILURE;
    struct args args;
    struct traceroute *tr;
    struct ring_buffer *log_buf;

    if (parse_args(argc, argv, &args) < 0)
        goto exit;

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    /* Set up libbpf errors and debug info callback */
    libbpf_set_print(libbpf_print_fn);

    tr = traceroute_init(&args);
    if (!tr)
        goto exit;

    DECLARE_LIBBPF_OPTS(bpf_tc_hook, hook, .ifindex = args.ifindex,
                        .attach_point = BPF_TC_INGRESS);
    DECLARE_LIBBPF_OPTS(bpf_tc_opts, opts, .handle = FILTER_HANDLE,
                        .priority = FILTER_PRIO,
                        .prog_fd = bpf_program__fd(tr->progs.prog));

    bpf_tc_hook_create(&hook);
    if (bpf_tc_attach(&hook, &opts) < 0)
        goto destroy;

    fprintf(stderr, "\n\nSession timeout in nanoseconds: %llu\n",
            tr->rodata->TIMEOUT_NS);
    fprintf(stderr, "Maximum session entries: %u\n",
            bpf_map__max_entries(tr->maps.map_sessions));
    fprintf(stderr, "Indirect trace enabled: %s\n\n\n",
            tr->rodata->INDIRECT_TRACE_ENABLED ? "yes" : "no");

    log_buf = ring_buffer__new(bpf_map__fd(tr->maps.log_buf), log_message, NULL,
                               NULL);
    if (!log_buf) {
        fprintf(stderr, "Failed to create logging buffer.\n");
        goto detach;
    }

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    while (!exiting) {
        ret = ring_buffer__poll(log_buf, 100);
        if (ret == -EINTR) {
            break;
        } else if (ret < 0) {
            fprintf(stderr, "Failed to poll the logging buffer.\n");
            goto free;
        }
    }

    ret = EXIT_SUCCESS;
free:
    ring_buffer__free(log_buf);
detach:
    opts.flags = opts.prog_fd = opts.prog_id = 0;
    bpf_tc_detach(&hook, &opts);
destroy:
    traceroute__destroy(tr);
exit:
    return ret;
}
