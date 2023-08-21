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

#include "ipaddr.h"
#include "messages.h"
#include "net.h"
#include "traceroute.skel.h"
#include <linux/types.h>
#include <arpa/inet.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <net/if.h>

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
    // Always specified by the user
    int ifindex;

    // Optional arguments, 0 if not specified
    int indirect_enabled;
    int indirect_disabled;

    int tcp_syn_enabled;
    int tcp_syn_disabled;

    __u64 timeout_ns;
    __u32 max_elem;

    char *sources_filename;
    char *indirect_sources_filename;
};

const char *fmt_help_message =
    "Usage: %s [-t TIMEOUT_NS] [-n MAX_ENTRIES] [--[no-]indirect]\n"
    "\t\t[--[no-]tcp-syn-probes] [--sources-from FILENAME]\n"
    "\t\t[--indirect-sources-from FILENAME] ifname\n"
    "\n"
    "\t-t: The time after which a session expires, in nanoseconds.\n"
    "\t-n: The maximum number of sessions the server can handle.\n"
    "\t--[no-]indirect: Whether or not the client is allowed to choose the "
    "trace target.\n"
    "\t--[no-]tcp-syn-probes: Whether or not TCP probes are sent with the SYN "
    "flag set.\n"
    "\t--sources-from: The filename that contains allowed networks in CIDR "
    "notation for traceroute requests\n"
    "\t--indirect-sources-from: The filename that contains allowed networks in "
    "CIDR notation for indirect traceroute requests\n";

static int parse_args(int argc, char **argv, struct args *args)
{
    memset(args, 0, sizeof(*args));

    struct option long_opts[] = {
        {"indirect", no_argument, &args->indirect_enabled, 1},
        {"no-indirect", no_argument, &args->indirect_disabled, 1},
        {"tcp-syn-probes", no_argument, &args->tcp_syn_enabled, 1},
        {"no-tcp-syn-probes", no_argument, &args->tcp_syn_disabled, 1},
        {"sources-from", required_argument, 0, 's'},
        {"indirect-sources-from", required_argument, 0, 'i'},
        {0, 0, 0, 0}};

    char *endptr;
    int option_id, option_index = 0;
    while ((option_id = getopt_long(argc, argv, "t:n:h", long_opts,
                                    &option_index)) != -1) {
        switch (option_id) {
        // Long option encountered
        case 0:
            continue;
        // Allowed sources filename
        case 's':
            args->sources_filename = strdup(optarg);
            break;
        // Allowed indirect sources filename
        case 'i':
            args->indirect_sources_filename = strdup(optarg);
            break;
        // Timeout
        case 't':
            args->timeout_ns = strtoull(optarg, &endptr, 0);
            if (*endptr != '\0' || args->timeout_ns == 0) {
                fprintf(stderr, "Invalid number specified.\n");
                goto help;
            }
            break;
        // Maximum session elements
        case 'n':
            args->max_elem = strtoul(optarg, &endptr, 0);
            if (*endptr != '\0') {
                fprintf(stderr, "Invalid number specified.\n");
                goto help;
            }
            break;
        default:
            goto help;
        };
    }

    if (args->indirect_disabled && args->indirect_enabled) {
        fprintf(stderr, "The '--indirect' and '--no-indirect' flags are "
                        "mutually exclusive!\n");
        goto help;
    }
    if (args->tcp_syn_disabled && args->tcp_syn_enabled) {
        fprintf(stderr, "The '--tcp-syn-probes' and '--no-tcp-syn-probes' "
                        "flags are mutually exclusive!\n");
        goto help;
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

struct list_elem {
    struct net_entry entry;
    struct list_elem *next;
};

static int create_netmask(const ipaddr_t address, __u8 prefixlen,
                          ipaddr_t *netmask)
{
    if (prefixlen > sizeof(ipaddr_t) * 8)
        return -2;

    const __u8 nchunks = sizeof(ipaddr_t) / sizeof(__be32);
    __be32 *addr_chunk = (__be32 *)&address;
    __be32 *mask_chunk = (__be32 *)netmask;

    int index = prefixlen / 32;
    int value = prefixlen % 32;

    mask_chunk[index] = htonl((__u64)0xffffffff << (32 - value));
    for (int i = 0; i < index; i++)
        mask_chunk[i] = 0xffffffff;
    for (int i = index + 1; i < nchunks; i++)
        mask_chunk[i] = 0;

    // Validate that no host bits are set for the network address
    for (int i = index; i < nchunks; i++)
        if ((addr_chunk[i] & mask_chunk[i]) != addr_chunk[i])
            return -1;

    return 0;
}

static ssize_t parse_networks(const char *sources_filename,
                              struct list_elem **head)
{
    struct list_elem *list_head = NULL;
    size_t list_len = 0, nentries = 0, nlines = 0;

    FILE *sources = fopen(sources_filename, "r");
    if (!sources) {
        fprintf(stderr, "Failed to open '%s'!\n", sources_filename);
        return 0;
    }
    fprintf(stderr, "Attempting to read network entries from '%s'\n",
            sources_filename);

    char *line = NULL;
    size_t line_size = 0;
    ssize_t nread;
    errno = 0;
    while ((nread = getline(&line, &line_size, sources)) > 0) {
        nlines += 1;
        // Replace newline with string-terminator
        ipaddr_t addr;
        line[nread - 1] = '\0';

        // Ignore empty lines and comments
        if (*line == '\0' || *line == '#')
            continue;

        nentries += 1;
        char *original_line = strdup(line);

#define PARSE_ERROR(error)                                                     \
    fprintf(stderr, "Line %ld: '%s': %s\n", nlines, original_line, (error))

        char *address_start = strtok(line, "/");
        char *prefixlen_start = strtok(NULL, "/");

        if (!prefixlen_start) {
            PARSE_ERROR("expected a network in CIDR notation");
            goto err_loop;
        }

        char *endptr;
        unsigned long prefixlen = strtoul(prefixlen_start, &endptr, 0);
        if (*endptr != '\0' || endptr == prefixlen_start) {
            PARSE_ERROR("invalid prefix length");
            goto err_loop;
        }

        if (inet_pton(ADDR_FAMILY, address_start, &addr) == 0) {
            PARSE_ERROR("invalid address format");
            goto err_loop;
        }

        ipaddr_t netmask;
        switch (create_netmask(addr, prefixlen, &netmask)) {
        case 0:
            break;
        case -1:
            PARSE_ERROR("host bits are set");
            goto err_loop;
        case -2:
            PARSE_ERROR("prefix length outside of bounds");
            goto err_loop;
        default:
            goto err_loop;
        }

        struct list_elem *new_elem = malloc(sizeof(*list_head));
        new_elem->entry.address = addr;
        new_elem->entry.netmask = netmask;
        new_elem->next = list_head;

        list_head = new_elem;
        list_len += 1;

    err_loop:
#undef PARSE_ERROR
        free(original_line);
    }
    fclose(sources);
    free(line);
    if (errno) {
        perror("getline: ");
        return 0;
    }

    if (nentries == 0) {
        fprintf(stderr, "No network entries found in '%s'\n", sources_filename);
        return 0;
    }
    if (list_len != nentries) {
        fprintf(stderr, "Errors encountered while parsing '%s'\n",
                sources_filename);
        return 0;
    }

    fprintf(stderr, "Loaded %ld network entries from '%s'\n", list_len,
            sources_filename);
    *head = list_head;
    return nentries;
}

static int update_networks(struct bpf_map *map, struct list_elem *list_head)
{
    net_index counter = 0;

    for (struct list_elem *elem = list_head; elem != NULL; elem = elem->next) {
        if (bpf_map__update_elem(map, &counter, sizeof(counter), &elem->entry,
                                 sizeof(elem->entry), 0) < 0)
            return -1;

        counter += 1;
    }
    return 0;
}

static void free_networks(struct list_elem *head)
{
    while (head) {
        struct list_elem *elem = head;
        head = head->next;
        free(elem);
    }
}

static struct traceroute *traceroute_init(const struct args *args)
{
    struct traceroute *traceroute = traceroute__open();

    if (!traceroute) {
        fprintf(stderr, "Failed to open the eBPF program!\n");
        return NULL;
    }

    if (args->indirect_enabled)
        traceroute->rodata->CONFIG_INDIRECT_TRACE_ENABLED = 1;
    else if (args->indirect_disabled)
        traceroute->rodata->CONFIG_INDIRECT_TRACE_ENABLED = 0;

    if (args->tcp_syn_enabled)
        traceroute->rodata->CONFIG_TCP_SYN_ENABLED = 1;
    else if (args->tcp_syn_disabled)
        traceroute->rodata->CONFIG_TCP_SYN_ENABLED = 0;

    if (args->timeout_ns)
        traceroute->rodata->CONFIG_TIMEOUT_NS = args->timeout_ns;

    if (args->max_elem) {
        if (bpf_map__set_max_entries(traceroute->maps.sessions,
                                     args->max_elem) < 0) {
            fprintf(stderr, "Failed to set maximum number of sessions to %u!\n",
                    args->max_elem);
            goto err;
        }
    }

    struct list_elem *sources = NULL;
    size_t sources_len;
    if (args->sources_filename) {
        sources_len = parse_networks(args->sources_filename, &sources);
        if (sources_len == 0)
            goto err;
        if (bpf_map__set_max_entries(traceroute->maps.allowed_sources,
                                     sources_len) < 0) {
            fprintf(
                stderr,
                "Failed to set maximum number of allowed networks to %zu!\n",
                sources_len);
            goto err;
        }
    }

    struct list_elem *indirect_sources = NULL;
    size_t indirect_sources_len;
    if (args->indirect_sources_filename) {
        if (traceroute->rodata->CONFIG_INDIRECT_TRACE_ENABLED) {
            indirect_sources_len = parse_networks(
                args->indirect_sources_filename, &indirect_sources);
            if (indirect_sources_len == 0)
                goto err;
            if (bpf_map__set_max_entries(
                    traceroute->maps.allowed_sources_multipart,
                    indirect_sources_len) < 0) {
                fprintf(stderr,
                        "Failed to set maximum number of allowed networks for "
                        "indirect requests to %zu!\n",
                        indirect_sources_len);
                goto err;
            }
        } else {
            fprintf(stderr, "Indirect tracing is disabled, ignoring the "
                            "'--indirect-sources-from' argument\n");
        }
    }

    if (traceroute__load(traceroute) < 0) {
        fprintf(stderr, "Failed to load the program!\n");
        goto err;
    }

    if (sources) {
        if (update_networks(traceroute->maps.allowed_sources, sources) < 0)
            goto err;
        free_networks(sources);
    }
    if (indirect_sources) {
        if (update_networks(traceroute->maps.allowed_sources_multipart,
                            indirect_sources) < 0)
            goto err;
        free_networks(indirect_sources);
    }

    return traceroute;
err:
    traceroute__destroy(traceroute);
    return NULL;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
                           va_list args)
{
    if (level == LIBBPF_WARN || level == LIBBPF_INFO)
        return vfprintf(stderr, format, args);
    return 0;
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
            tr->rodata->CONFIG_TIMEOUT_NS);
    fprintf(stderr, "Maximum session entries: %u\n",
            bpf_map__max_entries(tr->maps.sessions));
    fprintf(stderr, "Indirect trace enabled: %s\n",
            tr->rodata->CONFIG_INDIRECT_TRACE_ENABLED ? "yes" : "no");
    fprintf(stderr, "TCP SYN probes enabled: %s\n\n\n",
            tr->rodata->CONFIG_TCP_SYN_ENABLED ? "yes" : "no");

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
