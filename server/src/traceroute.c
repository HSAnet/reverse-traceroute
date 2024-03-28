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

#include "cidr.h"
#include "ipaddr.h"
#include "netlist.h"
#include "messages.h"
#include "net.h"
#include "traceroute.skel.h"
#include <linux/types.h>
#include <arpa/inet.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
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
#define AF_STR        "v4"
#elif defined(TRACEROUTE_V6)
#define FILTER_HANDLE 0xbeaf6
#define ADDRSTRLEN    INET6_ADDRSTRLEN
#define ADDR_FAMILY   AF_INET6
#define AF_STR        "v6"
#endif

#define SECONDS_TO_NS 1E9

#define FILTER_PRIO   1

struct args {
    // Always specified by the user
    int ifindex;

    // Defaults to config file in /etc
    char *sources_filename;
    char *indirect_sources_filename;

    // Optional arguments
    int indirect_set;
    int indirect_enabled;

    int tcp_syn_set;
    int tcp_syn_enabled;

    // 0 if not specified
    unsigned long timeout_ns;
    unsigned long max_elem;
};

const char *fmt_help_message =
    "Usage: %s [-t TIMEOUT] [-n MAX_ENTRIES]\n"
    "\t\t[--indirect=yes|no] [--tcp-syn-probes=yes|no]\n"
    "\t\t[--allow-from=filepath] [--allow-indirect-from=filepath]\n"
    "\n"
    "\t-t: The time after which a session expires, in seconds.\n"
    "\t-n: The maximum number of sessions the server can handle.\n"
    "\t--indirect: Whether or not the client is allowed to choose the "
    "trace target.\n"
    "\t--tcp-syn-probes: Whether or not TCP probes are sent with the SYN "
    "flag set.\n"
    "\t--allow-from: The path to a file containing IP networks that are "
    "allowed to request reverse-traceroute measurements.\n"
    "\t--allow-indirect-from: The path to a file containing IP networks that "
    "are allowed to set the reverse-traceroute target.\n"
    "\t\tOnly effective when used together with the --indirect flag.\n";

static void free_args(struct args *args)
{
    if (args->sources_filename)
        free(args->sources_filename);
    if (args->indirect_sources_filename)
        free(args->indirect_sources_filename);
}

static int parse_args(int argc, char **argv, struct args *args)
{
    memset(args, 0, sizeof(*args));

    struct option long_opts[] = {
        {"indirect", required_argument, &args->indirect_set, 1},
        {"tcp-syn-probes", required_argument, &args->tcp_syn_set, 1},

        {"allow-from", required_argument, 0, 's'},
        {"allow-indirect-from", required_argument, 0, 'i'},
        {0, 0, 0, 0}};

    char *endptr;
    int option_id, option_index = 0;
    errno = 0;

    while ((option_id = getopt_long(argc, argv, "t:n:h", long_opts,
                                    &option_index)) != -1) {
        switch (option_id) {
        // Long option encountered
        case 0:;
            int is_set;

            if (strcmp(optarg, "yes") == 0) {
                is_set = 1;
            } else if (strcmp(optarg, "no") == 0) {
                is_set = 0;
            } else {
                fprintf(stderr,
                        "Option '%s' expects 'yes|no' as the argument.\n",
                        long_opts[option_index].name);
                goto help;
            }

            switch (option_index) {
            case 0:
                args->indirect_enabled = is_set;
                break;
            case 1:
                args->tcp_syn_enabled = is_set;
                break;
            default:
                fprintf(stderr, "Unhandled option '%s'.\n",
                        long_opts[option_index].name);
                goto help;
            }

            break;
        // Allowed indirect sources filename
        case 's':
            // Close memleak when invoking this argument multiple times
            if (args->sources_filename)
                free(args->sources_filename);
            args->sources_filename = strdup(optarg);
            break;
        // Allowed indirect sources filename
        case 'i':
            // Close memleak when invoking this argument multiple times
            if (args->indirect_sources_filename)
                free(args->indirect_sources_filename);
            args->indirect_sources_filename = strdup(optarg);
            break;
        // Timeout
        case 't':;
            double seconds = strtod(optarg, &endptr);

            if (*endptr != '\0' || seconds <= 0) {
                fprintf(stderr, "Invalid number specified.\n");
                goto help;
            }

            args->timeout_ns = seconds * SECONDS_TO_NS;
            break;
        // Maximum session elements
        case 'n':;
            unsigned long max_elem = strtoul(optarg, &endptr, 0);

            if (max_elem > 0xffff) {
                fprintf(stderr, "Specified session count exceeds the possible "
                                "limit of 65535.\n");
                goto help;
            }
            if (*endptr != '\0' || max_elem == 0) {
                fprintf(stderr, "Invalid number specified.\n");
                goto help;
            }

            args->max_elem = max_elem;
            break;
        default:
            goto help;
        };
    }

    if (!args->sources_filename)
        args->sources_filename =
            strdup("/etc/augsburg-traceroute-server/" AF_STR "/allowed.txt");
    if (!args->indirect_sources_filename)
        args->indirect_sources_filename = strdup(
            "/etc/augsburg-traceroute-server/" AF_STR "/allowed_indirect.txt");

    // Somewhere along the way strdup might fail, setting errno
    if (errno) {
        free_args(args);
        perror("Unexpected error while parsing arguments:");
        return -1;
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

static int parse_networks(FILE *sources, struct netlist *networks,
                          struct netlist *parents)
{
    ssize_t nread;
    size_t line_size = 0, nentries = 0, nlines = 0;
    char *line = NULL;
    errno = 0;

    while ((nread = getline(&line, &line_size, sources)) > 0) {
        nlines++;
        // Replace newline with string-terminator
        line[nread - 1] = '\0';

        // Ignore empty lines and comments
        if (*line == '\0' || *line == '#')
            continue;

#define PARSE_ERROR(err)                                                       \
    fprintf(stderr, "Line %lu: '%s': %s\n", nlines, line, err)

        struct network entry;
        switch (parse_cidr(ADDR_FAMILY, line, &entry)) {
        case 0:
            if (parents && parents->len > 0) {
                struct netlist_elem *elem;
                NETLIST_LOOP(parents, elem)
                {
                    if (net_contains(&elem->net, &entry.address) == 0)
                        goto ok;
                }
                PARSE_ERROR("not contained in parents, skipping");
                continue;
            }
        ok:
            if (netlist_push_back(networks, &entry) < 0) {
                fprintf(stderr, "Failed to add network entry to the list!\n");
                return -1;
            }
            break;
        case -CIDR_ERR_FORMAT:
            PARSE_ERROR("expected network in CIDR format");
            break;
        case -CIDR_ERR_ADDRESS:
            PARSE_ERROR("invalid address format");
            break;
        case -CIDR_ERR_PREFIX:
            PARSE_ERROR("invalid prefix length");
            break;
        case -CIDR_ERR_PREFIXLEN:
            PARSE_ERROR("prefix length is outside of valid bounds");
            break;
        case -CIDR_ERR_HOSTBITS:
            PARSE_ERROR("host bits are set");
            break;
        default:
            PARSE_ERROR("unknown error");
            break;
        }

        // Count this line as an entry, should the final list len
        // and this number differ, errors were encountered.
        nentries++;
#undef PARSE_ERROR
    }

    free(line);

    if (errno) {
        perror("getline: ");
        return -1;
    }
    if (networks->len != nentries)
        return -1;

    return nentries;
}

static int update_networks(struct bpf_map *map, struct netlist *networks)
{
    struct network entry;
    net_index counter = 0;

    while (netlist_pop_front(networks, &entry) == 0) {
        if (bpf_map__update_elem(map, &counter, sizeof(counter), &entry,
                                 sizeof(entry), 0) < 0)
            return -1;

        char buffer[ADDRSTRLEN];
        fprintf(stderr, "Inserted %s ",
                inet_ntop(ADDR_FAMILY, &entry.address, buffer, sizeof(buffer)));
        fprintf(stderr, "with netmask %s ",
                inet_ntop(ADDR_FAMILY, &entry.netmask, buffer, sizeof(buffer)));
        fprintf(stderr, "into position %u\n", counter);

        counter++;
    }

    return 0;
}

static int load_networks(FILE *sources, struct bpf_map *map,
                         struct netlist *networks, struct netlist *parents)
{
    if (parse_networks(sources, networks, parents) < 0)
        return -1;

    // When no networks were found (empty file) don't resize the map.
    // In that case we still want to rely on the default values.
    if (networks->len == 0) {
        fprintf(stderr, "No network entries found, allowing requests from all "
                        "addresses!\n");
        return 0;
    }

    if (bpf_map__set_max_entries(map, networks->len) < 0) {
        perror("Failed to resize network map: ");
        return -1;
    }

    fprintf(stderr, "Resized map to %zu entries\n", networks->len);
    return 0;
}
static int load_networks_from_path(char *sources_filename, struct bpf_map *map,
                                   struct netlist *networks,
                                   struct netlist *parents)
{
    fprintf(stderr, "Attempting to read network entries from '%s'\n",
            sources_filename);

    FILE *sources = fopen(sources_filename, "r");
    if (!sources) {
        fprintf(stderr, "Failed to open file!\n");
        return -1;
    }

    int ret = load_networks(sources, map, networks, parents);
    fclose(sources);

    if (ret < 0)
        fprintf(stderr, "Detected errors while parsing '%s'\n",
                sources_filename);

    return ret;
}

static struct traceroute *traceroute_init(const struct args *args)
{
    struct traceroute *traceroute = traceroute__open();

    if (!traceroute) {
        fprintf(stderr, "Failed to open the eBPF program!\n");
        return NULL;
    }

    if (args->indirect_set)
        traceroute->rodata->CONFIG_INDIRECT_TRACE_ENABLED =
            args->indirect_enabled;

    if (args->tcp_syn_set)
        traceroute->rodata->CONFIG_TCP_SYN_ENABLED = args->tcp_syn_enabled;

    if (args->timeout_ns)
        traceroute->rodata->CONFIG_TIMEOUT_NS = args->timeout_ns;

    if (args->max_elem) {
        if (bpf_map__set_max_entries(traceroute->maps.sessions,
                                     args->max_elem) < 0 ||
            bpf_map__set_max_entries(traceroute->maps.session_ids,
                                     args->max_elem) < 0) {
            fprintf(stderr,
                    "Failed to set maximum number of sessions to %lu!\n",
                    args->max_elem);
            goto err;
        }
    }

    struct netlist sources = NETLIST_INIT;
    if (load_networks_from_path(args->sources_filename,
                                traceroute->maps.allowed_sources, &sources,
                                NULL) < 0)
        goto err;

    struct netlist indirect_sources = NETLIST_INIT;
    if (traceroute->rodata->CONFIG_INDIRECT_TRACE_ENABLED) {
        if (load_networks_from_path(args->indirect_sources_filename,
                                    traceroute->maps.allowed_sources_multipart,
                                    &indirect_sources, &sources) < 0) {
            netlist_clear(&sources);
            goto err;
        }
    } else {
        fprintf(stderr, "Indirect tracing is disabled, ignoring the "
                        "'--allow-indirect-from' argument\n");
    }

    if (traceroute__load(traceroute) < 0) {
        fprintf(stderr, "Failed to load the program!\n");
        goto free;
    }

    if (update_networks(traceroute->maps.allowed_sources, &sources) < 0)
        goto free;
    if (update_networks(traceroute->maps.allowed_sources_multipart,
                        &indirect_sources) < 0)
        goto free;

    netlist_clear(&sources);
    netlist_clear(&indirect_sources);

    // Create valid session identifiers and populate the kernel side with them.
    for (__u32 i = 1; i <= bpf_map__max_entries(traceroute->maps.sessions);
         i++) {
        __u16 value = i;
        if (bpf_map__update_elem(traceroute->maps.session_ids, NULL, 0, &value,
                                 sizeof(value), BPF_ANY) < 0) {
            fprintf(stderr, "Error while inserting session identifiers\n.");
            goto err;
        }
    }

    return traceroute;

free:
    netlist_clear(&sources);
    netlist_clear(&indirect_sources);
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
    case SESSION_CREATED:
        printf("session created.\n");
        break;
    case SESSION_DELETED:
        printf("session deleted.\n");
        break;
    case SESSION_TIMEOUT:
        printf("session timed out.\n");
        break;
    case SESSION_ID_POP:
    case SESSION_BUFFER_FULL:
        printf("session buffer full.\n");
        break;
    case SESSION_PROBE_ANSWERED:
        printf("probe answer received.\n");
        break;
    case SESSION_ID_PUSH:
        printf("failed to return session ID to queue. Program now runs with "
               "degraded set of sessions.\n");
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
    free_args(&args);
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

    fprintf(stderr, "\n\nSession timeout in seconds: %.2lf\n",
            tr->rodata->CONFIG_TIMEOUT_NS / SECONDS_TO_NS);
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
