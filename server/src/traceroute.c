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
#include <time.h>
#include <unistd.h>

struct args {
  int ifindex;      // Always specified by the user
  __u64 TIMEOUT_NS; // Optional, 0 if not specified
  __u32 MAX_ELEM;   // Optional, 0 if not specified
};

const char *fmt_help_message =
    "Usage: %s [-t TIMEOUT_NS] [-n MAX_ENTRIES] if_index\n"
    "\t-t: The time after which a session expires, in nanoseconds.\n"
    "\t-n: The maximum number of sessions the server can handle.\n";

static int parse_args(int argc, char **argv, struct args *args) {
  memset(args, 0, sizeof(*args));

  char *endptr;
  int option;
  while ((option = getopt(argc, argv, "t:n:h")) != -1) {
    switch (option) {
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
    args->ifindex = atoi(argv[optind]);
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

static struct traceroute *traceroute_init(struct args *args) {

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
                           va_list args) {
  return vfprintf(stderr, format, args);
}

static int log_message(void *ctx, void *data, size_t size) {
#define TSTAMP_MAX_LEN 25
  const char *tstamp_fmt = "%Y-%m-%dT%H:%M:%S%z";

  char address[INET_ADDRSTRLEN];
  char tstamp[TSTAMP_MAX_LEN + 1];

  const time_t rtime = time(NULL);
  const struct tm *ltime = localtime(&rtime);
  strftime(tstamp, sizeof(tstamp), tstamp_fmt, ltime);

  struct message *msg = data;
  if (!inet_ntop(AF_INET, &msg->data.address, address, sizeof(address)))
    return 0;

  printf("%*s | [%*s, %5u] | ", TSTAMP_MAX_LEN, tstamp, INET_ADDRSTRLEN,
         address, msg->data.probe_id);
  switch (msg->type) {
  case SESSION_CREATED:
    printf("session created.");
    break;
  case SESSION_DELETED:
    printf("session deleted.");
    break;
  case SESSION_TIMEOUT:
    printf("session timed out.");
    break;
  case SESSION_BUFFER_FULL:
    printf("session buffer full.");
    break;
  case SESSION_PROBE_ANSWERED:
    printf("probe answer received.");
    break;
  }
  printf("\n");
  fflush(stdout);

  return 0;
}

static volatile bool exiting = false;

static void sig_handler(int signum) { exiting = true; }

int main(int argc, char **argv) {
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
  DECLARE_LIBBPF_OPTS(bpf_tc_opts, opts, .handle = 1, .priority = 1,
                      .prog_fd = bpf_program__fd(tr->progs.prog));

  if (bpf_tc_hook_create(&hook) < 0)
    goto exit;
  if (bpf_tc_attach(&hook, &opts) < 0)
    goto destroy;

  fprintf(stderr, "\n\nSession timeout in nanoseconds: %llu\n",
          tr->rodata->TIMEOUT_NS);
  fprintf(stderr, "Maximum session entries: %u\n\n\n",
          bpf_map__max_entries(tr->maps.map_sessions));

  log_buf =
      ring_buffer__new(bpf_map__fd(tr->maps.log_buf), log_message, NULL, NULL);
  if (!log_buf) {
    fprintf(stderr, "Failed to create logging buffer.\n");
    goto detach;
  }

  signal(SIGINT, sig_handler);
  signal(SIGTERM, sig_handler);

  while (!exiting) {
    ret = ring_buffer__poll(log_buf, 100);
    if (ret == -EINTR) {
      ret = 0;
      break;
    } else if (ret < 0) {
      fprintf(stderr, "Failed to poll the logging buffer.\n");
      break;
    }
  }

  ret = EXIT_SUCCESS;
  ring_buffer__free(log_buf);
detach:
  opts.flags = opts.prog_fd = opts.prog_id = 0;
  bpf_tc_detach(&hook, &opts);
destroy:
  hook.attach_point = BPF_TC_INGRESS | BPF_TC_EGRESS;
  bpf_tc_hook_destroy(&hook);
  traceroute__destroy(tr);
exit:
  return ret;
}
