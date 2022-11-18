#include "logging.h"
#include "../messages.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <linux/types.h>

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 128 * 1024);
} log_buf SEC(".maps");

INTERNAL void log_message(enum message_type type, struct session_key *key) {
  struct message *msg =
      bpf_ringbuf_reserve(&log_buf, sizeof(struct message), 0);
  if (!msg)
    return;

  msg->type = type;
  msg->data.address = key->addr;
  // As no arithmetic is performed on the identifier,
  // it is stored in network byte order in the session key.
  // For presentation we must convert it to the hosts byte order.
  msg->data.probe_id = bpf_ntohs(key->identifier);

  bpf_ringbuf_submit(msg, 0);
}
