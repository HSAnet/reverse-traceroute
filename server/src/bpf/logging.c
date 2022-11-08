#include "logging.h"
#include "../messages.h"
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4096);
} log_buf SEC(".maps");


INTERNAL void log_message(enum message_type type, struct session_key *key)
{
    struct message *msg = bpf_ringbuf_reserve(&log_buf, sizeof(struct message), 0);
    if (!msg)
        return;

    msg->type = type;
    msg->data.address = key->addr;
    msg->data.probe_id = key->identifier;

    bpf_ringbuf_submit(msg, 0);
}
