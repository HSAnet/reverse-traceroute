#ifndef MESSAGES_H
#define MESSAGES_H

enum message_type {
    SESSION_CREATED,
    SESSION_DELETED,
    SESSION_TIMEOUT,
    SESSION_BUFFER_FULL,
    SESSION_PROBE_ANSWERED,
};

struct message {
    enum message_type type;
    struct {
        __be32 address;
        __be32 probe_id;
    } data;
};

#endif
