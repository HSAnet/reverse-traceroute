#ifndef CURSOR_H
#define CURSOR_H

#include <linux/bpf.h>

struct cursor
{
    struct __sk_buff *skb;
    void *pos;
};

static long cursor_start(struct cursor *cursor)
{
    return cursor->skb->data;
}

static long cursor_end(struct cursor *cursor)
{
    return cursor->skb->data_end;
}

static void cursor_reset(struct cursor *cursor)
{
    cursor->pos = (void *)cursor_start(cursor);
}

static void cursor_init(struct cursor *cursor, struct __sk_buff *skb)
{
    cursor->skb = skb;
    cursor_reset(cursor);
}

static void cursor_clone(struct cursor *original, struct cursor *clone)
{
    *clone = *original;
}

#define PARSE(cursor, hdr) \
({ \
    int __ret = -1; \
    typeof(*(hdr)) __tmp = (cursor)->pos; \
    if ((long)(cursor)->pos + sizeof(*__tmp) <= cursor_end(cursor)) \
    { \
        (cursor)->pos = __tmp + 1; \
        *(hdr) = __tmp; \
        __ret = 0;\
    } \
    __ret; \
})

#endif
