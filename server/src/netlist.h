#ifndef NETLIST_H
#define NETLIST_H

#include "net.h"
#include <assert.h>
#include <stddef.h>
#include <stdlib.h>

struct netlist_elem {
    struct net_entry net;
    struct netlist_elem *next;
};

#define NETLIST_INIT                                                              \
    {                                                                          \
        NULL, NULL, 0                                                                \
    }
struct netlist_head {
    struct netlist_elem *first;
    struct netlist_elem *last;
    size_t len;
};

#define NETLIST_LOOP(head, entry) \
    for ((entry) = (head)->first; (entry) != NULL; (entry) = (entry)->next)

#define NETLIST_HEAD_GUARD(head)                                                  \
    assert(((head)->first == NULL && (head)->last == NULL && (head)->len == 0) ||                      \
           ((head)->first != NULL && (head)->last != NULL && (head)->len > 0))

static int netlist_push_back(struct netlist_head *head, struct net_entry *entry)
{
    LIST_HEAD_GUARD(head);

    struct netlist_elem *new_elem = malloc(sizeof(*new_elem));
    if (!new_elem)
        return -1;

    new_elem->next = NULL;
    new_elem->net = *entry;

    if (head->len > 0) {
        head->last->next = new_elem;
        head->last = new_elem;
    } else {
        head->first = new_elem;
        head->last = new_elem;
    }

    head->len++;
    return 0;
}

static int netlist_pop_front(struct netlist_head *head, struct net_entry *elem)
{
    LIST_HEAD_GUARD(head);

    struct netlist_elem *first = head->first;
    if (!first)
        return -1;

    if (elem)
        *elem = first->net;

    head->first = first->next;
    head->len --;
    if (head->len == 0)
        head->last = NULL;

    free(first);
    return 0;
}

static void netlist_clear(struct netlist_head *head)
{
    LIST_HEAD_GUARD(head);
    while (netlist_pop_front(head, NULL) == 0)
        ;
}

#undef LIST_HEAD_GUARD

#endif