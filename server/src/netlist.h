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

#define LIST_INIT { NULL, 0 }
struct netlist_head {
    struct netlist_elem *first;
    size_t len;
};


#define LIST_HEAD_GUARD(head) \
    assert(((head)->first == NULL && (head)->len == 0) || ((head)->first != NULL && (head)->len > 0))

static int netlist_push_back(struct netlist_head *head, struct net_entry *entry)
{
    LIST_HEAD_GUARD(head);

    struct netlist_elem *new_elem = malloc(sizeof(*new_elem));
    if (!new_elem)
        return -1;
    
    new_elem->next = NULL;
    new_elem->net = *entry; 
    
    if (head->first) {
        struct netlist_elem *last = head->first;
        for (; last->next != NULL; last = last->next);
        last->next = new_elem;
    } else {
       head->first = new_elem; 
    }
    head->len++;

    return 0;
}

static int netlist_pop_front(struct netlist_head *head, struct net_entry *elem)
{
    LIST_HEAD_GUARD(head);

    struct netlist_elem *first = head->first;
    if (!first) return -1;

    if (elem) *elem = first->net;
    head->first = first->next;
    head->len--;

    free(first);
    return 0;
}

static void netlist_free(struct netlist_head *head)
{
    LIST_HEAD_GUARD(head);
    while (netlist_pop_front(head, NULL) == 0);
}

#undef LIST_HEAD_GUARD

#endif