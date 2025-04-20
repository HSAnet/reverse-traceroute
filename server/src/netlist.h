#ifndef NETLIST_H
#define NETLIST_H

#include "net.h"
#include <assert.h>
#include <stddef.h>
#include <stdlib.h>

struct netlist_elem {
    struct network net;
    struct netlist_elem *next;
};

#define NETLIST_INIT                                                           \
    (struct netlist)                                                           \
    {                                                                          \
        NULL, NULL, 0                                                          \
    }
struct netlist {
    struct netlist_elem *first;
    struct netlist_elem *last;
    size_t len;
};

#define NETLIST_LOOP(head, entry)                                              \
    for ((entry) = (head)->first; (entry) != NULL; (entry) = (entry)->next)

#define NETLIST_HEAD_GUARD(head)                                               \
    assert(                                                                    \
        ((head)->first == NULL && (head)->last == NULL && (head)->len == 0) || \
        ((head)->first != NULL && (head)->last != NULL && (head)->len > 0))

/**
 * @brief Appends a network to the end of \p list.
 * The element pointed to by \p elem is copied to the heap.
 *
 * @param list The list to append to.
 * @param elem A pointer to the new element.
 * @return -1 on failure, 0 on success.
 */
static int netlist_push_back(struct netlist *list, struct network *elem)
{
    NETLIST_HEAD_GUARD(list);

    struct netlist_elem *new_elem = malloc(sizeof(*new_elem));
    if (!new_elem)
        return -1;

    new_elem->next = NULL;
    new_elem->net = *elem;

    if (list->len > 0) {
        list->last->next = new_elem;
        list->last = new_elem;
    } else {
        list->first = new_elem;
        list->last = new_elem;
    }

    list->len++;
    return 0;
}

/**
 * @brief Removes the first element from the @p list
 * and copies it's value to the location referenced by @p elem.
 *
 * @details @p elem can be a NULL pointer, in which case the first element will
 * be removed.
 * @param list The list from which to remove the first element.
 * @param elem A pointer to a valid memory location, which will contain the
 * first network element.
 * @return -1 when the list is empty, 0 on success.
 */
static int netlist_pop_front(struct netlist *list, struct network *elem)
{
    NETLIST_HEAD_GUARD(list);

    struct netlist_elem *first = list->first;
    if (!first)
        return -1;

    if (elem)
        *elem = first->net;

    list->first = first->next;
    list->len--;

    if (list->len == 0)
        *list = NETLIST_INIT;

    free(first);
    return 0;
}

/**
 * @brief Removes all elements from the @p list.
 *
 * @param list The list to clear.
 */
static void netlist_clear(struct netlist *list)
{
    NETLIST_HEAD_GUARD(list);

    while (netlist_pop_front(list, NULL) == 0)
        ;
}

#undef NETLIST_HEAD_GUARD

#endif