#ifndef BPF_SOURCE_H
#define BPF_SOURCE_H

#include "internal.h"
#include "ip_generic.h"

INTERNAL int source_allowed(const ipaddr_t *source);

#endif