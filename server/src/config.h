#ifndef CONFIG_H
#define CONFIG_H

#include <linux/types.h>

#define DEFAULT_MAX_ELEM                                                                                                       \
    500 // The maximum number of traceroute sessions.
        // Upon reaching the limit, new reverse traceroute requests
        // are silently ignored.

#define DEFAULT_TIMEOUT_NS                                                                                                     \
    5000000000 // The session cleanup timeout in nanoseconds.
               // If no answer to a traceroute probe is received in this time,
               // the associated state is cleaned up.

extern volatile const __u64 TIMEOUT_NS;

#endif
