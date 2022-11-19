#ifndef CONFIG_H
#define CONFIG_H

#include <linux/types.h>

// The default value for the maximum session entries if not overridden by the loader
#define DEFAULT_MAX_ELEM 5000

// The default value for the session entry timeout if not overridden by the loader
#define DEFAULT_TIMEOUT_NS 5000000000

extern volatile const __u64 TIMEOUT_NS;

#endif
