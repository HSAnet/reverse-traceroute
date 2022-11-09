#ifndef LOGGING_H
#define LOGGING_H

#include "../messages.h"
#include "internal.h"
#include "session.h"

INTERNAL void log_message(enum message_type type, struct session_key *key);

#endif
