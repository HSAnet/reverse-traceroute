#ifndef LOGGING_H
#define LOGGING_H

#include "internal.h"
#include "session.h"
#include "../messages.h"

INTERNAL void log_message(enum message_type type, struct session_key *key);

#endif
