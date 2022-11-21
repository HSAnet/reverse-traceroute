/*
Copyright 2022 University of Applied Sciences Augsburg

This file is part of Augsburg-Traceroute.

Augsburg-Traceroute is free software: you can redistribute it and/or modify it under the terms
of the GNU General Public License as published by the Free Software Foundation,
either version 3 of the License, or (at your option) any later version.

Augsburg-Traceroute is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with Augsburg-Traceroute.
If not, see <https://www.gnu.org/licenses/>. 
*/

#ifndef CONFIG_H
#define CONFIG_H

#include <linux/types.h>

// The default value for the maximum session entries if not overridden by the
// loader
#define DEFAULT_MAX_ELEM 5000

// The default value for the session entry timeout if not overridden by the
// loader
#define DEFAULT_TIMEOUT_NS 5000000000

extern volatile const __u64 TIMEOUT_NS;

#endif
