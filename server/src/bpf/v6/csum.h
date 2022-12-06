/*
Copyright 2022 University of Applied Sciences Augsburg

This file is part of Augsburg-Traceroute.

Augsburg-Traceroute is free software: you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the Free
Software Foundation, either version 3 of the License, or (at your option) any
later version.

Augsburg-Traceroute is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
details.

You should have received a copy of the GNU General Public License along with
Augsburg-Traceroute. If not, see <https://www.gnu.org/licenses/>.
*/

#ifndef CSUM_H
#define CSUM_H

#include <linux/types.h>

// Computes the checksum. See RFC1071 for details.
static __sum16 csum(void *cursor, __u16 len, __be32 seed)
{
    __be32 sum = seed;
    __be16 *pos = cursor;

    while (len > 1) {
        sum += *(pos++);
        len -= 2;
    }

    if (len > 0)
        sum += *pos;

    // Fold the recorded carry-outs back into the 16-bit sum.
    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);

    return (__sum16)~sum;
}

#endif
