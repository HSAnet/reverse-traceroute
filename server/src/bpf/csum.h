#ifndef CSUM_H
#define CSUM_H

#include <linux/types.h>

// Computes the checksum. See RFC1071 for details.
static __sum16 csum(void *cursor, __u16 len, __be32 seed) {
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
