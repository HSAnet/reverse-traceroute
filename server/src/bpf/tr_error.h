#ifndef BPF_ERROR_H
#define BPF_ERROR_H

typedef enum {
    ERR_NONE = 0x00,
    ERR_TTL = 0x01,
    ERR_PROTO = 0x02,
    ERR_FLOW = 0x03,
    ERR_MULTIPART_NOT_SUPPORTED = 0x04,
} tr_error;

#endif