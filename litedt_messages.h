#ifndef _LITEDT_MESSAGES_H_
#define _LITEDT_MESSAGES_H_

#include <stdint.h>

#define LITEDT_VERSION 0xED01

enum LITEDT_CMD_ID {
    // session messages
    LITEDT_PING_REQ     = 0x10,
    LITEDT_PING_RSP     = 0x11,
    // data messages
    LITEDT_DATA_POST    = 0x20,
    LITEDT_DATA_ACK     = 0x21,
    LITEDT_CONNECT_REQ  = 0x22,
    LITEDT_CONNECT_RSP  = 0x23,
    LITEDT_CLOSE_REQ    = 0x24,
    LITEDT_CLOSE_RSP    = 0x25,
    LITEDT_CONNECT_RST  = 0x26
};

#pragma pack(1)
typedef struct _litedt_header {
    uint16_t ver;
    uint8_t cmd;
    uint32_t flow;
} litedt_header_t;

typedef struct _ping_req {
    uint32_t ping_id;
    uint8_t data[8];
} ping_req_t;

typedef struct _ping_rsp {
    uint32_t ping_id;
    uint8_t data[8];
} ping_rsp_t;

typedef struct _data_post {
    uint32_t offset;
    uint16_t len;
    char data[0];
} data_post_t;

typedef struct _data_ack {
    uint32_t win_start;
    uint32_t win_size;
    uint8_t ack_size;
    uint32_t acks[0];
} data_ack_t;

typedef struct _conn_req {
    uint16_t target_port;
} conn_req_t;

typedef struct _conn_rsp {
    int32_t status;
} conn_rsp_t;

typedef struct _close_req {
    uint32_t last_offset;
} close_req_t;
#pragma pack()

#endif
