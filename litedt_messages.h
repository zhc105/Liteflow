/*
 * Copyright (c) 2021, Moonflow <me@zhc105.net>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef _LITEDT_MESSAGES_H_
#define _LITEDT_MESSAGES_H_

#include <stdint.h>

#define LITEDT_VERSION      0xED03
#define LITEDT_MSS_MAX      1400
#define LITEDT_MAX_HEADER   28
#define LITEDT_MTU_MAX      (LITEDT_MSS_MAX + LITEDT_MAX_HEADER)

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
    LITEDT_CONNECT_RST  = 0x26,
    LITEDT_CONNECT_DATA = 0x27,
    // FEC message
    LITEDT_DATA_FEC     = 0x30
};

#pragma pack(1)
typedef struct _litedt_header {
    uint16_t    ver;
    uint8_t     mode;
    uint8_t     cmd;
    uint32_t    flow;
} litedt_header_t;

typedef struct _ping_req {
    uint16_t    node_id;
    uint32_t    ping_id;
    uint8_t     data[8];
} ping_req_t;

typedef struct _ping_rsp {
    uint16_t    node_id;
    uint32_t    ping_id;
    uint8_t     data[8];
} ping_rsp_t;

typedef struct _data_post {
    uint32_t    seq;
    uint16_t    len;
    uint32_t    fec_seq;
    uint8_t     fec_index;
    char        data[0];
} data_post_t;

typedef struct _data_ack {
    uint32_t    win_start;
    uint32_t    win_size;
    uint8_t     ack_size;
    uint32_t    acks[0][2];
} data_ack_t;

typedef struct _conn_req {
    uint16_t    tunnel_id;
} conn_req_t;

typedef struct _data_conn {
    conn_req_t  conn_req;
    data_post_t data_post;
} data_conn_t;

typedef struct _conn_rsp {
    int32_t     status;
} conn_rsp_t;

typedef struct _close_req {
    uint32_t    last_seq;
} close_req_t;

typedef struct _data_fec {
    uint32_t    fec_seq;
    uint8_t     fec_members;
    uint16_t    fec_len;
    char        fec_data[0];
} data_fec_t;
#pragma pack()

#endif
