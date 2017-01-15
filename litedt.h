/*
 * Copyright (c) 2016, Moonflow <me@zhc105.net>
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

#ifndef _LITEDT_H_
#define _LITEDT_H_

#include <arpa/inet.h>
#include "litedt_messages.h"
#include "hashqueue.h"
#include "rbuffer.h"
#include "retrans.h"
#include "ctrl.h"
#include "fec.h"

#define CONN_HASH_SIZE      1013

enum CONNECT_STATUS {
    CONN_REQUEST = 0,
    CONN_ESTABLISHED,
    CONN_FIN_WAIT,
    CONN_CLOSE_WAIT,
    CONN_CLOSED
};

enum LITEDT_ERRCODE {
    RECORD_NOT_FOUND    = -100,
    RECORD_EXISTS       = -101,
    SOCKET_ERROR        = -102,
    MEM_ALLOC_ERROR     = -103,
    PARAMETER_ERROR     = -104,
    NOT_ENOUGH_SPACE    = -105,
    OFFSET_OUT_OF_RANGE = -106,
    SEND_FLOW_CONTROL   = -200,
    CLIENT_OFFLINE      = -300
};

enum TIME_PARAMETER {
    CONNECTION_TIMEOUT  = 60000,
    TIME_WAIT_EXPIRE    = 120000,
    PERF_CTRL_INTERVAL  = 20000,
    PING_INTERVAL       = 2000,
    FLOW_CTRL_UNIT      = 10,

    FAST_ACK_DELAY      = 20,
    REACK_DELAY         = 40,
    NORMAL_ACK_DELAY    = 1000,

    IDLE_INTERVAL       = 1000,
    BUSY_INTERVAL       = 1
};

typedef struct _litedt_host litedt_host_t;

typedef int 
litedt_connect_fn(litedt_host_t *host, uint32_t flow, uint16_t map_id);
typedef void 
litedt_close_fn(litedt_host_t *host, uint32_t flow);
typedef void 
litedt_receive_fn(litedt_host_t *host, uint32_t flow, int readable);
typedef void 
litedt_send_fn(litedt_host_t *host, uint32_t flow, int writable);
typedef void
litedt_event_time_fn(litedt_host_t *host, int64_t interval);

#pragma pack(1)
typedef struct _litedt_stat {
    uint32_t send_bytes_stat;
    uint32_t recv_bytes_stat;
    uint32_t send_bytes_data;
    uint32_t recv_bytes_data;
    uint32_t send_bytes_ack;
    uint32_t recv_bytes_ack;
    uint32_t data_packet_post;
    uint32_t retrans_packet_post;
    uint32_t fec_packet_post;
    uint32_t data_packet_post_succ;
    uint32_t repeat_packet_recv;
    uint32_t fec_recover;
    uint32_t send_error;
    uint32_t udp_lost;
    uint32_t connection_num;
    uint32_t timewait_num;
    uint32_t fec_group_size;
    uint32_t rtt;
} litedt_stat_t;
#pragma pack()

struct _litedt_host {
    int             sockfd;
    litedt_stat_t   stat;
    uint32_t        send_bytes;
    uint32_t        send_bytes_limit;
    int             lock_remote_addr;
    int             remote_online;
    struct          sockaddr_in remote_addr;
    uint32_t        ping_id;
    uint32_t        rtt;
    int64_t         cur_time;
    int64_t         clear_send_time;
    int64_t         ctrl_adjust_time;
    int64_t         last_ping;
    int64_t         last_ping_rsp;
    uint8_t         fec_group_size_ctrl;

    hash_node_t*    conn_send;
    hash_queue_t    conn_queue;
    hash_queue_t    timewait_queue;

    retrans_mod_t   retrans;
    ctrl_mod_t      ctrl;

    litedt_connect_fn*      connect_cb;
    litedt_close_fn*        close_cb;
    litedt_receive_fn*      receive_cb;
    litedt_send_fn*         send_cb;
    litedt_event_time_fn*   event_time_cb;
};

typedef struct _litedt_conn {
    int         status;
    uint16_t    map_id;
    uint32_t    flow;
    uint32_t    swin_start;
    uint32_t    swin_size;
    uint32_t    rwin_start;
    uint32_t    rwin_size;
    int64_t     last_responsed;
    int64_t     next_ack_time;
    uint32_t    write_offset;
    uint32_t    send_offset;
    uint32_t    *ack_list;
    uint32_t    ack_num;
    uint32_t    reack_times;
    int         notify_recvnew;
    int         notify_recv;
    int         notify_send;

    rbuf_t      send_buf;
    rbuf_t      recv_buf;

    fec_mod_t   *fec;
} litedt_conn_t;

typedef struct _litedt_tw_conn {
    uint32_t    flow;
    int64_t     close_time;
} litedt_tw_conn_t;

int litedt_init(litedt_host_t *host);

int  litedt_connect(litedt_host_t *host, uint32_t flow, uint16_t map_id);
int  litedt_close(litedt_host_t *host, uint32_t flow);
int  litedt_send(litedt_host_t *host, uint32_t flow, const char *buf, 
                 uint32_t len);
int  litedt_recv(litedt_host_t *host, uint32_t flow, char *buf, uint32_t len);
int  litedt_peek(litedt_host_t *host, uint32_t flow, char *buf, uint32_t len);
void litedt_recv_skip(litedt_host_t *host, uint32_t flow, uint32_t len);
int  litedt_writable_bytes(litedt_host_t *host, uint32_t flow);
int  litedt_readable_bytes(litedt_host_t *host, uint32_t flow);

void litedt_set_remote_addr(litedt_host_t *host, char *addr, uint16_t port);
void litedt_set_connect_cb(litedt_host_t *host, litedt_connect_fn *conn_cb);
void litedt_set_close_cb(litedt_host_t *host, litedt_close_fn *close_cb);
void litedt_set_receive_cb(litedt_host_t *host, litedt_receive_fn *recv_cb);
void litedt_set_send_cb(litedt_host_t *host, litedt_send_fn *send_cb);
void litedt_set_event_time_cb(litedt_host_t *host, litedt_event_time_fn *cb);
void litedt_set_notify_recv(litedt_host_t *host, uint32_t flow, int notify);
void litedt_set_notify_recvnew(litedt_host_t *host, uint32_t flow, int notify);
void litedt_set_notify_send(litedt_host_t *host, uint32_t flow, int notify);

void litedt_io_event(litedt_host_t *host, int64_t cur_time);
void litedt_time_event(litedt_host_t *host, int64_t cur_time);
litedt_stat_t* litedt_get_stat(litedt_host_t *host);
void litedt_clear_stat(litedt_host_t *host);
int  litedt_online_status(litedt_host_t *host);

int  litedt_startup(litedt_host_t *host);
void litedt_shutdown(litedt_host_t *host);

void litedt_fini(litedt_host_t *host);

/* internal methods */
int socket_send(litedt_host_t *host, const void *buf, size_t len, int force);
litedt_conn_t* find_connection(litedt_host_t *host, uint32_t flow);
int litedt_ping_req(litedt_host_t *host);
int litedt_ping_rsp(litedt_host_t *host, ping_req_t *req);
int litedt_conn_req(litedt_host_t *host, uint32_t flow, uint16_t map_id);
int litedt_conn_rsp(litedt_host_t *host, uint32_t flow, int32_t status);
int litedt_data_post(litedt_host_t *host, uint32_t flow, uint32_t offset, 
                     uint32_t len, uint32_t fec_offset, uint8_t fec_index, 
                     int64_t curtime, int fec_post);
int litedt_data_ack(litedt_host_t *host, uint32_t flow, int ack_list);
int litedt_close_req(litedt_host_t *host, uint32_t flow, uint32_t last_offset);
int litedt_close_rsp(litedt_host_t *host, uint32_t flow);
int litedt_conn_rst(litedt_host_t *host, uint32_t flow);

int litedt_on_ping_req(litedt_host_t *host, ping_req_t *req);
int litedt_on_ping_rsp(litedt_host_t *host, ping_rsp_t *rsp);
int litedt_on_conn_req(litedt_host_t *host, uint32_t flow, conn_req_t *req,
                       int no_rsp);
int litedt_on_conn_rsp(litedt_host_t *host, uint32_t flow, conn_rsp_t *rsp);
int litedt_on_data_recv(litedt_host_t *host, uint32_t flow, data_post_t *data, 
                        int fec_recv);
int litedt_on_data_ack(litedt_host_t *host, uint32_t flow, data_ack_t *ack);
int litedt_on_close_req(litedt_host_t *host, uint32_t flow, close_req_t *req);
int litedt_on_close_rsp(litedt_host_t *host, uint32_t flow);
int litedt_on_conn_rst(litedt_host_t *host, uint32_t flow);
int litedt_on_data_fec(litedt_host_t *host, uint32_t flow, data_fec_t *fec);


#endif
