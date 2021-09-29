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

#ifndef _LITEDT_H_
#define _LITEDT_H_

#include <arpa/inet.h>
#include "litedt_messages.h"
#include "litedt_fwd.h"
#include "hashqueue.h"
#include "rbuffer.h"
#include "timerlist.h"
#include "windowed_filter.h"
#include "retrans.h"
#include "ctrl.h"
#include "fec.h"

enum LITEDT_ERRCODE {
    LITEDT_RECORD_NOT_FOUND     = -100,
    LITEDT_RECORD_EXISTS        = -101,
    LITEDT_SOCKET_ERROR         = -102,
    LITEDT_MEM_ALLOC_ERROR      = -103,
    LITEDT_PARAMETER_ERROR      = -104,
    LITEDT_NOT_ENOUGH_SPACE     = -105,
    LITEDT_SEQ_OUT_OF_RANGE     = -106,
    LITEDT_SEND_FLOW_CONTROL    = -200,
    LITEDT_CLIENT_OFFLINE       = -300
};

typedef void
litedt_accept_fn(
    litedt_host_t *host, uint16_t node_id, const struct sockaddr_in *addr);
typedef void
litedt_online_fn(litedt_host_t *host, int online);
typedef int
litedt_connect_fn(litedt_host_t *host, uint32_t flow, uint16_t tunnel_id);
typedef void
litedt_close_fn(litedt_host_t *host, uint32_t flow);
typedef void
litedt_receive_fn(litedt_host_t *host, uint32_t flow, int readable);
typedef void
litedt_send_fn(litedt_host_t *host, uint32_t flow, int writable);
typedef void
litedt_event_time_fn(litedt_host_t *host, litedt_time_t event_after);

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
    uint32_t dup_packet_recv;
    uint32_t fec_recover;
    uint32_t send_error;
    uint32_t udp_lost;
    uint32_t connection_num;
    uint32_t timewait_num;
    uint32_t fec_group_size;
    uint32_t rtt;
    uint32_t bandwidth;
} litedt_stat_t;
#pragma pack()

struct _litedt_host {
    int             sockfd;
    uint16_t        peer_node_id;
    uint16_t        mss;
    litedt_stat_t   stat;
    litedt_time_t   pacing_time;
    uint32_t        pacing_credit;
    uint32_t        pacing_rate;
    uint32_t        snd_cwnd;
    uint8_t         connected : 1,
                    remote_online : 1,
                    unused : 6;
    struct          sockaddr_in remote_addr;
    uint32_t        ping_id;
    uint32_t        srtt;
    litedt_time_t   cur_time;
    litedt_time_t   last_event_time;
    litedt_time_t   next_event_time;
    litedt_time_t   prior_ping_time;
    litedt_time_t   next_ping_time;
    litedt_time_t   offline_time;
    void*           ext;

    windowed_filter_t   rtt_min;
    windowed_filter_t   bw;

    uint32_t    ping_rtt;
    uint32_t    rtt_round;
    uint32_t    next_rtt_delivered;
    uint32_t    inflight;
    uint32_t    inflight_bytes;
    uint32_t    delivered;
    uint32_t    delivered_bytes;
    uint32_t    app_limited; /* limited until "delivered" reaches this val */
    litedt_time_t delivered_time;
    litedt_time_t first_tx_time;

    timerlist_t     conn_queue;
    timerlist_t     retrans_queue;
    hash_queue_t    timewait_queue;
    list_head_t     active_queue;

    ctrl_mod_t ctrl;

    litedt_accept_fn*       accept_cb;
    litedt_online_fn*       online_cb;
    litedt_connect_fn*      connect_cb;
    litedt_close_fn*        close_cb;
    litedt_receive_fn*      receive_cb;
    litedt_send_fn*         send_cb;
    litedt_event_time_fn*   event_time_cb;
};

typedef struct _litedt_conn {
    uint16_t    tunnel_id;
    uint32_t    flow;
    uint32_t    swin_start;
    uint32_t    swin_size;
    uint32_t    rwin_start;
    uint32_t    rwin_size;
    uint32_t    write_seq;
    uint32_t    send_seq;
    uint8_t     reack_times;
    uint8_t     probes_sent;
    uint8_t     state : 3,
                notify_recvnew : 1,
                notify_recv : 1,
                notify_send : 1,
                fec_enabled : 1,
                unused : 1;
    list_head_t active_list;
    treemap_t   sack_map;

    litedt_time_t last_probe_time;
    litedt_time_t last_sync_time;
    litedt_time_t next_sync_time;

    rbuf_t      send_buf;
    rbuf_t      recv_buf;

    retrans_mod_t   retrans;
    fec_mod_t       fec;
} litedt_conn_t;

typedef struct _litedt_tw_conn {
    uint32_t        flow;
    litedt_time_t   close_time;
} litedt_tw_conn_t;

int  litedt_init(litedt_host_t *host);

int  litedt_connect(litedt_host_t *host, uint32_t flow, uint16_t tunnel_id);
int  litedt_close(litedt_host_t *host, uint32_t flow);
int  litedt_send(litedt_host_t *host, uint32_t flow, const char *buf,
                uint32_t len);
int  litedt_recv(litedt_host_t *host, uint32_t flow, char *buf, uint32_t len);
int  litedt_peek(litedt_host_t *host, uint32_t flow, char *buf, uint32_t len);
void litedt_recv_skip(litedt_host_t *host, uint32_t flow, uint32_t len);
int  litedt_writable_bytes(litedt_host_t *host, uint32_t flow);
int  litedt_readable_bytes(litedt_host_t *host, uint32_t flow);

void litedt_set_remote_addr_v4(litedt_host_t *host, char *addr, uint16_t port);
void litedt_set_remote_addr(litedt_host_t *host,
                            const struct sockaddr_in *addr);
void litedt_set_ext(litedt_host_t *host, void *ext);

void litedt_set_accept_cb(litedt_host_t *host, litedt_accept_fn *accept_cb);
void litedt_set_online_cb(litedt_host_t *host, litedt_online_fn *online_cb);
void litedt_set_connect_cb(litedt_host_t *host, litedt_connect_fn *conn_cb);
void litedt_set_close_cb(litedt_host_t *host, litedt_close_fn *close_cb);
void litedt_set_receive_cb(litedt_host_t *host, litedt_receive_fn *recv_cb);
void litedt_set_send_cb(litedt_host_t *host, litedt_send_fn *send_cb);
void litedt_set_event_time_cb(litedt_host_t *host, litedt_event_time_fn *cb);
void litedt_set_notify_recv(litedt_host_t *host, uint32_t flow, int notify);
void litedt_set_notify_recvnew(litedt_host_t *host, uint32_t flow, int notify);
void litedt_set_notify_send(litedt_host_t *host, uint32_t flow, int notify);

void litedt_io_event(litedt_host_t *host);
litedt_time_t litedt_time_event(litedt_host_t *host);
litedt_stat_t* litedt_get_stat(litedt_host_t *host);
void litedt_clear_stat(litedt_host_t *host);
int  litedt_online_status(litedt_host_t *host);
uint16_t litedt_peer_node_id(litedt_host_t *host);
void* litedt_ext(litedt_host_t *host);
int  litedt_is_closed(litedt_host_t *host);
const char* litedt_ctrl_mode_name(litedt_host_t *host);

int  litedt_startup(litedt_host_t *host, int socket_connect, uint16_t node_id);
void litedt_shutdown(litedt_host_t *host);

void litedt_fini(litedt_host_t *host);

#endif
