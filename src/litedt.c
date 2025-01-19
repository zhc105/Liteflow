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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "litedt_internal.h"
#include "config.h"
#include "sha256.h"
#include "util.h"

#define SWND_MAX_SIZE       1073741824
#define CONN_HASH_SIZE      1013
#define CYCLE_LEN           8

#define ZERO_WINDOW_PROBES  120
#define KEEPALIVE_PROBES    18

/* Time constants */
#define CONNECTION_TIMEOUT  120000000
#define TIME_WAIT_EXPIRE    120000000
#define PING_INTERVAL       10000000
#define PING_RETRY_WAIT     1000000

#define KEEPALIVE_TIME      30000000
#define KEEPALIVE_INTERVAL  5000000

#define FAST_ACK_DELAY      20000
#define REACK_DELAY         40000
#define NORMAL_ACK_DELAY    1000000
#define SLOW_ACK_DELAY      60000000

#define IDLE_INTERVAL       1000000
#define SEND_INTERVAL       1000

typedef struct _sack_info {
    uint32_t seq_end;
    uint8_t send_times;
} sack_info_t;

static void
check_connection_state(litedt_host_t *host, litedt_time_t *next_time);

static void
check_retrans_queue(litedt_host_t *host, litedt_time_t *next_time);

static void
check_transmit_queue(litedt_host_t *host, litedt_time_t *next_time);

static litedt_time_t
check_and_send_probes(litedt_host_t *host, litedt_conn_t *conn);

static void
probe_window(litedt_host_t *host, litedt_conn_t *conn, int max_probes);

static void
push_sack_map(litedt_conn_t *conn, uint32_t seq);

static litedt_time_t
get_offline_time(litedt_time_t cur_time);

static int
is_snd_queue_empty(litedt_conn_t *conn);

static int
check_peer_node_id(litedt_host_t *host, uint16_t node_id);

static void
generate_token(uint16_t node_id, uint8_t *payload, size_t length,
    uint8_t out[32]);

static int
validate_token(uint16_t node_id, uint8_t *payload, size_t length,
            uint8_t token[32]);

int socket_sendto(litedt_host_t *host, const void *buf, size_t len,
    const struct sockaddr *addr, socklen_t addr_len, int force)
{
    int ret = -1;
    if (!force && host->pacing_credit < len)
        return LITEDT_SEND_FLOW_CONTROL; // flow control

    if (host->pacing_credit >= len)
        host->pacing_credit -= len;
    else
        host->pacing_credit = 0;
    host->stat.send_bytes_stat += len;

    ret = host->sys_sendto_cb(host, buf, len, addr, addr_len);
    if (ret < (int)len) {
        ++host->stat.send_error;
    }

    return ret;
}

int socket_send(litedt_host_t *host, const void *buf, size_t len, int force)
{
    struct sockaddr *addr = (struct sockaddr *)&host->remote_addr;
    socklen_t addr_len = host->remote_addr_len;
    return socket_sendto(host, buf, len, addr, addr_len, force);
}

void build_litedt_header(litedt_header_t *header, uint8_t cmd, uint32_t flow)
{
    header->ver = LITEDT_VERSION;
    header->mode = 0;   // reserve for now
    header->cmd = cmd;
    header->flow = flow;
}

litedt_conn_t* find_connection(litedt_host_t *host, uint32_t flow)
{
    litedt_conn_t *conn = (litedt_conn_t *)
        timerlist_get(&host->conn_queue, NULL, &flow);
    return conn;
}

int create_connection(
    litedt_host_t *host,
    uint32_t flow,
    uint16_t tunnel_id,
    int state)
{
    int ret = 0;
    litedt_time_t cur_time = get_curtime();
    litedt_conn_t conn_buf = {}, *conn;
    if (find_connection(host, flow) != NULL)
        return LITEDT_RECORD_EXISTS;
    if (queue_get(&host->timewait_queue, &flow) != NULL)
        return LITEDT_RECORD_EXISTS;
    if (state == CONN_ESTABLISHED && host->connect_cb) {
        ret = host->connect_cb(host, flow, tunnel_id);
        if (ret)
            return ret;
    }

    ret = timerlist_push(&host->conn_queue, cur_time, &flow, &conn_buf);
    if (ret != 0) {
        DBG("create connection %u failed: %d\n", flow, ret);
        return ret;
    }
    conn = (litedt_conn_t*)timerlist_get(&host->conn_queue, NULL, &flow);

    conn->state             = state;
    conn->tunnel_id         = tunnel_id;
    conn->flow              = flow;
    conn->swin_start        = 0;
    // use buffer size as default window size, will be update on first ack
    conn->swin_size         = g_config.transport.buffer_size;
    conn->last_probe_time   = cur_time;
    conn->last_sync_time    = cur_time;
    conn->next_sync_time    = cur_time;
    conn->write_seq         = 0;
    conn->send_seq          = 0;
    conn->reack_times       = 0;
    conn->probes_sent       = 0;
    conn->notify_recvnew    = 0;
    conn->notify_recv       = 1;
    conn->notify_send       = 0;
    conn->active_list.next = conn->active_list.prev = NULL;
    treemap_init(
        &conn->sack_map, sizeof(uint32_t), sizeof(sack_info_t), seq_cmp);
    rbuf_init(
        &conn->send_buf,
        g_config.transport.buffer_size / RBUF_BLOCK_SIZE);
    rbuf_init(
        &conn->recv_buf,
        g_config.transport.buffer_size / RBUF_BLOCK_SIZE);
    rbuf_window_info(&conn->recv_buf, &conn->rwin_start, &conn->rwin_size);

    retrans_mod_init(&conn->retrans, host, conn);
    if (g_config.transport.fec_decode || g_config.transport.fec_group_size) {
        conn->fec_enabled = 1;
        ret = fec_mod_init(&conn->fec, host, flow);
        if (ret != 0) {
            LOG("error: FEC init failed: %d\n", ret);
            retrans_mod_fini(&conn->retrans);
            timerlist_del(&host->conn_queue, &flow);
            return ret;
        }
    }

    DBG("create connection %u success\n", flow);
    litedt_mod_evtime(host, conn, cur_time);

    return ret;
}

void release_connection(litedt_host_t *host, uint32_t flow)
{
    litedt_tw_conn_t time_wait;
    litedt_conn_t *conn = find_connection(host, flow);
    if (NULL == conn)
        return;
    if (host->close_cb)
        host->close_cb(host, flow);

    if (conn->active_list.next) {
        // this connection is active
        list_del(&conn->active_list);
    }

    treemap_fini(&conn->sack_map);
    rbuf_fini(&conn->send_buf);
    rbuf_fini(&conn->recv_buf);
    retrans_mod_fini(&conn->retrans);
    if (conn->fec_enabled)
        fec_mod_fini(&conn->fec);
    timerlist_del(&host->conn_queue, &flow);

    time_wait.flow = flow;
    time_wait.close_time = get_curtime();
    queue_append(&host->timewait_queue, &flow, &time_wait);

    DBG("connection %u released\n", flow);
}

void release_all_connections(litedt_host_t *host)
{
    while (!timerlist_empty(&host->conn_queue)) {
        litedt_conn_t *conn = timerlist_top(&host->conn_queue, NULL, NULL);
        release_connection(host, conn->flow);
    }
}

int litedt_init(litedt_host_t *host, uint16_t node_id)
{
    litedt_time_t cur_time = get_curtime();
    int ret = 0;

    bzero(host, sizeof(litedt_host_t));
    host->node_id           = node_id;
    host->peer_node_id      = 0;
    host->mss               = g_config.transport.mtu - LITEDT_MAX_HEADER;
    host->pacing_time       = cur_time;
    host->pacing_credit     = 0;
    host->pacing_rate       = g_config.transport.transmit_rate_init;
    host->snd_cwnd          =
        MAX(2 * (host->pacing_rate / g_config.transport.mtu), 4);
    host->remote_online     = 0;
    host->closed            = 0;
    host->remote_af         = AF_UNSPEC;
    host->remote_addr_len   = 0;
    host->ping_id           = 0;
    host->srtt              = 0;
    host->cur_time          = cur_time;
    host->last_event_time   = cur_time;
    host->next_event_time   = cur_time;
    host->prior_ping_time   = cur_time;
    host->next_ping_time    = cur_time;
    host->offline_time      = get_offline_time(cur_time);

    ret = timerlist_init(&host->conn_queue, CONN_HASH_SIZE, sizeof(uint32_t),
                        sizeof(litedt_conn_t), NULL);
    if (ret != 0)
        return -1;

    ret = queue_init(&host->timewait_queue, CONN_HASH_SIZE, sizeof(uint32_t),
                    sizeof(litedt_tw_conn_t), NULL, 0);
    if (ret != 0) {
        timerlist_fini(&host->conn_queue);
        return -1;
    }

    ret = retrans_queue_init(host);
    if (ret != 0) {
        timerlist_fini(&host->conn_queue);
        queue_fini(&host->timewait_queue);
        return -1;
    }

    INIT_LIST_HEAD(&host->active_queue);

    ctrl_mod_init(&host->ctrl, host);
    filter_init(&host->bw, CYCLE_LEN + 2);
    filter_init(&host->rtt_min, 10);

    host->inflight              = 0;
    host->inflight_bytes        = 0;
    host->delivered             = 1;
    host->delivered_bytes       = 0;
    host->app_limited           = ~0U;
    host->delivered_time        = cur_time;
    host->first_tx_time         = cur_time;
    host->ping_rtt              = 0;
    host->rtt_round             = 0;
    host->next_rtt_delivered    = 0;

    return 0;
}

int litedt_ping_req(litedt_host_t *host)
{
    char buf[80];
    uint8_t token_data[12];
    uint32_t plen;
    litedt_header_t *header = (litedt_header_t *)buf;
    ping_req_t *req = (ping_req_t *)(buf + sizeof(litedt_header_t));

    build_litedt_header(header, LITEDT_PING_REQ, 0);

    req->node_id = host->node_id;
    req->ping_id = ++host->ping_id;
    req->timestamp = get_realtime();
    host->prior_ping_time = req->timestamp;
    memcpy(token_data, &req->ping_id, 4);
    memcpy(token_data + 4, &req->timestamp, 8);
    generate_token(host->node_id, token_data, 12, req->token);

    plen = sizeof(litedt_header_t) + sizeof(ping_req_t);
    socket_send(host, buf, plen, 1);

    return 0;
}

int litedt_ping_rsp(litedt_host_t *host, ping_req_t *req,
    const struct sockaddr *peer_addr, socklen_t addr_len)
{
    char buf[80];
    uint32_t plen;
    litedt_header_t *header = (litedt_header_t *)buf;
    ping_rsp_t *rsp = (ping_rsp_t *)(buf + sizeof(litedt_header_t));

    build_litedt_header(header, LITEDT_PING_RSP, 0);

    rsp->node_id = host->node_id;
    rsp->ping_id = req->ping_id;
    rsp->timestamp = req->timestamp;
    generate_token(host->node_id, req->token, 32, rsp->token);

    plen = sizeof(litedt_header_t) + sizeof(ping_rsp_t);
    socket_sendto(host, buf, plen, peer_addr, addr_len, 1);

    return 0;
}

int litedt_conn_req(litedt_host_t *host, uint32_t flow, uint16_t tunnel_id)
{
    char buf[80];
    uint32_t plen;
    litedt_header_t *header = (litedt_header_t *)buf;
    conn_req_t *req = (conn_req_t *)(buf + sizeof(litedt_header_t));

    build_litedt_header(header, LITEDT_CONNECT_REQ, flow);

    req->tunnel_id = tunnel_id;

    plen = sizeof(litedt_header_t) + sizeof(conn_req_t);
    socket_send(host, buf, plen, 1);

    return 0;
}

int litedt_conn_rsp(litedt_host_t *host, uint32_t flow, int32_t status)
{
    char buf[80];
    uint32_t plen;
    litedt_header_t *header = (litedt_header_t *)buf;
    conn_rsp_t *rsp = (conn_rsp_t *)(buf + sizeof(litedt_header_t));

    build_litedt_header(header, LITEDT_CONNECT_RSP, flow);

    rsp->status = status;

    plen = sizeof(litedt_header_t) + sizeof(conn_rsp_t);
    socket_send(host, buf, plen, 1);

    return 0;
}

int litedt_data_post(litedt_host_t *host, uint32_t flow, uint32_t seq,
                    uint32_t len, uint32_t fec_seq, uint8_t fec_index,
                    int fec_post)
{
    int send_ret = 0, ret;
    char buf[LITEDT_MTU_MAX];
    uint32_t plen;
    litedt_conn_t *conn;
    if (!litedt_online_status(host))
        return LITEDT_CLIENT_OFFLINE;
    if (len > host->mss)
        return LITEDT_PARAMETER_ERROR;
    if ((conn = find_connection(host, flow)) == NULL)
        return LITEDT_RECORD_NOT_FOUND;
    if (seq - conn->swin_start > conn->swin_size
        || seq + len - conn->swin_start > conn->swin_size)
        return LITEDT_SEQ_OUT_OF_RANGE;

    litedt_header_t *header = (litedt_header_t *)buf;
    data_post_t *post = (data_post_t *)(buf + sizeof(litedt_header_t));
    data_conn_t *dcon = (data_conn_t *)(buf + sizeof(litedt_header_t));

    if (conn->state == CONN_REQUEST) {
        build_litedt_header(header, LITEDT_CONNECT_DATA, flow);
        dcon->conn_req.tunnel_id = conn->tunnel_id;
        post = &dcon->data_post;
        plen = sizeof(litedt_header_t) + sizeof(data_conn_t) + len;
    } else {
        build_litedt_header(header, LITEDT_DATA_POST, flow);
        plen = sizeof(litedt_header_t) + sizeof(data_post_t) + len;
    }

    post->seq       = seq;
    post->len       = len;
    post->fec_seq   = fec_seq;
    post->fec_index = fec_index;

    if (len) {
        rbuf_read(&conn->send_buf, seq, post->data, len);
        ++host->stat.data_packet_post;

        ret = create_packet_entry(
            &conn->retrans, seq, len, fec_seq, fec_index);
        if (ret && ret != LITEDT_RECORD_EXISTS) {
            LOG("ERROR: failed to create packet entry: "
                "seq=%u, len=%u, ret=%d\n", seq, len, ret);
        }
    }

    // force send if this is a keepalive packet
    send_ret = socket_send(host, buf, plen, len ? 0 : 1);
    if (send_ret >= 0)
        host->stat.send_bytes_data += plen;

    if (conn->fec_enabled && g_config.transport.fec_group_size && fec_post) {
        fec_push_data(&conn->fec, post);
    }

    if (send_ret == LITEDT_SEND_FLOW_CONTROL)  {
        DBG("Warning: unexpected flow control during sending data!\n");
        return LITEDT_SEND_FLOW_CONTROL;
    }

    return 0;
}

int litedt_data_ack(litedt_host_t *host, uint32_t flow, int ack_list)
{
    char buf[LITEDT_MTU_MAX];
    uint32_t plen;
    litedt_conn_t *conn;
    if ((conn = find_connection(host, flow)) == NULL)
        return LITEDT_RECORD_NOT_FOUND;

    litedt_header_t *header = (litedt_header_t *)buf;
    data_ack_t *ack = (data_ack_t *)(buf + sizeof(litedt_header_t));

    build_litedt_header(header, LITEDT_DATA_ACK, flow);

    ack->win_start = conn->rwin_start;
    ack->win_size  = conn->rwin_size;
    if (ack_list) {
        uint32_t cnt = 0;
        tree_node_t *it;
        for (it = treemap_first(&conn->sack_map); it != NULL;) {
            uint32_t start = *(uint32_t *)treemap_key(&conn->sack_map, it);
            sack_info_t *sack = (sack_info_t *)treemap_value(
                &conn->sack_map, it);
            ack->acks[cnt][0] = start;
            ack->acks[cnt][1] = sack->seq_end;

            it = treemap_next(it);
            if (++sack->send_times >= 2) {
                // each sack range will send twice
                treemap_delete(&conn->sack_map, &start);
            }

            if (++cnt >= g_config.transport.ack_size)
                break;
        }
        ack->ack_size = cnt;
        //DBG("ack_size:%u remain:%u\n", cnt, treemap_size(&conn->sack_map));
    } else {
        ack->ack_size = 0;
    }

    plen = sizeof(litedt_header_t) + sizeof(data_ack_t)
           + sizeof(ack->acks[0]) * ack->ack_size;
    socket_send(host, buf, plen, 1);
    host->stat.send_bytes_ack += plen;

    return 0;
}

int litedt_close_req(litedt_host_t *host, uint32_t flow, uint32_t last_seq)
{
    char buf[80];
    uint32_t plen;
    litedt_header_t *header = (litedt_header_t *)buf;
    close_req_t *req = (close_req_t *)(buf + sizeof(litedt_header_t));

    build_litedt_header(header, LITEDT_CLOSE_REQ, flow);

    req->last_seq = last_seq;
    DBG("send close req: %u\n", last_seq);

    plen = sizeof(litedt_header_t) + sizeof(close_req_t);
    socket_send(host, buf, plen, 1);

    return 0;
}

int litedt_close_rsp(litedt_host_t *host, uint32_t flow)
{
    char buf[80];
    uint32_t plen;
    litedt_header_t *header = (litedt_header_t *)buf;

    build_litedt_header(header, LITEDT_CLOSE_RSP, flow);

    plen = sizeof(litedt_header_t);
    socket_send(host, buf, plen, 1);

    return 0;
}

int litedt_conn_rst(litedt_host_t *host, uint32_t flow)
{
    char buf[80];
    uint32_t plen;
    litedt_header_t *header = (litedt_header_t *)buf;

    build_litedt_header(header, LITEDT_CONNECT_RST, flow);

    plen = sizeof(litedt_header_t);
    socket_send(host, buf, plen, 1);

    return 0;
}

int litedt_connect(litedt_host_t *host, uint32_t flow, uint16_t tunnel_id)
{
    int ret = 0;
    if (!litedt_online_status(host))
        return LITEDT_CLIENT_OFFLINE;
    if (find_connection(host, flow) == NULL)
        ret = create_connection(host, flow, tunnel_id, CONN_REQUEST);
    if (!ret)
        litedt_conn_req(host, flow, tunnel_id);
    return ret;
}

int litedt_close(litedt_host_t *host, uint32_t flow)
{
    litedt_conn_t *conn;
    if ((conn = find_connection(host, flow)) == NULL)
        return LITEDT_RECORD_NOT_FOUND;
    if (conn->state <= CONN_ESTABLISHED) {
        conn->state = CONN_FIN_WAIT;
        litedt_close_req(host, flow, conn->write_seq);

        litedt_time_t event_time = host->last_event_time + NORMAL_ACK_DELAY;
        litedt_mod_evtime(host, conn, event_time);
    } else if (conn->state != CONN_FIN_WAIT) {
        litedt_close_rsp(host, flow);
        release_connection(host, flow);
    }
    return 0;
}

int litedt_send(litedt_host_t *host, uint32_t flow, const char *buf,
                uint32_t len)
{
    litedt_conn_t *conn;
    if ((conn = find_connection(host, flow)) == NULL
        || conn->state >= CONN_FIN_WAIT)
        return LITEDT_RECORD_NOT_FOUND;
    if (rbuf_writable_bytes(&conn->send_buf) < len)
        return LITEDT_NOT_ENOUGH_SPACE;
    if (len > 0) {
        // write to buffer and send later
        rbuf_write_front(&conn->send_buf, buf, len);
        conn->write_seq = rbuf_write_pos(&conn->send_buf);

        if (conn->active_list.next == NULL) {
            // bring connection to active
            list_add_tail(&conn->active_list, &host->active_queue);
        }

        litedt_mod_evtime(host, NULL, host->last_event_time + SEND_INTERVAL);
    }
    return 0;
}

int litedt_recv(litedt_host_t *host, uint32_t flow, char *buf, uint32_t len)
{
    int ret, readable;
    litedt_conn_t *conn;
    if ((conn = find_connection(host, flow)) == NULL)
        return LITEDT_RECORD_NOT_FOUND;
    ret = rbuf_read_front(&conn->recv_buf, buf, len);
    if (ret > 0) {
        rbuf_release(&conn->recv_buf, ret);

        // update recv_wnd after release buffer
        rbuf_window_info(&conn->recv_buf, &conn->rwin_start, &conn->rwin_size);
        readable = rbuf_readable_bytes(&conn->recv_buf);
        conn->rwin_start += readable;
        conn->rwin_size  -= readable;

        // recv windows was changed, send ack to sync up
        litedt_time_t event_time = get_curtime() + FAST_ACK_DELAY;
        conn->reack_times = 2;
        litedt_mod_evtime(host, conn, event_time);
    }
    return ret;
}

int litedt_peek(litedt_host_t *host, uint32_t flow, char *buf, uint32_t len)
{
    int ret;
    litedt_conn_t *conn;
    if ((conn = find_connection(host, flow)) == NULL)
        return LITEDT_RECORD_NOT_FOUND;
    ret = rbuf_read_front(&conn->recv_buf, buf, len);
    return ret;
}

void litedt_recv_skip(litedt_host_t *host, uint32_t flow, uint32_t len)
{
    int readable;
    litedt_conn_t *conn;
    if ((conn = find_connection(host, flow)) == NULL)
        return;
    if (!len)
        return;

    rbuf_release(&conn->recv_buf, len);

    // update recv_wnd after release buffer
    rbuf_window_info(&conn->recv_buf, &conn->rwin_start, &conn->rwin_size);
    readable = rbuf_readable_bytes(&conn->recv_buf);
    conn->rwin_start += readable;
    conn->rwin_size  -= readable;

    // recv windows was changed, send ack to sync up
    litedt_time_t event_time = get_curtime() + FAST_ACK_DELAY;
    conn->reack_times = 2;
    litedt_mod_evtime(host, conn, event_time);
}

int litedt_writable_bytes(litedt_host_t *host, uint32_t flow)
{
    litedt_conn_t *conn;
    if ((conn = find_connection(host, flow)) == NULL)
        return LITEDT_RECORD_NOT_FOUND;
    return rbuf_writable_bytes(&conn->send_buf);
}

int litedt_readable_bytes(litedt_host_t *host, uint32_t flow)
{
    litedt_conn_t *conn;
    if ((conn = find_connection(host, flow)) == NULL)
        return LITEDT_RECORD_NOT_FOUND;
    return rbuf_readable_bytes(&conn->recv_buf);
}

void litedt_set_remote_addr_v4(litedt_host_t *host, char *addr, uint16_t port)
{
    bzero(&host->remote_addr, sizeof(host->remote_addr));
    struct sockaddr_in *saddr = (struct sockaddr_in *)&host->remote_addr;
    saddr->sin_family = AF_INET;
    saddr->sin_port = htons(port);
    inet_pton(AF_INET, addr, &(saddr->sin_addr));
    host->remote_addr_len = sizeof(struct sockaddr_in);
    host->remote_af = AF_INET;
}

void litedt_set_remote_addr_v6(litedt_host_t *host, char *addr, uint16_t port)
{
    bzero(&host->remote_addr, sizeof(host->remote_addr));
    struct sockaddr_in6 *saddr = (struct sockaddr_in6 *)&host->remote_addr;
    saddr->sin6_family = AF_INET6;
    saddr->sin6_port = htons(port);
    inet_pton(AF_INET6, addr, &(saddr->sin6_addr));
    host->remote_addr_len = sizeof(struct sockaddr_in6);
    host->remote_af = AF_INET6;
}


int litedt_set_remote_addr(litedt_host_t *host, const struct sockaddr *addr,
    socklen_t addr_len)
{
    if (addr_len > sizeof(struct sockaddr_storage))
        return -1;

    host->remote_af = addr->sa_family;
    memcpy(&host->remote_addr, addr, addr_len);
    host->remote_addr_len = addr_len;
    return 0;
}

void litedt_set_ext(litedt_host_t *host, void *ext)
{
    host->ext = ext;
}

void litedt_set_sys_sendto_cb(litedt_host_t *host, litedt_sys_sendto_fn *cb)
{
    host->sys_sendto_cb = cb;
}

void litedt_set_online_cb(litedt_host_t *host, litedt_online_fn *online_cb)
{
    host->online_cb = online_cb;
}

void litedt_set_connect_cb(litedt_host_t *host, litedt_connect_fn *conn_cb)
{
    host->connect_cb = conn_cb;
}

void litedt_set_close_cb(litedt_host_t *host, litedt_close_fn *close_cb)
{
    host->close_cb = close_cb;
}

void litedt_set_receive_cb(litedt_host_t *host, litedt_receive_fn *recv_cb)
{
    host->receive_cb = recv_cb;
}

void litedt_set_send_cb(litedt_host_t *host, litedt_send_fn *send_cb)
{
    host->send_cb = send_cb;
}

void litedt_set_event_time_cb(litedt_host_t *host, litedt_event_time_fn *cb)
{
    host->event_time_cb = cb;
}

void litedt_set_notify_recv(litedt_host_t *host, uint32_t flow, int notify)
{
    litedt_conn_t *conn = find_connection(host, flow);
    if (conn) {
        conn->notify_recv = notify;
    }
}

void litedt_set_notify_recvnew(litedt_host_t *host, uint32_t flow, int notify)
{
    litedt_conn_t *conn = find_connection(host, flow);
    if (conn) {
        conn->notify_recvnew = notify;
    }
}

void litedt_set_notify_send(litedt_host_t *host, uint32_t flow, int notify)
{
    litedt_conn_t *conn = find_connection(host, flow);
    if (conn) {
        conn->notify_send = notify;
    }
}

int litedt_on_ping_req(litedt_host_t *host, ping_req_t *req,
    const struct sockaddr *peer_addr, socklen_t addr_len)
{
    uint8_t token_data[12];

    /* Validate Token */
    if (g_config.transport.token_expire) {
        litedt_time_t real_time = get_realtime();
        litedt_time_t token_time = req->timestamp;
        litedt_time_t exp = (litedt_time_t)
            g_config.transport.token_expire * USEC_PER_SEC;
        if (token_time - real_time > exp || real_time - token_time > exp) {
            host->stat.io_event_reject++;
            return 0;
        }   
    }

    memcpy(token_data, &req->ping_id, 4);
    memcpy(token_data + 4, &req->timestamp, 8);
    if (!validate_token(req->node_id, token_data, 12, req->token)) {
        host->stat.io_event_reject++;
        return 0;
    }

    /* Print warning message if peer node_id was changed*/
    if (check_peer_node_id(host, req->node_id))
        return 0;

    litedt_ping_rsp(host, req, peer_addr, addr_len);
    return 0;
}

int litedt_on_ping_rsp(litedt_host_t *host, ping_rsp_t *rsp)
{
    uint8_t temp_token[32], token_data[12];
    litedt_time_t real_time = get_realtime();
    litedt_time_t ping_rtt;
    if (rsp->ping_id != host->ping_id
        || rsp->timestamp != host->prior_ping_time)
        return 0;
    if (!rsp->node_id || check_peer_node_id(host, rsp->node_id))
        return 0;

    /* Validate Token */
    if (g_config.transport.token_expire) {
        litedt_time_t token_time = rsp->timestamp;
        litedt_time_t exp = (litedt_time_t)
            g_config.transport.token_expire * USEC_PER_SEC;
        if (token_time - real_time > exp || real_time - token_time > exp) {
            host->stat.io_event_reject++;
            return 0;
        }
    }

    memcpy(token_data, &rsp->ping_id, 4);
    memcpy(token_data + 4, &rsp->timestamp, 8);
    generate_token(host->node_id, token_data, 12, temp_token);
    if (!validate_token(rsp->node_id, temp_token, 32, rsp->token)) {
        host->stat.io_event_reject++;
        return 0;
    }

    if (!host->peer_node_id)
        host->peer_node_id = rsp->node_id;

    ++host->ping_id;
    ping_rtt = real_time - rsp->timestamp;
    host->ping_rtt = (uint32_t)ping_rtt;
    host->next_ping_time = host->cur_time + PING_INTERVAL;
    host->offline_time = get_offline_time(host->cur_time);
    DBG("ping rsp, rtt=%u\n", host->ping_rtt);

    if (!host->remote_online) {
        char ip[ADDRESS_MAX_LEN];
        uint16_t port;
        uint16_t node = rsp->node_id;

        get_ip_port((struct sockaddr *)&host->remote_addr, ip, ADDRESS_MAX_LEN,
            &port);
        host->remote_online = 1;
        host->pacing_time = host->cur_time; // reset pacing time
        LOG("Remote host[%u] [%s]:%u is online and active\n", node, ip, port);

        if (host->online_cb)
            host->online_cb(host, 1);
        if (!timerlist_empty(&host->conn_queue)) {
            litedt_time_t event_time = host->last_event_time + SEND_INTERVAL;
            litedt_mod_evtime(host, NULL, event_time);
        }
    }

    return 0;
}

int litedt_on_conn_req(
    litedt_host_t *host, uint32_t flow, conn_req_t *req, int no_rsp)
{
    int ret = 0;
    litedt_conn_t *conn = find_connection(host, flow);
    if (conn) {
        litedt_conn_rsp(host, flow, 0);
        return 0;
    }

    ret = create_connection(host, flow, req->tunnel_id, CONN_ESTABLISHED);
    if (ret == 0) {
        if (!no_rsp) {
            litedt_conn_rsp(host, flow, ret);
            litedt_data_ack(host, flow, 0);
        }
    } else {
        litedt_conn_rsp(host, flow, ret);
    }

    return ret;
}

int litedt_on_conn_rsp(litedt_host_t *host, uint32_t flow, conn_rsp_t *rsp)
{
    litedt_conn_t *conn = find_connection(host, flow);
    if (NULL == conn)
        return LITEDT_RECORD_NOT_FOUND;
    if (0 == rsp->status) {
        if (conn->state == CONN_REQUEST) {
            conn->state = CONN_ESTABLISHED;
            DBG("connection %u established\n", flow);
        }

        // send ack when connection established
        litedt_data_ack(host, flow, 0);
    } else {
        release_connection(host, flow);
    }

    return 0;
}

int litedt_on_data_recv(litedt_host_t *host, uint32_t flow, data_post_t *data,
                        int fec_recv)
{
    int ret, readable = 0;
    uint32_t dseq = data->seq;
    uint16_t dlen = data->len;
    litedt_time_t cur_time = host->cur_time;
    litedt_conn_t *conn = find_connection(host, flow);
    if (NULL == conn)
        return LITEDT_RECORD_NOT_FOUND;
    if (conn->state == CONN_REQUEST)
        conn->state = CONN_ESTABLISHED;

    if (!data->len) {
        // This is a keepalive packet, response ack immediately
        litedt_data_ack(host, flow, 1);
        conn->reack_times = 1;
        litedt_mod_evtime(host, conn, cur_time + REACK_DELAY);
        return 0;
    }

    ret = rbuf_write(&conn->recv_buf, dseq, data->data, dlen);
    if (ret == 1 || ret == RBUF_OUT_OF_RANGE)
        ++host->stat.dup_packet_recv;
    if (ret >= 0) {
        rbuf_window_info(&conn->recv_buf, &conn->rwin_start, &conn->rwin_size);
        readable = rbuf_readable_bytes(&conn->recv_buf);
        conn->rwin_start += readable;
        conn->rwin_size  -= readable;
        push_sack_map(conn, dseq);

        if (conn->fec_enabled && g_config.transport.fec_decode) {
            if (!fec_recv) {
                fec_insert_data(&conn->fec, data);
                // readable bytes of recv_buf might be changed
                readable = rbuf_readable_bytes(&conn->recv_buf);
            }
            fec_checkpoint(&conn->fec, conn->rwin_start);
        }
    }

    if (treemap_size(&conn->sack_map) >= g_config.transport.ack_size) {
        // send ack msg immediately
        litedt_data_ack(host, flow, 1);
        while (g_config.transport.ack_size
            && treemap_size(&conn->sack_map) >= g_config.transport.ack_size) {
            // ack list is still full, send ack msg again
            litedt_data_ack(host, flow, 1);
        }
        conn->reack_times = 1;
        litedt_mod_evtime(host, conn, cur_time + REACK_DELAY);
    } else {
        // delay sending ack packet
        litedt_time_t next_time = MIN(conn->next_sync_time,
                                    cur_time + FAST_ACK_DELAY);
        conn->reack_times = 2;
        litedt_mod_evtime(host, conn, next_time);
    }

    if ((conn->notify_recv || conn->notify_recvnew)
        && host->receive_cb && readable > 0
        && conn->state != CONN_FIN_WAIT && conn->state <= CONN_CLOSED)
        host->receive_cb(host, flow, readable);

    return 0;
}

int litedt_on_data_ack(litedt_host_t *host, uint32_t flow, data_ack_t *ack)
{
    uint32_t i;
    uint32_t delivered;
    rate_sample_t rs = { .prior_delivered = 0 };
    litedt_time_t cur_time = host->cur_time;
    litedt_conn_t *conn = find_connection(host, flow);
    if (NULL == conn)
        return LITEDT_RECORD_NOT_FOUND;
    if (conn->state == CONN_REQUEST)
        conn->state = CONN_ESTABLISHED;

    delivered = host->delivered;

    for (i = 0; i < ack->ack_size; i++) {
        uint32_t start = ack->acks[i][0];
        uint32_t end = ack->acks[i][1];
        release_packet_range(&conn->retrans, start, end, &rs);
    }

    if (LESS_EQUAL(conn->swin_start, ack->win_start) &&
        LESS_EQUAL(ack->win_start, conn->send_seq)) {
        uint32_t release_size, sendbuf_start, sendbuf_size;
        conn->last_sync_time = cur_time;
        conn->probes_sent = 0;
        conn->swin_start = ack->win_start;
        conn->swin_size = MIN(ack->win_size, SWND_MAX_SIZE);

        rbuf_window_info(&conn->send_buf, &sendbuf_start, &sendbuf_size);
        release_size = conn->swin_start - sendbuf_start;
        if (release_size > 0)
            rbuf_release(&conn->send_buf, release_size);
        retrans_checkpoint(&conn->retrans, conn->swin_start, &rs);
    }

    generate_bandwidth(&conn->retrans, &rs, host->delivered - delivered);
    ctrl_io_event(&host->ctrl, &rs);

    if (conn->notify_send && host->send_cb
        && conn->state <= CONN_ESTABLISHED) {
        int writable = rbuf_writable_bytes(&conn->send_buf);
        if (writable > 0)
            host->send_cb(host, flow, writable);
    }

    return 0;
}

int litedt_on_close_req(litedt_host_t *host, uint32_t flow, close_req_t *req)
{
    litedt_time_t cur_time = host->cur_time;
    litedt_conn_t *conn = find_connection(host, flow);
    if (NULL == conn) {
        litedt_close_rsp(host, flow);
        return 0;
    }
    DBG("recv close req: end_seq=%u\n", req->last_seq);

    if (conn->state == CONN_FIN_WAIT) {
        release_connection(host, flow);
        litedt_close_rsp(host, flow);
    } else if (conn->state != CONN_CLOSED) {
        uint32_t win_start, win_len, readable;
        conn->state = CONN_CLOSE_WAIT;
        rbuf_window_info(&conn->recv_buf, &win_start, &win_len);
        readable = rbuf_readable_bytes(&conn->recv_buf);
        if (win_start + readable == req->last_seq) {
            conn->state = CONN_CLOSED;
            litedt_close_rsp(host, flow);
            litedt_mod_evtime(host, conn, cur_time);
        } else {
            litedt_mod_evtime(host, conn, cur_time + NORMAL_ACK_DELAY);
        }
    }

    return 0;
}

int litedt_on_close_rsp(litedt_host_t *host, uint32_t flow)
{
    litedt_conn_t *conn = find_connection(host, flow);
    if (NULL == conn)
        return 0;
    if (conn->state == CONN_FIN_WAIT)
        release_connection(host, flow);
    return 0;
}

int litedt_on_conn_rst(litedt_host_t *host, uint32_t flow)
{
    litedt_conn_t *conn = find_connection(host, flow);
    if (NULL == conn)
        return 0;

    if (conn->state == CONN_FIN_WAIT) {
        release_connection(host, flow);
    } else {
        conn->state = CONN_CLOSED;
        litedt_mod_evtime(host, conn, host->cur_time);
    }

    DBG("connection %u reset\n", flow);
    return 0;
}

int litedt_on_data_fec(litedt_host_t *host, uint32_t flow, data_fec_t *fec)
{
    litedt_conn_t *conn = find_connection(host, flow);
    if (NULL == conn)
        return LITEDT_RECORD_NOT_FOUND;
    if (!conn->fec_enabled || !g_config.transport.fec_decode)
        return 0;

    if (conn->state == CONN_REQUEST)
        conn->state = CONN_ESTABLISHED;
    if (conn->state != CONN_ESTABLISHED && conn->state != CONN_CLOSE_WAIT)
        return 0;

    fec_insert_sum(&conn->fec, fec);
    fec_checkpoint(&conn->fec, conn->rwin_start);

    return 0;
}

void litedt_mod_evtime(litedt_host_t *host, litedt_conn_t *conn,
                    litedt_time_t event_time)
{
    if (conn != NULL && event_time < conn->next_sync_time) {
        conn->next_sync_time = event_time;
        timerlist_moveup(&host->conn_queue, event_time, &conn->flow);
    }
    if (event_time < host->next_event_time) {
        litedt_time_t cur_time = get_curtime();
        litedt_time_t after = event_time > cur_time
                            ? event_time - cur_time : 0;
        host->next_event_time = event_time;
        if (host->event_time_cb)
            host->event_time_cb(host, after);
    }
}

void litedt_io_event(litedt_host_t *host, char *buf, size_t recv_len,
    const struct sockaddr *from_addr, socklen_t from_addr_len)
{
    int ret = 0, status;
    uint32_t flow;
    int hlen = sizeof(litedt_header_t);
    litedt_header_t *header = (litedt_header_t *)buf;
    host->cur_time = get_curtime();
    host->stat.io_event++;
    host->stat.recv_bytes_stat += recv_len;

    if (recv_len < hlen || header->ver != LITEDT_VERSION) {
        host->stat.io_event_wrong_packet++;
        return;
    }   

    ret = 0;
    flow = header->flow;
    switch (header->cmd) {
    case LITEDT_PING_REQ:
        if (recv_len < hlen + (int)sizeof(ping_req_t))
            break;
        ret = litedt_on_ping_req(host, (ping_req_t *)(buf + hlen),
            from_addr, from_addr_len);
        break;
    case LITEDT_PING_RSP:
        if (recv_len < hlen + (int)sizeof(ping_rsp_t))
            break;
        ret = litedt_on_ping_rsp(host, (ping_rsp_t *)(buf + hlen));
        break;
    case LITEDT_CONNECT_REQ:
        if (recv_len < hlen + (int)sizeof(conn_req_t))
            break;
        litedt_on_conn_req(host, flow, (conn_req_t *)(buf + hlen), 0);
        break;
    case LITEDT_CONNECT_RSP:
        if (recv_len < hlen + (int)sizeof(conn_rsp_t))
            break;
        ret = litedt_on_conn_rsp(host, flow, (conn_rsp_t *)(buf + hlen));
        break;
    case LITEDT_DATA_POST: {
            data_post_t *data;
            data = (data_post_t *)(buf + hlen);
            if (recv_len < hlen + (int)sizeof(data_post_t))
                break;
            if (recv_len < hlen + (int)sizeof(data_post_t) + data->len)
                break;
            host->stat.recv_bytes_data += recv_len;
            ret = litedt_on_data_recv(host, flow, data, 0);
            break;
        }
    case LITEDT_DATA_ACK: {
            data_ack_t *ack;
            ack = (data_ack_t *)(buf + hlen);
            if (recv_len < hlen + (int)sizeof(data_ack_t))
                break;
            if (recv_len < hlen + (int)sizeof(data_ack_t)
                + ack->ack_size * (int)sizeof(uint32_t) * 2)
                break;
            host->stat.recv_bytes_ack += recv_len;
            ret = litedt_on_data_ack(host, flow, ack);
            break;
        }
    case LITEDT_CLOSE_REQ:
        if (recv_len < hlen + (int)sizeof(close_req_t))
            break;
        litedt_on_close_req(host, flow, (close_req_t *)(buf + hlen));
        break;
    case LITEDT_CLOSE_RSP:
        litedt_on_close_rsp(host, flow);
        break;
    case LITEDT_CONNECT_RST:
        litedt_on_conn_rst(host, flow);
        break;
    case LITEDT_CONNECT_DATA: {
            data_conn_t *dcon;
            dcon = (data_conn_t *)(buf + hlen);
            if (recv_len < hlen + (int)sizeof(data_conn_t))
                break;
            if (recv_len < hlen + (int)sizeof(data_conn_t) +
                dcon->data_post.len)
                break;
            status = litedt_on_conn_req(host, flow, &dcon->conn_req, 1);
            if (status == 0) {
                ret = litedt_on_data_recv(host, flow, &dcon->data_post, 0);
            }
            break;
        }
    case LITEDT_DATA_FEC: {
            data_fec_t *fec = (data_fec_t *)(buf + hlen);
            if (recv_len < hlen + (int)sizeof(data_fec_t))
                break;
            if (recv_len < hlen + (int)sizeof(data_fec_t) + fec->fec_len)
                break;
            ret = litedt_on_data_fec(host, flow, fec);
            break;
        }

    default:
        break;
    }

    if (ret != 0) {
        // connection error or closed already, send rst to client
        if (ret != LITEDT_RECORD_NOT_FOUND ||
            queue_get(&host->timewait_queue, &flow) == NULL) {
            LOG("Connection %u error, reset\n", flow);
        }
        litedt_conn_rst(host, flow);
    }
}

litedt_time_t litedt_time_event(litedt_host_t *host)
{
    int ret = 0, flow_ctrl = 1;
    litedt_time_t cur_time = host->cur_time = get_curtime();
    litedt_time_t pacing_interval, next_time = cur_time + IDLE_INTERVAL;
    queue_node_t *q_it, *q_start;

    if (host->closed)
        return 0;

    // send ping request
    if (cur_time >= host->next_ping_time) {
        litedt_ping_req(host);
        host->next_ping_time = cur_time + PING_RETRY_WAIT;
    }

    // remove expired TIME_WAIT status flow
    while (!queue_empty(&host->timewait_queue)) {
        litedt_tw_conn_t *twait;
        litedt_time_t expire_time;
        uint32_t flow;

        q_it = queue_first(&host->timewait_queue);
        twait = (litedt_tw_conn_t *)queue_value(&host->timewait_queue, q_it);
        expire_time = twait->close_time + TIME_WAIT_EXPIRE;
        if (cur_time < expire_time) {
            next_time = MIN(next_time, expire_time);
            break;
        }
        flow = twait->flow;
        queue_del(&host->timewait_queue, &flow);
    }

    if (cur_time >= host->offline_time) {
        char     ip[ADDRESS_MAX_LEN];
        uint16_t port;
        uint16_t node = host->peer_node_id;

        get_ip_port((struct sockaddr *)&host->remote_addr, ip, ADDRESS_MAX_LEN,
            &port);
        LOG("Remote host[%u] [%s]:%u is offline\n", node, ip, port);

        host->offline_time = get_offline_time(cur_time);
        release_all_connections(host);
        host->remote_online = 0;
        if (host->online_cb)
            host->online_cb(host, 0);

        return -1;
    } else {
        next_time = MIN(next_time, host->offline_time);
    }

    if (!host->remote_online)
        goto time_event_exit;

    pacing_interval = MAX(
        (litedt_time_t)g_config.transport.mtu * (litedt_time_t)USEC_PER_SEC
            / (litedt_time_t)host->pacing_rate,
        (litedt_time_t)SEND_INTERVAL);

    if (cur_time >= host->pacing_time + pacing_interval) {
        host->pacing_credit += (uint64_t)host->pacing_rate
            * (cur_time - host->pacing_time) / USEC_PER_SEC;
        host->pacing_time = cur_time;
    }

    ctrl_time_event(&host->ctrl);
    check_connection_state(host, &next_time);
    check_retrans_queue(host, &next_time);
    check_transmit_queue(host, &next_time);

    if (next_time < cur_time + SEND_INTERVAL)
        next_time = cur_time + SEND_INTERVAL;
    host->last_event_time = cur_time;
    host->next_event_time = next_time;

time_event_exit:
    // calculate interval for next event time
    cur_time = get_curtime();
    if (next_time <= cur_time)
        return 0;   // need to call this function again ASAP.

    return next_time - cur_time;
}

litedt_stat_t* litedt_get_stat(litedt_host_t *host)
{
    host->stat.connection_num   = timerlist_size(&host->conn_queue);
    host->stat.timewait_num     = queue_size(&host->timewait_queue);
    host->stat.fec_group_size   = g_config.transport.fec_group_size;
    host->stat.rtt              = host->ping_rtt;
    host->stat.bandwidth        = filter_get(&host->bw);
    host->stat.inflight         = host->inflight;
    host->stat.cwnd             = host->snd_cwnd;
    return &host->stat;
}

void litedt_clear_stat(litedt_host_t *host)
{
    memset(&host->stat, 0, sizeof(litedt_stat_t));
}

int litedt_online_status(litedt_host_t *host)
{
    return host->remote_online && !host->closed;
}

uint16_t litedt_peer_node_id(litedt_host_t *host)
{
    return host->peer_node_id;
}

void* litedt_ext(litedt_host_t *host)
{
    return host->ext;
}

socklen_t litedt_remote_addr(litedt_host_t *host, struct sockaddr *addr,
    socklen_t *addr_len)
{
    memcpy(addr, &host->remote_addr, host->remote_addr_len);
    return host->remote_addr_len;
}

int litedt_is_closed(litedt_host_t *host)
{
    return !!host->closed;
}

const char* litedt_ctrl_mode_name(litedt_host_t *host)
{
    return get_ctrl_mode_name(&host->ctrl);
}

void litedt_fini(litedt_host_t *host)
{
    release_all_connections(host);
    retrans_queue_fini(host);
    queue_fini(&host->timewait_queue);
    timerlist_fini(&host->conn_queue);
    host->closed = 1;
}

static void
check_connection_state(litedt_host_t *host, litedt_time_t *next_time)
{
    litedt_time_t event_time, cur_time = host->cur_time;

    while (!timerlist_empty(&host->conn_queue)) {
        litedt_conn_t *conn = (litedt_conn_t *)
            timerlist_top(&host->conn_queue, &event_time, NULL);
        if (event_time > cur_time)
            break;
        if (cur_time - conn->last_sync_time > CONNECTION_TIMEOUT) {
            release_connection(host, conn->flow);
            continue;
        }

        litedt_time_t probe_time = check_and_send_probes(host, conn);

        // send ack msg to synchronize data window
        if (cur_time >= conn->next_sync_time) {
            switch (conn->state) {
            case CONN_REQUEST:
                litedt_conn_req(host, conn->flow, conn->tunnel_id);
                break;
            case CONN_ESTABLISHED:
                if (conn->fec_enabled && g_config.transport.fec_group_size)
                    fec_post(&conn->fec);
                litedt_data_ack(host, conn->flow, conn->reack_times > 0);
                break;
            case CONN_FIN_WAIT:
                if (conn->fec_enabled && g_config.transport.fec_group_size)
                    fec_post(&conn->fec);
                litedt_close_req(host, conn->flow, conn->write_seq);
                break;
            case CONN_CLOSE_WAIT:
                litedt_data_ack(host, conn->flow, conn->reack_times > 0);
                break;
            default: {
                    uint32_t readable = rbuf_readable_bytes(&conn->recv_buf);
                    if (!readable) {
                        release_connection(host, conn->flow);
                        continue;
                    }
                }
            }
            if (conn->reack_times > 1) {
                // send ack msg again after 40ms
                --conn->reack_times;
                conn->next_sync_time = cur_time + REACK_DELAY;
            } else {
                conn->reack_times = 0;
                conn->next_sync_time = cur_time + (
                    conn->state == CONN_ESTABLISHED
                    ? SLOW_ACK_DELAY
                    : NORMAL_ACK_DELAY);
            }
        }

        uint32_t readable = 0, writable = 0;
        // check recv/send buffer and notify user
        if (conn->notify_recv && host->receive_cb
            && conn->state != CONN_FIN_WAIT && conn->state <= CONN_CLOSED) {
            readable = rbuf_readable_bytes(&conn->recv_buf);
            if (readable > 0)
                host->receive_cb(host, conn->flow, readable);
        }
        if (conn->notify_send && host->send_cb
            && conn->state <= CONN_ESTABLISHED) {
            writable = rbuf_writable_bytes(&conn->send_buf);
            if (writable > 0)
                host->send_cb(host, conn->flow, writable);
        }

        if (readable || writable) {
            // event mode is level triggered and send/recv pipe contains data
            timerlist_resched_top(&host->conn_queue, cur_time + 1);
        } else {
            litedt_time_t next_time = conn->next_sync_time;
            if (probe_time > 0 && probe_time < conn->next_sync_time)
                next_time = probe_time;
            timerlist_resched_top(&host->conn_queue, next_time);
        }
    }

    if (!timerlist_empty(&host->conn_queue)) {
        timerlist_top(&host->conn_queue, &event_time, NULL);
        *next_time = MIN(*next_time, event_time);
    }
}

static void
check_retrans_queue(litedt_host_t *host, litedt_time_t *next_time)
{
    litedt_time_t cur_time = host->cur_time;
    int ret = 0;
    litedt_conn_t *conn;

    list_for_each_entry(conn, &host->active_queue, active_list) {
        ret = retrans_time_event(&conn->retrans, cur_time);
        if (ret != 0)
            break;
        *next_time = MIN(*next_time,
                        retrans_next_event_time(&conn->retrans, cur_time));
    }

    retrans_queue_send(host);   // send packets from retransmission queue

    if (!timerlist_empty(&host->retrans_queue)) {
        // packets remaining in retransmission queue
        uint32_t predict = retrans_packet_length(host) + LITEDT_MAX_HEADER;
        litedt_time_t next_send_time = host->pacing_time +
            ((litedt_time_t)predict * (litedt_time_t)USEC_PER_SEC
                / (litedt_time_t)host->pacing_rate);
        *next_time = MIN(*next_time, next_send_time);
    }
}

static void
check_transmit_queue(litedt_host_t *host, litedt_time_t *next_time)
{
    litedt_time_t cur_time = host->cur_time;
    int app_limited = 1, ret = 0;
    litedt_conn_t *conn, *next;
    
    #define STOP_SENDING_APP_LIMITED 0
    #define STOP_SENDING_RATE_LIMITED 1
    #define STOP_SENDING_CWND_LIMITED 2
    int stop_sending = STOP_SENDING_APP_LIMITED;

    list_for_each_entry_safe(conn, next, &host->active_queue, active_list) {
        if (host->inflight >= host->snd_cwnd) {
            stop_sending = STOP_SENDING_CWND_LIMITED;
            app_limited = 0;
        }

        if (!app_limited) {
            // move list head
            // next time we start sending from current connection
            if (conn->active_list.prev != &host->active_queue)
                list_move(&host->active_queue, conn->active_list.prev);
            break;
        }

        if (conn->state > CONN_FIN_WAIT) {
            list_del(&conn->active_list);
            conn->active_list.next = conn->active_list.prev = NULL;
            continue;
        }

        // check send buffer and post data to network
        while (conn->write_seq != conn->send_seq) {
            uint32_t fec_seq = 0;
            uint8_t fec_index = 0;
            uint32_t bytes = MIN(conn->write_seq - conn->send_seq, host->mss);
            uint32_t swin_end = conn->swin_start + conn->swin_size;
            if (bytes > swin_end - conn->send_seq)
                bytes = swin_end - conn->send_seq;
            if (0 == bytes)
                break;

            uint32_t predict = bytes + LITEDT_MAX_HEADER;
            if (predict > host->pacing_credit) {
                litedt_time_t next_send_time = host->pacing_time
                    + ((litedt_time_t)predict * (litedt_time_t)USEC_PER_SEC
                        / (litedt_time_t)host->pacing_rate);
                *next_time = MIN(*next_time, next_send_time);
                app_limited = 0;
                stop_sending = STOP_SENDING_RATE_LIMITED;
                break;
            }

            if (host->inflight >= host->snd_cwnd) {
                app_limited = 0;
                stop_sending = STOP_SENDING_CWND_LIMITED;
                break;
            }

            if (conn->fec_enabled && g_config.transport.fec_group_size)
                get_fec_header(&conn->fec, &fec_seq, &fec_index);

            ret = litedt_data_post(host, conn->flow, conn->send_seq, bytes,
                                fec_seq, fec_index, 1);
            if (!ret) {
                conn->send_seq += bytes;
            } else {
                if (ret == LITEDT_SEND_FLOW_CONTROL) {
                    *next_time = MIN(*next_time, cur_time + SEND_INTERVAL);
                    app_limited = 0;
                    stop_sending = STOP_SENDING_RATE_LIMITED;
                }
                break;
            }
        }

        if (is_snd_queue_empty(conn)) {
            // all data sent, this connection is inactive now
            list_del(&conn->active_list);
            conn->active_list.next = conn->active_list.prev = NULL;
        }
    }

    if (app_limited) {
        host->app_limited = (host->delivered + host->inflight) ? : 1;
    }

    if (app_limited || host->inflight >= host->snd_cwnd) {
        host->pacing_credit = 0; // clear credit to prevent traffic spike
    }

    if (stop_sending == STOP_SENDING_APP_LIMITED) {
        host->stat.time_event_app_limited++;
    } else if (stop_sending == STOP_SENDING_RATE_LIMITED) {
        host->stat.time_event_rate_limited++;
    } else {
        host->stat.time_event_cwnd_limited++;
    }
}

static litedt_time_t
check_and_send_probes(litedt_host_t *host, litedt_conn_t *conn)
{
    litedt_time_t cur_time = host->cur_time, next_time = -1;
    if (conn->state >= CONN_CLOSE_WAIT)
        return -1;

    if (is_snd_queue_empty(conn)) {
        // output window is empty, send keepalive probes
        if (cur_time - conn->last_sync_time >= KEEPALIVE_TIME) {
            if (cur_time - conn->last_probe_time >= KEEPALIVE_INTERVAL)
                probe_window(host, conn, KEEPALIVE_PROBES);
            next_time = conn->last_probe_time + KEEPALIVE_INTERVAL;
        } else {
            next_time = conn->last_sync_time + KEEPALIVE_TIME;
        }
    } else if (!conn->swin_size) {
        // remote host advertises a zero window size for its input window
        // send zero window probes
        if (cur_time - conn->last_probe_time >= IDLE_INTERVAL)
            probe_window(host, conn, ZERO_WINDOW_PROBES);
        next_time = conn->last_probe_time + IDLE_INTERVAL;
    }

    return next_time;
}

static void
probe_window(litedt_host_t *host, litedt_conn_t *conn, int max_probes)
{
    if (conn->probes_sent < max_probes) {
        litedt_data_post(host, conn->flow, conn->send_seq, 0, 0, 0, 0);
        ++conn->probes_sent;
    }
    conn->last_probe_time = host->cur_time;
}

static void push_sack_map(litedt_conn_t *conn, uint32_t seq)
{
    int ret = 0;
    sack_info_t sack = {};
    if (!LESS_EQUAL(conn->rwin_start, seq))
        return;

    /* remove expired sack record */
    tree_node_t *it = treemap_first(&conn->sack_map);
    while (it != NULL) {
        uint32_t sack_seq = *(uint32_t *)treemap_key(&conn->sack_map, it);
        sack_info_t *sack_info = (sack_info_t *)treemap_value(
            &conn->sack_map, it);
        if (LESS_EQUAL(conn->rwin_start, sack_seq))
            break;

        sack.seq_end = sack_info->seq_end;
        sack.send_times = sack_info->send_times;
        treemap_delete(&conn->sack_map, &sack_seq);
        if (!LESS_EQUAL(sack.seq_end, conn->rwin_start)) {
            treemap_insert(&conn->sack_map, &conn->rwin_start, &sack);
            break;
        }

        it = treemap_first(&conn->sack_map);
    }

    treemap_t *rmap = rbuf_range_map(&conn->recv_buf);
    it = treemap_upper_bound(rmap, &seq);
    it = (it == NULL ? treemap_last(rmap) : treemap_prev(it));
    uint32_t start = *(uint32_t *)treemap_key(rmap, it);
    sack.seq_end = *(uint32_t *)treemap_value(rmap, it);
    sack.send_times = 0;

    it = treemap_upper_bound(&conn->sack_map, &start);
    it = (it == NULL ? treemap_last(&conn->sack_map) : treemap_prev(it));
    if (it != NULL) {
        uint32_t rstart = *(uint32_t *)treemap_key(&conn->sack_map, it);
        uint32_t rend = ((sack_info_t *)treemap_value(
            &conn->sack_map, it))->seq_end;
        if (LESS_EQUAL(sack.seq_end, rend))
            return; // sack duplicated
        if (LESS_EQUAL(rstart, start) && LESS_EQUAL(start, rend)) {
            sack_info_t *prev = (sack_info_t *)treemap_value(
                &conn->sack_map, it);
            if (LESS_EQUAL(sack.seq_end, prev->seq_end))
                return;
            prev->seq_end = sack.seq_end;
            prev->send_times = 0;
        } else {
            ret = treemap_insert2(&conn->sack_map, &start, &sack, &it);
        }
    } else {
        ret = treemap_insert2(&conn->sack_map, &start, &sack, &it);
    }
    if (-1 == ret)
        return;

    sack_info_t *pend = (sack_info_t *)treemap_value(&conn->sack_map, it);
    for (tree_node_t *next = treemap_next(it); next != NULL;
        next = treemap_next(it)) {
        uint32_t nstart = *(uint32_t *)treemap_key(&conn->sack_map, next);
        sack_info_t *nend = (sack_info_t *)treemap_value(
            &conn->sack_map, next);
        if (LESS_EQUAL(nstart, pend->seq_end)) {
            if (LESS_EQUAL(pend->seq_end, nend->seq_end))
                pend->seq_end = nend->seq_end;
            treemap_delete(&conn->sack_map, &nstart);
        } else {
            break;
        }
    }
}

static litedt_time_t get_offline_time(litedt_time_t cur_time)
{
    return cur_time + g_config.transport.offline_timeout * USEC_PER_SEC;
}

static int is_snd_queue_empty(litedt_conn_t *conn)
{
    return conn->write_seq == conn->send_seq &&
        !retrans_list_size(&conn->retrans);
}

static int check_peer_node_id(litedt_host_t *host, uint16_t node_id)
{
    char ip[ADDRESS_MAX_LEN];
    uint16_t port;

    if (host->peer_node_id && host->peer_node_id != node_id) {
        get_ip_port((struct sockaddr *)&host->remote_addr, ip, ADDRESS_MAX_LEN,
            &port);
        LOG("Warning: Peer [%s]:%u node id not match, expect: %u, actual: %u\n",
            ip, port, host->peer_node_id, node_id);

        return 1;
    }

    return 0;
}


static void generate_token(uint16_t node_id, uint8_t *payload, size_t length,
    uint8_t out[32])
{
    SHA256_CTX ctx;

    sha256_init(&ctx);
    sha256_update(&ctx, g_config.transport.password, PASSWORD_LEN);
    sha256_update(
        &ctx,
        (uint8_t*)&node_id,
        sizeof(uint16_t));
    sha256_update(&ctx, payload, length);
    sha256_final(&ctx, out);
}

static int validate_token(uint16_t node_id, uint8_t *payload, size_t length,
                        uint8_t token[32])
{
    SHA256_CTX ctx;
    uint8_t expect_token[32];

    sha256_init(&ctx);
    sha256_update(&ctx, g_config.transport.password, PASSWORD_LEN);
    sha256_update(&ctx, (uint8_t*)&node_id, sizeof(uint16_t));
    sha256_update(&ctx, payload, length);
    sha256_final(&ctx, expect_token);

    return memcmp(token, expect_token, 32) ? 0 : 1;
}