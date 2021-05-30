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
#include "litedt.h"
#include "config.h"
#include "util.h"

typedef struct _sack_info {
    uint32_t seq_end;
    uint8_t send_times;
} sack_info_t;

static void litedt_connection_actor(litedt_host_t *host, int64_t *wait_time);
static void litedt_retrans_actor(litedt_host_t *host, int64_t *wait_time);
static void litedt_transmit_actor(litedt_host_t *host, int64_t *wait_time);
static void push_sack_map(litedt_conn_t *conn, uint32_t seq);

int socket_send(litedt_host_t *host, const void *buf, size_t len, int force)
{
    int ret = -1;
    if (!force && host->pacing_credit < len)
        return SEND_FLOW_CONTROL; // flow control

    host->pacing_credit -= len;
    host->stat.send_bytes_stat += len;

    if (host->connected) {
        ret = send(host->sockfd, buf, len, 0);
    }

    if (!host->connected || ret < (int)len) {
        ++host->stat.send_error;
    }
        
    return ret;
}

int socket_sendto(
    litedt_host_t *host, 
    const void *buf, 
    size_t len,
    struct sockaddr_in *addr,
    int force)
{
    int ret = -1;
    if (!force && host->pacing_credit < len)
        return SEND_FLOW_CONTROL; // flow control

    host->pacing_credit -= len;
    host->stat.send_bytes_stat += len;

    ret = sendto(
        host->sockfd, buf, len, 0, 
        (struct sockaddr *)addr, 
        sizeof(struct sockaddr));


    if (!host->connected || ret < (int)len) {
        ++host->stat.send_error;
    }
        
    return ret;
}

uint32_t seq_hash(void *key)
{
    return *(uint32_t *)key;
}

litedt_conn_t* find_connection(litedt_host_t *host, uint32_t flow)
{
    litedt_conn_t *conn = (litedt_conn_t *)queue_get(&host->conn_queue, &flow);
    return conn;
}

int create_connection(
    litedt_host_t *host,
    uint32_t flow,
    uint16_t tunnel_id,
    int status)
{
    int ret = 0;
    int64_t cur_time;
    litedt_conn_t conn_tmp, *conn;
    if (find_connection(host, flow) != NULL)
        return RECORD_EXISTS;
    if (queue_get(&host->timewait_queue, &flow) != NULL)
        return RECORD_EXISTS;
    if (status == CONN_ESTABLISHED && host->connect_cb) {
        ret = host->connect_cb(host, flow, tunnel_id);
        if (ret)
            return ret;
    }

    ret = queue_append(&host->conn_queue, &flow, &conn_tmp);
    if (ret != 0) {
        DBG("create connection %u failed: %d\n", flow, ret);
        return ret;
    }
    conn = (litedt_conn_t*)queue_get(&host->conn_queue, &flow);

    cur_time = host->cur_time;
    conn->status        = status;
    conn->tunnel_id     = tunnel_id;
    conn->flow          = flow;
    conn->swin_start    = 0;
    conn->swin_size     = g_config.buffer_size; // default window size
    conn->last_responsed = cur_time;
    conn->next_ack_time = cur_time + NORMAL_ACK_DELAY;
    conn->write_seq  = 0;
    conn->send_seq   = 0;
    conn->reack_times   = 0;
    conn->notify_recvnew = 0;
    conn->notify_recv   = 1;
    conn->notify_send   = 0;
    conn->fec_enabled   = 0;
    treemap_init(
        &conn->sack_map, sizeof(uint32_t), sizeof(sack_info_t), seq_cmp);
    rbuf_init(&conn->send_buf, g_config.buffer_size / RBUF_BLOCK_SIZE);
    rbuf_init(&conn->recv_buf, g_config.buffer_size / RBUF_BLOCK_SIZE);
    rbuf_window_info(&conn->recv_buf, &conn->rwin_start, &conn->rwin_size);

    retrans_mod_init(&conn->retrans, host, conn);
    if (g_config.fec_group_size) {
        conn->fec_enabled = 1;
        ret = fec_mod_init(&conn->fec, host, flow);
        if (ret != 0) {
            LOG("error: FEC init failed: %d\n", ret);
            retrans_mod_fini(&conn->retrans);
            queue_del(&host->conn_queue, &flow);
            return ret;
        }
    }

    DBG("create connection %u success\n", flow);

    litedt_update_event_time(host, host->last_event_time + SEND_INTERVAL);

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

    if (host->conn_send) {
        // move pointer to next connection if current connection is closing
        litedt_conn_t *curr = (litedt_conn_t *)queue_value(&host->conn_queue,
                                                           host->conn_send);
        if (curr->flow == flow)
            host->conn_send = queue_next(&host->conn_queue, host->conn_send);
    }

    treemap_fini(&conn->sack_map);
    rbuf_fini(&conn->send_buf);
    rbuf_fini(&conn->recv_buf);
    retrans_mod_fini(&conn->retrans);
    if (conn->fec_enabled)
        fec_mod_fini(&conn->fec);
    queue_del(&host->conn_queue, &flow);
    
    time_wait.flow = flow;
    time_wait.close_time = host->cur_time;
    queue_append(&host->timewait_queue, &flow, &time_wait);

    DBG("connection %u released\n", flow);
}

void release_all_connections(litedt_host_t *host)
{
    hash_node_t *q_it;
    for (q_it = queue_first(&host->conn_queue); q_it != NULL;) {
        litedt_conn_t *conn = 
            (litedt_conn_t *)queue_value(&host->conn_queue, q_it);
        q_it = queue_next(&host->conn_queue, q_it);
        release_connection(host, conn->flow);
    }
}

void litedt_init(litedt_host_t *host)
{
    int64_t cur_time = get_curtime();
    
    host->sockfd = -1;
    memset(&host->stat, 0, sizeof(host->stat));
    host->pacing_time       = cur_time;
    host->pacing_credit     = 0;
    host->pacing_rate       = g_config.transmit_rate_init;
    host->snd_cwnd          = 2 * (host->pacing_rate / LITEDT_MTU);
    host->connected         = 0;
    host->remote_online     = 0;
    bzero(&host->remote_addr, sizeof(struct sockaddr_in));
    host->ping_id           = 0;
    host->srtt              = 0;
    host->cur_time          = cur_time;
    host->last_event_time   = cur_time;
    host->next_event_time   = cur_time + IDLE_INTERVAL;
    host->last_ping         = 0;
    host->last_ping_rsp     = cur_time;
    host->fec_group_size_ctrl = g_config.fec_group_size < 128
                              ? g_config.fec_group_size : 10;
    host->conn_send         = NULL;
    queue_init(&host->conn_queue, CONN_HASH_SIZE, sizeof(uint32_t), 
               sizeof(litedt_conn_t), seq_hash, 0);
    queue_init(&host->timewait_queue, CONN_HASH_SIZE, sizeof(uint32_t), 
               sizeof(litedt_tw_conn_t), seq_hash, 0);
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

    host->accept_cb     = NULL;
    host->connect_cb    = NULL;
    host->close_cb      = NULL;
    host->receive_cb    = NULL;
    host->send_cb       = NULL;
    host->event_time_cb = NULL;
}

int litedt_ping_req(litedt_host_t *host)
{
    char buf[80];
    int64_t ping_time;
    uint32_t plen;
    litedt_header_t *header = (litedt_header_t *)buf;
    ping_req_t *req = (ping_req_t *)(buf + sizeof(litedt_header_t));
    
    ping_time = host->cur_time;

    header->ver = LITEDT_VERSION;
    header->cmd = LITEDT_PING_REQ;
    header->flow = 0;

    req->node_id = g_config.node_id;
    req->ping_id = ++host->ping_id;
    memcpy(req->data, &ping_time, 8);

    plen = sizeof(litedt_header_t) + sizeof(ping_req_t);
    socket_send(host, buf, plen, 1);
    
    return 0;
}

int litedt_ping_rsp(
    litedt_host_t *host, 
    ping_req_t *req,
    struct sockaddr_in *peer_addr)
{
    char buf[80];
    uint32_t plen;
    litedt_header_t *header = (litedt_header_t *)buf;
    ping_rsp_t *rsp = (ping_rsp_t *)(buf + sizeof(litedt_header_t));

    header->ver = LITEDT_VERSION;
    header->cmd = LITEDT_PING_RSP;
    header->flow = 0;

    rsp->node_id = g_config.node_id;
    rsp->ping_id = req->ping_id;
    memcpy(rsp->data, req->data, sizeof(rsp->data));

    plen = sizeof(litedt_header_t) + sizeof(ping_rsp_t);
    socket_sendto(host, buf, plen, peer_addr, 1);

    return 0;
}

int litedt_conn_req(litedt_host_t *host, uint32_t flow, uint16_t tunnel_id)
{
    char buf[80];
    uint32_t plen;
    litedt_header_t *header = (litedt_header_t *)buf;
    conn_req_t *req = (conn_req_t *)(buf + sizeof(litedt_header_t));

    header->ver = LITEDT_VERSION;
    header->cmd = LITEDT_CONNECT_REQ;
    header->flow = flow;

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

    header->ver = LITEDT_VERSION;
    header->cmd = LITEDT_CONNECT_RSP;
    header->flow = flow;

    rsp->status = status;

    plen = sizeof(litedt_header_t) + sizeof(conn_rsp_t);
    socket_send(host, buf, plen, 1);
    
    return 0;
}

int litedt_data_post(
    litedt_host_t *host, uint32_t flow, uint32_t seq, uint32_t len, 
    uint32_t fec_seq, uint8_t fec_index, int64_t curtime, int fec_post)
{
    int send_ret = 0, ret;
    char buf[LITEDT_MTU];
    uint32_t plen;
    litedt_conn_t *conn;
    if (!host->remote_online)
        return CLIENT_OFFLINE;
    if (len > LITEDT_MSS)
        return PARAMETER_ERROR;
    if ((conn = find_connection(host, flow)) == NULL)
        return RECORD_NOT_FOUND;
    if (seq - conn->swin_start > conn->swin_size
        || seq + len - conn->swin_start > conn->swin_size)
        return SEQ_OUT_OF_RANGE;
    
    litedt_header_t *header = (litedt_header_t *)buf;
    data_post_t *post = (data_post_t *)(buf + sizeof(litedt_header_t));
    data_conn_t *dcon = (data_conn_t *)(buf + sizeof(litedt_header_t));
    
    header->ver     = LITEDT_VERSION;
    header->flow    = flow;

    if (conn->status == CONN_REQUEST) {
        header->cmd = LITEDT_CONNECT_DATA;
        dcon->conn_req.tunnel_id = conn->tunnel_id;
        post = &dcon->data_post;
        plen = sizeof(litedt_header_t) + sizeof(data_conn_t) + len;
    } else {
        header->cmd = LITEDT_DATA_POST;
        plen = sizeof(litedt_header_t) + sizeof(data_post_t) + len;
    }

    post->seq       = seq;
    post->len       = len;
    post->fec_seq   = fec_seq;
    post->fec_index = fec_index;

    rbuf_read(&conn->send_buf, seq, post->data, len);
    ++host->stat.data_packet_post;

    ret = create_packet_entry(
        &conn->retrans, seq, len, fec_seq, fec_index);
    if (ret && ret != RECORD_EXISTS) {
        LOG("ERROR: failed to create packet entry: seq=%u, len=%u, ret=%d\n",
            seq, len, ret);
    }

    send_ret = socket_send(host, buf, plen, 0);
    if (send_ret >= 0)
        host->stat.send_bytes_data += plen;

    if (conn->fec_enabled && fec_post) {
        fec_push_data(&conn->fec, post);
    }

    if (send_ret == SEND_FLOW_CONTROL)  {
        DBG("Warning: unexpected flow control during sending data!\n");
        return SEND_FLOW_CONTROL;
    }
    
    return 0;
}

int litedt_data_ack(litedt_host_t *host, uint32_t flow, int ack_list)
{
    char buf[LITEDT_MTU];
    uint32_t plen;
    litedt_conn_t *conn;
    if ((conn = find_connection(host, flow)) == NULL)
        return RECORD_NOT_FOUND;

    litedt_header_t *header = (litedt_header_t *)buf;
    data_ack_t *ack = (data_ack_t *)(buf + sizeof(litedt_header_t));

    header->ver = LITEDT_VERSION;
    header->cmd = LITEDT_DATA_ACK;
    header->flow = flow;

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

            if (++cnt >= g_config.ack_size)
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

    header->ver = LITEDT_VERSION;
    header->cmd = LITEDT_CLOSE_REQ;
    header->flow = flow;

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

    header->ver = LITEDT_VERSION;
    header->cmd = LITEDT_CLOSE_RSP;
    header->flow = flow;

    plen = sizeof(litedt_header_t);
    socket_send(host, buf, plen, 1);
    
    return 0;
}

int litedt_conn_rst(litedt_host_t *host, uint32_t flow)
{
    char buf[80];
    uint32_t plen;
    litedt_header_t *header = (litedt_header_t *)buf;

    header->ver = LITEDT_VERSION;
    header->cmd = LITEDT_CONNECT_RST;
    header->flow = flow;

    plen = sizeof(litedt_header_t);
    socket_send(host, buf, plen, 1);
    
    return 0;
}

int litedt_connect(litedt_host_t *host, uint32_t flow, uint16_t tunnel_id)
{
    int ret = 0;
    if (!host->remote_online)
        return CLIENT_OFFLINE;
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
        return RECORD_NOT_FOUND;
    if (conn->status <= CONN_ESTABLISHED) {
        conn->status = CONN_FIN_WAIT;
        litedt_close_req(host, flow, conn->write_seq);
    } else if (conn->status != CONN_FIN_WAIT) {
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
        || conn->status >= CONN_FIN_WAIT)
        return RECORD_NOT_FOUND;
    if (rbuf_writable_bytes(&conn->send_buf) < len)
        return NOT_ENOUGH_SPACE;
    if (len > 0) {
        // write to buffer and send later
        rbuf_write_front(&conn->send_buf, buf, len);
        conn->write_seq = rbuf_write_pos(&conn->send_buf);
        litedt_update_event_time(host, host->last_event_time + SEND_INTERVAL);
    }
    return 0;
}

int litedt_recv(litedt_host_t *host, uint32_t flow, char *buf, uint32_t len)
{
    int ret, readable;
    litedt_conn_t *conn;
    if ((conn = find_connection(host, flow)) == NULL)
        return RECORD_NOT_FOUND;
    ret = rbuf_read_front(&conn->recv_buf, buf, len);
    if (ret > 0) {
        rbuf_release(&conn->recv_buf, ret);

        // update recv_wnd after release buffer
        rbuf_window_info(&conn->recv_buf, &conn->rwin_start, &conn->rwin_size);
        readable = rbuf_readable_bytes(&conn->recv_buf);
        conn->rwin_start += readable;
        conn->rwin_size  -= readable;
    }
    return ret;
}

int litedt_peek(litedt_host_t *host, uint32_t flow, char *buf, uint32_t len)
{
    int ret;
    litedt_conn_t *conn;
    if ((conn = find_connection(host, flow)) == NULL)
        return RECORD_NOT_FOUND;
    ret = rbuf_read_front(&conn->recv_buf, buf, len);
    return ret;
}

void litedt_recv_skip(litedt_host_t *host, uint32_t flow, uint32_t len)
{
    int readable;
    litedt_conn_t *conn;
    if ((conn = find_connection(host, flow)) == NULL)
        return;
    rbuf_release(&conn->recv_buf, len);

    // update recv_wnd after release buffer
    rbuf_window_info(&conn->recv_buf, &conn->rwin_start, &conn->rwin_size);
    readable = rbuf_readable_bytes(&conn->recv_buf);
    conn->rwin_start += readable;
    conn->rwin_size  -= readable;
}

int litedt_writable_bytes(litedt_host_t *host, uint32_t flow)
{
    litedt_conn_t *conn;
    if ((conn = find_connection(host, flow)) == NULL)
        return RECORD_NOT_FOUND;
    return rbuf_writable_bytes(&conn->send_buf);
}

int litedt_readable_bytes(litedt_host_t *host, uint32_t flow)
{
    litedt_conn_t *conn;
    if ((conn = find_connection(host, flow)) == NULL)
        return RECORD_NOT_FOUND;
    return rbuf_readable_bytes(&conn->recv_buf);
}

void litedt_set_remote_addr(litedt_host_t *host, char *addr, uint16_t port)
{
    host->remote_addr.sin_family = AF_INET;
    host->remote_addr.sin_addr.s_addr = inet_addr(addr);
    host->remote_addr.sin_port = htons(port);
}

void litedt_set_remote_addr2(litedt_host_t *host, struct sockaddr_in *addr)
{
    memcpy(&host->remote_addr, addr, sizeof(struct sockaddr_in));
}

void litedt_set_accept_cb(litedt_host_t *host, litedt_accept_fn *accept_cb)
{
    host->accept_cb = accept_cb;
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

int litedt_on_ping_req(
    litedt_host_t *host, 
    ping_req_t *req, 
    struct sockaddr_in *peer_addr)
{
    if (!host->connected && host->accept_cb)
        host->accept_cb(host, req->node_id, peer_addr);

    litedt_ping_rsp(host, req, peer_addr);
    return 0;
}

int litedt_on_ping_rsp(litedt_host_t *host, ping_rsp_t *rsp)
{
    int64_t cur_time, ping_rtt;
    if (rsp->ping_id != host->ping_id)
        return 0;
    cur_time = host->cur_time;
    memcpy(&ping_rtt, rsp->data, 8);
    
    ++host->ping_id;
    host->last_ping_rsp = cur_time;
    ping_rtt = cur_time - ping_rtt;
    host->ping_rtt = (uint32_t)ping_rtt;
    DBG("ping rsp, rtt=%u\n", host->ping_rtt);

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
        return RECORD_NOT_FOUND;
    if (0 == rsp->status) {
        if (conn->status == CONN_REQUEST)
            conn->status = CONN_ESTABLISHED;
        // send ack when connection established
        litedt_data_ack(host, flow, 0);
        DBG("connection %u established\n", flow);
    } else {
        release_connection(host, flow);
    }

    return 0;
}

int litedt_on_data_recv(
    litedt_host_t *host, uint32_t flow, data_post_t *data, int fec_recv)
{
    int ret, readable   = 0;
    uint32_t dseq       = data->seq;
    uint16_t dlen       = data->len;
    int64_t  cur_time   = host->cur_time;
    litedt_conn_t *conn = find_connection(host, flow);
    if (NULL == conn)
        return RECORD_NOT_FOUND;
    if (conn->status == CONN_REQUEST)
        conn->status = CONN_ESTABLISHED;

    ret = rbuf_write(&conn->recv_buf, dseq, data->data, dlen);
    if (ret == 1 || ret == RBUF_OUT_OF_RANGE)
        ++host->stat.dup_packet_recv;
    if (ret >= 0) {
        rbuf_window_info(&conn->recv_buf, &conn->rwin_start, &conn->rwin_size);
        readable = rbuf_readable_bytes(&conn->recv_buf);
        conn->rwin_start += readable;
        conn->rwin_size  -= readable;
        push_sack_map(conn, dseq);

        if (conn->fec_enabled) {
            if (!fec_recv) {
                fec_insert_data(&conn->fec, data);
                // readable bytes of recv_buf might be changed
                readable = rbuf_readable_bytes(&conn->recv_buf);
            }
            fec_checkpoint(&conn->fec, conn->rwin_start);
        }
    }
    
    if (treemap_size(&conn->sack_map) >= g_config.ack_size) {
        // send ack msg immediately
        litedt_data_ack(host, flow, 1);
        while (g_config.ack_size 
            && treemap_size(&conn->sack_map) >= g_config.ack_size) {
            // ack list is still full, send ack msg again
            litedt_data_ack(host, flow, 1);
        }
        conn->next_ack_time = cur_time + REACK_DELAY;
        conn->reack_times = 1;
    } else {
        // delay sending ack packet
        conn->next_ack_time = MIN(conn->next_ack_time, cur_time + FAST_ACK_DELAY);
        conn->reack_times = 2;
    }

    if ((conn->notify_recv || conn->notify_recvnew) && host->receive_cb 
        && readable > 0)
        host->receive_cb(host, flow, readable);

    litedt_update_event_time(host, conn->next_ack_time);

    return 0;
}

int litedt_on_data_ack(litedt_host_t *host, uint32_t flow, data_ack_t *ack)
{
    uint32_t i;
    uint32_t delivered;
    rate_sample_t rs = { .prior_delivered = 0 };
    int64_t cur_time = host->cur_time;
    litedt_conn_t *conn = find_connection(host, flow);
    if (NULL == conn)
        return RECORD_NOT_FOUND;
    if (conn->status == CONN_REQUEST)
        conn->status = CONN_ESTABLISHED;

    delivered = host->delivered;

    for (i = 0; i < ack->ack_size; i++) {
        uint32_t start = ack->acks[i][0];
        uint32_t end = ack->acks[i][1];
        release_packet_range(&conn->retrans, start, end, &rs);
    }

    if (LESS_EQUAL(conn->swin_start, ack->win_start) && 
        LESS_EQUAL(ack->win_start, conn->send_seq)) {
        uint32_t release_size, sendbuf_start, sendbuf_size;
        conn->last_responsed = cur_time;
        conn->swin_start = ack->win_start;
        conn->swin_size = ack->win_size;

        rbuf_window_info(&conn->send_buf, &sendbuf_start, &sendbuf_size);
        release_size = conn->swin_start - sendbuf_start;
        if (release_size > 0)
            rbuf_release(&conn->send_buf, release_size);
        retrans_checkpoint(&conn->retrans, conn->swin_start, &rs);
    }

    generate_bandwidth(&conn->retrans, &rs, host->delivered - delivered);
    ctrl_io_event(&host->ctrl, &rs);

    if (conn->notify_send && host->send_cb 
        && conn->status <= CONN_ESTABLISHED) {
        int writable = rbuf_writable_bytes(&conn->send_buf);
        if (writable > 0)
            host->send_cb(host, flow, writable);
    }

    return 0;
}

int litedt_on_close_req(litedt_host_t *host, uint32_t flow, close_req_t *req)
{
    litedt_conn_t *conn = find_connection(host, flow);
    if (NULL == conn) {
        litedt_close_rsp(host, flow);
        return 0;
    }
    DBG("recv close req: end_seq=%u\n", req->last_seq);

    if (conn->status == CONN_FIN_WAIT) {
        release_connection(host, flow);
        litedt_close_rsp(host, flow);
    } else if (conn->status != CONN_CLOSED) {
        uint32_t win_start, win_len, readable;
        conn->status = CONN_CLOSE_WAIT;
        rbuf_window_info(&conn->recv_buf, &win_start, &win_len);
        readable = rbuf_readable_bytes(&conn->recv_buf);
        if (win_start + readable == req->last_seq) {
            conn->status = CONN_CLOSED;
            litedt_close_rsp(host, flow);
        }
    }

    return 0;
}

int litedt_on_close_rsp(litedt_host_t *host, uint32_t flow)
{
    litedt_conn_t *conn = find_connection(host, flow);
    if (NULL == conn)
        return 0;
    if (conn->status == CONN_FIN_WAIT) 
        release_connection(host, flow);
    return 0;
}

int litedt_on_conn_rst(litedt_host_t *host, uint32_t flow)
{
    litedt_conn_t *conn = find_connection(host, flow);
    if (NULL == conn)
        return 0;

    if (conn->status == CONN_FIN_WAIT)
        release_connection(host, flow);
    else
        conn->status = CONN_CLOSED;
    DBG("connection %u reset\n", flow);

    return 0;
}

int litedt_on_data_fec(litedt_host_t *host, uint32_t flow, data_fec_t *fec)
{
    litedt_conn_t *conn = find_connection(host, flow);
    if (NULL == conn)
        return RECORD_NOT_FOUND;
    if (!conn->fec_enabled)
        return 0;

    if (conn->status == CONN_REQUEST)
        conn->status = CONN_ESTABLISHED;
    if (conn->status != CONN_ESTABLISHED && conn->status != CONN_CLOSE_WAIT) 
        return 0;

    fec_insert_sum(&conn->fec, fec);
    fec_checkpoint(&conn->fec, conn->rwin_start);
    
    return 0;
}

void litedt_update_event_time(litedt_host_t *host, int64_t event_time)
{
    if (host->next_event_time <= event_time) 
        return;
    host->next_event_time = event_time;
    if (host->event_time_cb)
        host->event_time_cb(host, event_time);
}

void litedt_io_event(litedt_host_t *host, int64_t cur_time)
{
    int recv_len, ret = 0, status;
    uint32_t flow;
    struct sockaddr_in addr;
    int hlen = sizeof(litedt_header_t);
    socklen_t addr_len = sizeof(addr);
    char buf[2048];
    char ip[ADDRESS_MAX_LEN];
    litedt_header_t *header = (litedt_header_t *)buf;
    host->cur_time = cur_time;

    while ((recv_len = recvfrom(host->sockfd, buf, sizeof(buf), 0, 
            (struct sockaddr *)&addr, &addr_len)) >= 0) {
        host->stat.recv_bytes_stat += recv_len;
        //if ((host->remote_online || host->lock_remote_addr)
        //    && addr.sin_addr.s_addr != host->remote_addr.sin_addr.s_addr) 
        //    continue;
        if (recv_len < hlen)
            continue;
        if (header->ver != LITEDT_VERSION)
            continue;

        /*if (addr.sin_port != host->remote_addr.sin_port) {
            if (host->lock_remote_addr) {
                continue;
            } else if (host->remote_online) {
                LOG("Notice: Remote port has been changed to %u.\n", 
                    ntohs(addr.sin_port));
                host->remote_addr.sin_port = addr.sin_port;
            }
        }
        
        if (!host->remote_online) {
            inet_ntop(AF_INET, &addr.sin_addr, ip, ADDRESS_MAX_LEN);
            LOG("Remote host %s:%u is online and active\n", ip, 
                    ntohs(addr.sin_port));
            host->remote_online = 1;
            host->last_ping_rsp = cur_time;
            memcpy(&host->remote_addr, &addr, sizeof(struct sockaddr_in));

            if (!queue_empty(&host->conn_queue)) {
                int64_t event_time = host->last_event_time + SEND_INTERVAL;
                litedt_update_event_time(host, event_time);
            }
        }*/

        if (!host->connected && header->cmd != LITEDT_PING_REQ) {
            DBG("Unsupported command for host: %u\n", header->cmd);
            continue;
        }
            
        ret = 0;
        flow = header->flow;
        switch (header->cmd) {
        case LITEDT_PING_REQ:
            if (recv_len < hlen + (int)sizeof(ping_req_t))
                break;
            ret = litedt_on_ping_req(host, (ping_req_t *)(buf + hlen), &addr);
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
            if (ret != RECORD_NOT_FOUND || 
                queue_get(&host->timewait_queue, &flow) == NULL) {
                LOG("Connection %u error, reset\n", flow);
            }
            litedt_conn_rst(host, flow);
        }
    }
}

int64_t litedt_time_event(litedt_host_t *host, int64_t cur_time)
{
    int ret = 0, flow_ctrl = 1;
    int64_t wait_time = cur_time + IDLE_INTERVAL, offline_time;
    hash_node_t *q_it, *q_start;

    host->cur_time = cur_time;
    // send ping request
    if (host->remote_online || host->connected) {
        int64_t ping_time = host->last_ping + PING_INTERVAL;
        if (cur_time >= ping_time) {
            litedt_ping_req(host);
            host->last_ping = cur_time;
            wait_time = MIN(wait_time, cur_time + PING_INTERVAL);
        } else {
            wait_time = MIN(wait_time, ping_time);
        }
    }

    // remove expired TIME_WAIT status flow
    while (!queue_empty(&host->timewait_queue)) {
        litedt_tw_conn_t *twait;
        int64_t expire_time;

        q_it = queue_first(&host->timewait_queue);
        twait = (litedt_tw_conn_t *)queue_value(&host->timewait_queue, q_it);
        expire_time = twait->close_time + TIME_WAIT_EXPIRE;
        if (cur_time < expire_time) {
            wait_time = MIN(wait_time, expire_time);
            break;
        }
        queue_del(&host->timewait_queue, &twait->flow);
    }

    if (!host->remote_online) 
        return wait_time;

    if (cur_time > host->pacing_time) {
        host->pacing_credit += (uint64_t)host->pacing_rate 
            * (cur_time - host->pacing_time) / USEC_PER_SEC;
        host->pacing_time = cur_time;
    }

    offline_time = host->last_ping_rsp + g_config.offline_timeout
        * USEC_PER_SEC;
    if (cur_time >= offline_time) {
        char     ip[ADDRESS_MAX_LEN];
        uint16_t port = ntohs(host->remote_addr.sin_port);
        inet_ntop(AF_INET, &host->remote_addr.sin_addr, ip, ADDRESS_MAX_LEN);
        LOG("Remote host %s:%u is offline\n", ip, port);

        release_all_connections(host);
        host->remote_online = 0;
        wait_time = MIN(wait_time, cur_time + IDLE_INTERVAL);
    } else {
        wait_time = MIN(wait_time, offline_time);
    }
   
    ctrl_time_event(&host->ctrl);
    litedt_connection_actor(host, &wait_time);
    litedt_retrans_actor(host, &wait_time);
    litedt_transmit_actor(host, &wait_time);

    if (wait_time < cur_time + 1) 
        wait_time = cur_time + 1;
    host->last_event_time = cur_time;
    host->next_event_time = wait_time;
    return wait_time;
}

litedt_stat_t* litedt_get_stat(litedt_host_t *host)
{
    host->stat.connection_num   = queue_size(&host->conn_queue);
    host->stat.timewait_num     = queue_size(&host->timewait_queue);
    host->stat.fec_group_size   = host->fec_group_size_ctrl;
    host->stat.rtt              = host->srtt;
    return &host->stat;
}

void litedt_clear_stat(litedt_host_t *host)
{
    memset(&host->stat, 0, sizeof(litedt_stat_t));
}

int litedt_online_status(litedt_host_t *host)
{
    return host->remote_online;
}

int litedt_startup(litedt_host_t *host, int socket_connect)
{
    struct sockaddr_in addr;
    int flag = 1, ret, sock;
    int bufsize = 5 * 1048576;

    if (host->sockfd >= 0)
        return host->sockfd;

    if ((sock = socket(PF_INET, SOCK_DGRAM, 0)) < 0)
        return SOCKET_ERROR;
    ret = setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &flag, sizeof(int));
    if (ret < 0) {
        close(sock);
        return SOCKET_ERROR;
    }
    if (fcntl(sock, F_SETFL, fcntl(sock, F_GETFL) | O_NONBLOCK) < 0 ||
        fcntl(sock, F_SETFD, FD_CLOEXEC) < 0) { 
        close(sock);
        return SOCKET_ERROR;
    }
    if (setsockopt(sock, SOL_SOCKET, SO_RCVBUF, (const char*)&bufsize, 
                   sizeof(int)) < 0) {
        close(sock);
        return SOCKET_ERROR;
    }
    if (setsockopt(sock, SOL_SOCKET, SO_SNDBUF, (const char*)&bufsize, 
                   sizeof(int)) < 0) {
        close(sock);
        return SOCKET_ERROR;
    }

    if (g_config.flow_local_port > 0) {
        bzero(&addr, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = inet_addr(g_config.flow_local_addr);
        addr.sin_port = htons(g_config.flow_local_port);
        if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            close(sock);
            return SOCKET_ERROR;
        }
    }

    if (socket_connect) {
        if (connect(sock, (struct sockaddr*)&host->remote_addr,
                sizeof(struct sockaddr)) < 0) {
            close(sock);
            return SOCKET_ERROR;
        }
        host->connected = 1;
    }

    host->sockfd = sock;
    return sock;
}

void litedt_shutdown(litedt_host_t *host)
{
    if (host->sockfd < 0)
        return;
    close(host->sockfd);
    host->sockfd = -1;
}

void litedt_fini(litedt_host_t *host)
{
    litedt_shutdown(host);
    while (!queue_empty(&host->conn_queue)) {
        uint32_t ckey;
        litedt_conn_t *conn = (litedt_conn_t *)queue_front(
            &host->conn_queue, &ckey);
        release_connection(host, conn->flow);
    }
    queue_fini(&host->timewait_queue);
    queue_fini(&host->conn_queue);
}

static void litedt_connection_actor(litedt_host_t *host, int64_t *wait_time)
{
    hash_node_t *q_it;
    int64_t cur_time = host->cur_time;

    for (q_it = queue_first(&host->conn_queue); q_it != NULL;) {
        litedt_conn_t *conn = (litedt_conn_t *)queue_value(&host->conn_queue,
                                                           q_it);
        q_it = queue_next(&host->conn_queue, q_it);
        if (cur_time - conn->last_responsed > CONNECTION_TIMEOUT) {
            release_connection(host, conn->flow);
            continue;
        }
        // check recv/send buffer and notify user
        if (conn->notify_recv && host->receive_cb) {
            int readable = rbuf_readable_bytes(&conn->recv_buf);
            if (readable > 0)
                host->receive_cb(host, conn->flow, readable);
        }
        if (conn->notify_send && host->send_cb
            && conn->status <= CONN_ESTABLISHED) {
            int writable = rbuf_writable_bytes(&conn->send_buf);
            if (writable > 0)
                host->send_cb(host, conn->flow, writable);
        }
        // send ack msg to synchronize data window
        if (cur_time >= conn->next_ack_time) {
            switch (conn->status) {
            case CONN_REQUEST:
                litedt_conn_req(host, conn->flow, conn->tunnel_id);
                break;
            case CONN_ESTABLISHED:
                if (conn->fec_enabled)
                    fec_post(&conn->fec);
                litedt_data_ack(host, conn->flow, conn->reack_times > 0);
                break;
            case CONN_FIN_WAIT:
                if (conn->fec_enabled)
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
                conn->next_ack_time = cur_time + REACK_DELAY;
            } else {
                // send keep-alive msg after 1s
                conn->reack_times = 0;
                conn->next_ack_time = cur_time + NORMAL_ACK_DELAY;
            }
        }
        *wait_time = MIN(*wait_time, conn->next_ack_time);
    }
}

static void litedt_retrans_actor(litedt_host_t *host, int64_t *wait_time)
{
    hash_node_t *q_it, *q_start;
    int64_t cur_time = host->cur_time;
    int ret = 0;

    q_it = q_start = host->conn_send;
    do {
        if (q_it ==  NULL) {
            q_it = queue_first(&host->conn_queue);
            if (q_start == q_it)
                break;
        }

        litedt_conn_t *conn = (litedt_conn_t *)queue_value(
            &host->conn_queue, q_it);
        ret = retrans_time_event(&conn->retrans, cur_time);
        if (ret == SEND_FLOW_CONTROL) {
            break;
        }

        *wait_time = MIN(*wait_time, 
            retrans_next_event_time(&conn->retrans, cur_time));
        q_it = queue_next(&host->conn_queue, q_it);
    } while (q_it != q_start);    
}

static void litedt_transmit_actor(litedt_host_t *host, int64_t *wait_time)
{
    hash_node_t *q_it, *q_start;
    int64_t cur_time = host->cur_time;
    int flow_ctrl = 1, ret = 0;
    
    q_it = q_start = host->conn_send;
    do {
        if (q_it ==  NULL) {
            q_it = queue_first(&host->conn_queue);
            if (q_start == q_it)
                break;
        }
        litedt_conn_t *conn = (litedt_conn_t *)queue_value(
            &host->conn_queue, q_it);
        // check send buffer and post data to network
        if (conn->status <= CONN_FIN_WAIT) {
            while (conn->write_seq != conn->send_seq) {
                uint32_t fec_seq = 0;
                uint8_t fec_index = 0;
                uint32_t bytes = conn->write_seq - conn->send_seq;
                uint32_t swin_end = conn->swin_start + conn->swin_size;
                if (bytes > swin_end - conn->send_seq)
                    bytes = swin_end - conn->send_seq;
                if (bytes > LITEDT_MSS)
                    bytes = LITEDT_MSS;
                if (0 == bytes)
                    break;

                if (host->inflight >= host->snd_cwnd) {
                    flow_ctrl = 0;
                    break;
                }
                uint32_t predict = bytes + LITEDT_MAX_HEADER;
                if (predict > host->pacing_credit) {
                    int64_t next_send_time = host->pacing_time + SEND_INTERVAL
                        + ((uint64_t)predict * (uint64_t)USEC_PER_SEC 
                            / (uint64_t)host->pacing_rate);
                    *wait_time = MIN(*wait_time, next_send_time);
                    flow_ctrl = 0;
                    break;
                }
                if (conn->fec_enabled)
                    get_fec_header(&conn->fec, &fec_seq, &fec_index);
                ret = litedt_data_post(
                    host, conn->flow, conn->send_seq, bytes, fec_seq, 
                    fec_index, cur_time, 1);
                if (!ret) {
                    conn->send_seq += bytes;
                } else {
                    if (ret == SEND_FLOW_CONTROL) {
                        *wait_time = MIN(*wait_time, cur_time + SEND_INTERVAL);
                        flow_ctrl = 0;
                    }
                    break;
                }
            }
        }

        q_it = queue_next(&host->conn_queue, q_it);
    } while (q_it != q_start && flow_ctrl);
    // next time start from here
    host->conn_send = q_it;

    if (flow_ctrl) {
        host->app_limited = (host->delivered + host->inflight) ? : 1;
        host->pacing_credit = 0; // clear credit to prevent traffic spike
    }
}

static void push_sack_map(litedt_conn_t *conn, uint32_t seq)
{
    int ret = 0;
    sack_info_t sack;
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