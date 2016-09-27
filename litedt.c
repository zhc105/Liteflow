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

#define LESS_EQUAL(a, b) ((uint32_t)(b) - (uint32_t)(a) < 0x80000000u)
#ifdef ENABLE_LITEDT_CHECKSUM
    #define PACKET_CHECKSUM(b, l) calculate_checksum(b, l)
#else
    #define PACKET_CHECKSUM(b, l)
#endif

int litedt_ping_req(litedt_host_t *host);
int litedt_ping_rsp(litedt_host_t *host, ping_req_t *req);
int litedt_conn_req(litedt_host_t *host, uint32_t flow, uint16_t map_id);
int litedt_conn_rsp(litedt_host_t *host, uint32_t flow, int32_t status);
int litedt_data_post(litedt_host_t *host, uint32_t flow, uint32_t offset, 
                        uint32_t len, int64_t curtime);
int litedt_data_ack(litedt_host_t *host, uint32_t flow, int ack_list);
int litedt_close_req(litedt_host_t *host, uint32_t flow, uint32_t last_offset);
int litedt_close_rsp(litedt_host_t *host, uint32_t flow);
int litedt_conn_rst(litedt_host_t *host, uint32_t flow);

#pragma pack(1)
typedef struct _retrans_key {
    uint32_t flow;
    uint32_t offset;
} retrans_key_t;
#pragma pack()

#ifdef ENABLE_LITEDT_CHECKSUM
void calculate_checksum(litedt_header_t *buf, size_t len)
{
    uint32_t checksum = LITEDT_CHECKSUM;
    uint32_t tmp = 0;
    uint32_t *now = (uint32_t *)buf;
    buf->checksum = 0;
    while (len > 0) {
        if (len < sizeof(uint32_t)) {
            memcpy(&tmp, now, len);
            checksum ^= tmp;
            break;
        } else {
            checksum ^= *(now++);
            len -= sizeof(uint32_t);
        }
    }
    buf->checksum = checksum;
}

int verify_checksum(litedt_header_t *buf, size_t len)
{
    uint32_t checksum = buf->checksum, bak = buf->checksum;
    uint32_t tmp = 0;
    uint32_t *now = (uint32_t *)buf;
    buf->checksum = 0;
    while (len > 0) {
        if (len < sizeof(uint32_t)) {
            memcpy(&tmp, now, len);
            checksum ^= tmp;
            break;
        } else {
            checksum ^= *(now++);
            len -= sizeof(uint32_t);
        }
    }
    buf->checksum = bak;
    return checksum == LITEDT_CHECKSUM;
}
#endif

int socket_send(litedt_host_t *host, const void *buf, size_t len, int force)
{
    int ret;
    if (!force && host->send_bytes + len / 2 > host->send_bytes_limit)
        return SEND_FLOW_CONTROL; // flow control
    host->send_bytes += len;
    host->stat.send_bytes_stat += len;
    ret = sendto(host->sockfd, buf, len, 0, (struct sockaddr *)
                 &host->remote_addr, sizeof(struct sockaddr));
    if (ret < (int)len)
        ++host->stat.send_error;
    return ret;
}

int64_t get_retrans_time(litedt_host_t *host, int64_t cur_time)
{
    if (host->rtt > g_config.max_rtt)
        return cur_time + (int)(g_config.max_rtt * g_config.timeout_rtt_ratio);
    else if (host->rtt < g_config.min_rtt)
        return cur_time + (int)(g_config.min_rtt * g_config.timeout_rtt_ratio);
    else
        return cur_time + (int)(host->rtt * g_config.timeout_rtt_ratio);
}

uint32_t conn_hash(void *key)
{
    return *(uint32_t *)key;
}

uint32_t retrans_hash(void *key)
{
    retrans_key_t *retrans = (retrans_key_t *)key;
    return (retrans->flow << 4) + retrans->offset;
}

litedt_conn_t* find_connection(litedt_host_t *host, uint32_t flow)
{
    litedt_conn_t *conn = (litedt_conn_t *)queue_get(&host->conn_queue, &flow);
    return conn;
}

int create_connection(litedt_host_t *host, uint32_t flow, uint16_t map_id, 
                        int status)
{
    int ret = 0;
    int64_t cur_time;
    litedt_conn_t conn;
    if (find_connection(host, flow) != NULL)
        return RECORD_EXISTS;
    if (status == CONN_ESTABLISHED && host->connect_cb) {
        ret = host->connect_cb(host, flow, map_id);
        if (ret)
            return ret;
    }
    cur_time = get_curtime();
    conn.last_responsed = cur_time;
    conn.next_ack_time = cur_time + NORMAL_ACK_DELAY;
    conn.map_id = map_id;
    conn.flow = flow;
    conn.write_offset = 0;
    conn.send_offset = 0;
    conn.swin_start = 0;
    conn.swin_size = g_config.buffer_size; // default window size
    conn.status = status;
    conn.ack_list = (uint32_t *)malloc(sizeof(uint32_t) * g_config.ack_size);
    conn.ack_num = 0;
    conn.reack_times = 0;
    conn.notify_recvnew = 0;
    conn.notify_recv = 1;
    conn.notify_send = 0;
    rbuf_init(&conn.send_buf, g_config.buffer_size / RBUF_BLOCK_SIZE);
    rbuf_init(&conn.recv_buf, g_config.buffer_size / RBUF_BLOCK_SIZE);
    rbuf_window_info(&conn.recv_buf, &conn.rwin_start, &conn.rwin_size);
    ret = queue_append(&host->conn_queue, &flow, &conn);
    if (ret != 0) {
        DBG("create connection %u failed: %d\n", flow, ret);
        return ret;
    }

    if (!host->conn_num && host->event_time_cb) {
        host->event_time_cb(host, BUSY_INTERVAL);
    }
    ++host->conn_num;

    DBG("create connection %u success\n", flow);
    return ret;
}

void release_connection(litedt_host_t *host, uint32_t flow)
{
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

    free(conn->ack_list);
    rbuf_fini(&conn->send_buf);
    rbuf_fini(&conn->recv_buf);
    queue_del(&host->conn_queue, &flow);

    --host->conn_num;
    if (!host->conn_num && host->event_time_cb) {
        host->event_time_cb(host, IDLE_INTERVAL);
    }
    DBG("connection %u released\n", flow);
}

void release_all_connections(litedt_host_t *host)
{
    hash_node_t *q_it;
    for (q_it = queue_first(&host->conn_queue); q_it != NULL;) {
        litedt_conn_t *conn = (litedt_conn_t *)queue_value(&host->conn_queue,
                                                           q_it);
        q_it = queue_next(&host->conn_queue, q_it);

        release_connection(host, conn->flow);
    }

}

litedt_retrans_t* find_retrans(litedt_host_t *host, uint32_t flow, 
                                uint32_t offset)
{
    litedt_retrans_t *rt;
    retrans_key_t rk;

    rk.flow = flow;
    rk.offset = offset;
    rt = (litedt_retrans_t *)queue_get(&host->retrans_queue, &rk);

    return rt;
}

int create_retrans(litedt_host_t *host, uint32_t flow, uint32_t offset, 
                    uint32_t length, int64_t cur_time)
{
    litedt_retrans_t retrans, *last;
    retrans_key_t rk;
    int64_t retrans_time = get_retrans_time(host, cur_time);
    if (find_retrans(host, flow, offset) != NULL) 
        return RECORD_EXISTS;

    last = (litedt_retrans_t *)queue_back(&host->retrans_queue, &rk);
    if (last && retrans_time < last->retrans_time)
        retrans_time = last->retrans_time;

    retrans.turn = 0;
    retrans.retrans_time = retrans_time;
    retrans.flow = flow;
    retrans.offset = offset;
    retrans.length = length;

    rk.flow = flow;
    rk.offset = offset;
    return queue_append(&host->retrans_queue, &rk, &retrans);
}

void update_retrans(litedt_host_t *host, litedt_retrans_t *retrans, 
                    int64_t cur_time)
{
    litedt_retrans_t *last;
    retrans_key_t rk;
    int64_t retrans_time = get_retrans_time(host, cur_time);
    last = (litedt_retrans_t *)queue_back(&host->retrans_queue, &rk);
    if (last && retrans_time < last->retrans_time)
        retrans_time = last->retrans_time;

    ++retrans->turn;
    retrans->retrans_time = retrans_time;

    if (retrans->turn >= 10) {
        DBG("flow: %u, offset: %u, retrans %d times.\n", retrans->flow, 
            retrans->offset, retrans->turn);
    }
    
    rk.flow = retrans->flow;
    rk.offset = retrans->offset;
    queue_move_back(&host->retrans_queue, &rk);
}

void release_retrans(litedt_host_t *host, uint32_t flow, uint32_t offset)
{
    retrans_key_t rk;
    rk.flow = flow;
    rk.offset = offset;
    queue_del(&host->retrans_queue, &rk);
}

int handle_retrans(litedt_host_t *host, litedt_retrans_t *rt, int64_t cur_time)
{
    int ret = 0;
    uint32_t flow = rt->flow;
    litedt_conn_t *conn;
    if ((conn = find_connection(host, flow)) == NULL
        || conn->status >= CONN_CLOSE_WAIT) {
        // invalid retrans record
        DBG("remove invalid retrans record, flow=%u, offset=%u\n", flow,
            rt->offset);
        release_retrans(host, flow, rt->offset);
        return 0;
    }
    if (!LESS_EQUAL(conn->swin_start, rt->offset)) {
        // retrans record has expired
        release_retrans(host, flow, rt->offset);
        return 0;
    }
    //DBG("retrans: offset=%u, length=%u, cur_time=%"PRId64"\n", 
    //        rt->offset, rt->length, cur_time);
    if (host->send_bytes + rt->length / 2 + 20 <= host->send_bytes_limit) {
        ++host->stat.retrans_packet_post;
        ret = litedt_data_post(host, flow, rt->offset, rt->length, cur_time);
        update_retrans(host, rt, cur_time);
    }

    if (ret == SEND_FLOW_CONTROL)
        return ret;
    return 0;
}

int litedt_init(litedt_host_t *host)
{
    struct sockaddr_in addr;
    int flag = 1, ret, sock;
    int recv_buf = 2 * 1024 * 1024;
    if ((sock = socket(PF_INET, SOCK_DGRAM, 0)) < 0)
        return SOCKET_ERROR;
    ret = setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &flag, 
                     sizeof(int));
    if (ret < 0) {
        close(sock);
        return SOCKET_ERROR;
    }
    if (fcntl(sock, F_SETFL, fcntl(sock, F_GETFL) | O_NONBLOCK) < 0 ||
        fcntl(sock, F_SETFD, FD_CLOEXEC) < 0) { 
        close(sock);
        return SOCKET_ERROR;
    }
    if (setsockopt(sock, SOL_SOCKET, SO_RCVBUF, (const char*)&recv_buf, 
                   sizeof(int)) < 0) {
        close(sock);
        return SOCKET_ERROR;
    }

    bzero(&addr, sizeof(addr));
    addr.sin_port = htons(g_config.flow_local_port);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr(g_config.flow_local_addr);
    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(sock);
        return SOCKET_ERROR;
    }

    host->sockfd = sock;
    memset(&host->stat, 0, sizeof(host->stat));
    host->send_bytes = 0;
    host->send_bytes_limit = g_config.send_bytes_per_sec * FLOW_CTRL_UNIT;
    host->send_bytes_limit /= 1000;
    bzero(&host->remote_addr, sizeof(struct sockaddr_in));
    host->remote_online = 0;
    host->lock_remote_addr = 0;
    host->ping_id = 0;
    host->rtt = g_config.max_rtt;
    host->clear_send_time = 0;
    host->last_ping = 0;
    host->last_ping_rsp = get_curtime();
    host->conn_num = 0;
    host->conn_send = NULL;
    queue_init(&host->conn_queue, CONN_HASH_SIZE, sizeof(uint32_t), 
               sizeof(litedt_conn_t), conn_hash);
    queue_init(&host->retrans_queue, RETRANS_HASH_SIZE, sizeof(retrans_key_t), 
               sizeof(litedt_retrans_t), retrans_hash);

    host->connect_cb = NULL;
    host->close_cb   = NULL;
    host->receive_cb = NULL;
    host->send_cb    = NULL;

    return sock;
}

int litedt_ping_req(litedt_host_t *host)
{
    char buf[80];
    int64_t ping_time;
    uint32_t plen;
    litedt_header_t *header = (litedt_header_t *)buf;
    ping_req_t *req = (ping_req_t *)(buf + sizeof(litedt_header_t));
    
    ping_time = get_curtime();

    header->ver = LITEDT_VERSION;
    header->cmd = LITEDT_PING_REQ;
    header->flow = 0;

    req->ping_id = ++host->ping_id;
    memcpy(req->data, &ping_time, 8);

    plen = sizeof(litedt_header_t) + sizeof(ping_req_t);
    PACKET_CHECKSUM(header, plen);
    socket_send(host, buf, plen, 1);
    
    return 0;
}

int litedt_ping_rsp(litedt_host_t *host, ping_req_t *req)
{
    char buf[80];
    uint32_t plen;
    litedt_header_t *header = (litedt_header_t *)buf;
    ping_rsp_t *rsp = (ping_rsp_t *)(buf + sizeof(litedt_header_t));

    header->ver = LITEDT_VERSION;
    header->cmd = LITEDT_PING_RSP;
    header->flow = 0;

    rsp->ping_id = req->ping_id;
    memcpy(rsp->data, req->data, sizeof(rsp->data));

    plen = sizeof(litedt_header_t) + sizeof(ping_rsp_t);
    PACKET_CHECKSUM(header, plen);
    socket_send(host, buf, plen, 1);

    return 0;
}

int litedt_conn_req(litedt_host_t *host, uint32_t flow, uint16_t map_id)
{
    char buf[80];
    uint32_t plen;
    litedt_header_t *header = (litedt_header_t *)buf;
    conn_req_t *req = (conn_req_t *)(buf + sizeof(litedt_header_t));

    header->ver = LITEDT_VERSION;
    header->cmd = LITEDT_CONNECT_REQ;
    header->flow = flow;

    req->map_id = map_id;

    plen = sizeof(litedt_header_t) + sizeof(conn_req_t);
    PACKET_CHECKSUM(header, plen);
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
    PACKET_CHECKSUM(header, plen);
    socket_send(host, buf, plen, 1);
    
    return 0;
}

int litedt_data_post(litedt_host_t *host, uint32_t flow, uint32_t offset, 
                        uint32_t len, int64_t curtime)
{
    int send_ret = 0;
    char buf[MAX_DATA_SIZE + 50];
    uint32_t plen;
    litedt_conn_t *conn;
    if (!host->remote_online)
        return CLIENT_OFFLINE;
    if (len > MAX_DATA_SIZE)
        return PARAMETER_ERROR;
    if ((conn = find_connection(host, flow)) == NULL)
        return RECORD_NOT_FOUND;
    if (offset - conn->swin_start > conn->swin_size
        || offset + len - conn->swin_start > conn->swin_size)
        return OFFSET_OUT_OF_RANGE;
    
    litedt_header_t *header = (litedt_header_t *)buf;
    data_post_t *post = (data_post_t *)(buf + sizeof(litedt_header_t));
    
    header->ver = LITEDT_VERSION;
    header->cmd = LITEDT_DATA_POST;
    header->flow = flow;

    post->offset = offset;
    post->len = len;
    rbuf_read(&conn->send_buf, offset, post->data, len);
    ++host->stat.data_packet_post;

    if (conn->status != CONN_REQUEST) {
        plen = sizeof(litedt_header_t) + sizeof(data_post_t) + len;
        PACKET_CHECKSUM(header, plen);
        send_ret = socket_send(host, buf, plen, 0);
        if (send_ret >= 0)
            host->stat.send_bytes_data += plen;
    }

    if (find_retrans(host, flow, offset) == NULL) {
        int ret = create_retrans(host, flow, offset, len, curtime);
        if (ret) {
            DBG("create retrans record failed: offset=%u, len=%u, ret=%d\n",
                offset, len, ret);
        }
    }

    if (send_ret == SEND_FLOW_CONTROL)  {
        DBG("Warning: send data flow control!\n");
        return SEND_FLOW_CONTROL;
    }
    
    return 0;
}

int litedt_data_ack(litedt_host_t *host, uint32_t flow, int ack_list)
{
    char buf[MAX_DATA_SIZE];
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
        ack->ack_size = conn->ack_num;
        memcpy(ack->acks, conn->ack_list, conn->ack_num * sizeof(uint32_t));
    } else {
        ack->ack_size = 0;
    }

    plen = sizeof(litedt_header_t) + sizeof(data_ack_t) 
           + sizeof(ack->acks[0]) * ack->ack_size;
    PACKET_CHECKSUM(header, plen);
    socket_send(host, buf, plen, 1);
    host->stat.send_bytes_ack += plen;

    return 0;
}

int litedt_close_req(litedt_host_t *host, uint32_t flow, uint32_t last_offset)
{
    char buf[80];
    uint32_t plen;
    litedt_header_t *header = (litedt_header_t *)buf;
    close_req_t *req = (close_req_t *)(buf + sizeof(litedt_header_t));

    header->ver = LITEDT_VERSION;
    header->cmd = LITEDT_CLOSE_REQ;
    header->flow = flow;

    req->last_offset = last_offset;
    DBG("send close req: %u\n", last_offset);

    plen = sizeof(litedt_header_t) + sizeof(close_req_t);
    PACKET_CHECKSUM(header, plen);
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
    PACKET_CHECKSUM(header, plen);
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
    PACKET_CHECKSUM(header, plen);
    socket_send(host, buf, plen, 1);
    
    return 0;
}

int litedt_connect(litedt_host_t *host, uint32_t flow, uint16_t map_id)
{
    int ret = 0;
    if (!host->remote_online)
        return CLIENT_OFFLINE;
    if (find_connection(host, flow) == NULL) 
        ret = create_connection(host, flow, map_id, CONN_REQUEST);
    if (!ret)
        litedt_conn_req(host, flow, map_id);
    return ret;
}

int litedt_close(litedt_host_t *host, uint32_t flow)
{
    litedt_conn_t *conn;
    if ((conn = find_connection(host, flow)) == NULL)
        return RECORD_NOT_FOUND;
    if (conn->status <= CONN_ESTABLISHED) {
        conn->status = CONN_FIN_WAIT;
        litedt_close_req(host, flow, conn->write_offset);
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
        conn->write_offset = rbuf_write_pos(&conn->send_buf);
    }
    return 0;
}

int litedt_recv(litedt_host_t *host, uint32_t flow, char *buf, uint32_t len)
{
    int ret;
    litedt_conn_t *conn;
    if ((conn = find_connection(host, flow)) == NULL)
        return RECORD_NOT_FOUND;
    ret = rbuf_read_front(&conn->recv_buf, buf, len);
    if (ret > 0)
        rbuf_release(&conn->recv_buf, ret);
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
    litedt_conn_t *conn;
    if ((conn = find_connection(host, flow)) == NULL)
        return;
    rbuf_release(&conn->recv_buf, len);
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
    host->lock_remote_addr = 1;
    host->remote_addr.sin_family = AF_INET;
    host->remote_addr.sin_addr.s_addr = inet_addr(addr);
    host->remote_addr.sin_port = htons(port);
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

int litedt_on_ping_req(litedt_host_t *host, ping_req_t *req)
{
    int64_t cur_time = get_curtime();

    host->last_ping_rsp = cur_time;
    litedt_ping_rsp(host, req);

    return 0;
}

int litedt_on_ping_rsp(litedt_host_t *host, ping_rsp_t *rsp)
{
    int64_t cur_time, ping_time;
    if (rsp->ping_id != host->ping_id)
        return 0;
    cur_time = get_curtime();
    memcpy(&ping_time, rsp->data, 8);
    
    host->last_ping_rsp = cur_time;
    host->rtt = cur_time - ping_time;
    DBG("ping rsp, rtt=%u, conn=%d\n", host->rtt, host->conn_num);

    return 0;
}

int litedt_on_conn_req(litedt_host_t *host, uint32_t flow, conn_req_t *req)
{
    int ret = 0;
    litedt_conn_t *conn = find_connection(host, flow);
    if (conn) {
        litedt_conn_rsp(host, flow, 0);
        return 0;
    }

    ret = create_connection(host, flow, req->map_id, CONN_ESTABLISHED);
    litedt_conn_rsp(host, flow, ret);
    litedt_data_ack(host, flow, 0);

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

int litedt_on_data_recv(litedt_host_t *host, uint32_t flow, data_post_t *data, 
                        int64_t cur_time)
{
    int ret, readable = 0;
    litedt_conn_t *conn = find_connection(host, flow);
    if (NULL == conn)
        return RECORD_NOT_FOUND;
    if (conn->status == CONN_REQUEST)
        conn->status = CONN_ESTABLISHED;
    
    ret = rbuf_write(&conn->recv_buf, data->offset, data->data, data->len);
    if (ret == 1 || ret == RBUF_OUT_OF_RANGE)
        ++host->stat.repeat_packet_recv;
    if (ret >= 0) {
        uint32_t ic = 0, iv = 0, data_dup = 0;
        rbuf_window_info(&conn->recv_buf, &conn->rwin_start, &conn->rwin_size);
        readable = rbuf_readable_bytes(&conn->recv_buf);
        conn->rwin_start += readable;
        conn->rwin_size  -= readable;

        while (ic < conn->ack_num) {
            if (conn->ack_list[ic] == data->offset)
                data_dup = 1;
            if (conn->ack_list[ic] - conn->rwin_start <= conn->rwin_size) {
                conn->ack_list[iv++] = conn->ack_list[ic];
            } 
            ++ic;
        }
        if (!data_dup)
            conn->ack_list[iv++] = data->offset;
        conn->ack_num = iv;
    }
    if (conn->ack_num >= g_config.ack_size) {
        // send ack msg now and clear ack list
        int remain = g_config.ack_size >> 1;
        int shift = g_config.ack_size - remain;
        litedt_data_ack(host, flow, 1);
        memcpy(conn->ack_list, conn->ack_list + shift, 
                remain * sizeof(uint32_t));
        conn->ack_num = remain;
        conn->next_ack_time = cur_time + REACK_DELAY;
        conn->reack_times = 0;
    } else {
        // send ack msg later
        if (conn->next_ack_time > cur_time + FAST_ACK_DELAY)
            conn->next_ack_time = cur_time + FAST_ACK_DELAY;
        conn->reack_times = 1;
    }

    if ((conn->notify_recv || conn->notify_recvnew) && host->receive_cb 
        && readable > 0)
        host->receive_cb(host, flow, readable);

    return 0;
}

int  litedt_on_data_ack(litedt_host_t *host, uint32_t flow, data_ack_t *ack,
                        int64_t cur_time)
{
    uint32_t i;
    litedt_conn_t *conn = find_connection(host, flow);
    if (NULL == conn)
        return RECORD_NOT_FOUND;
    if (conn->status == CONN_REQUEST)
        conn->status = CONN_ESTABLISHED;

    for (i = 0; i < ack->ack_size; i++) {
        uint32_t offset = ack->acks[i];
        release_retrans(host, flow, offset);
    }

    if (LESS_EQUAL(conn->swin_start, ack->win_start) && 
        LESS_EQUAL(ack->win_start, conn->send_offset)) {

        uint32_t release_size, sendbuf_start, sendbuf_size;
        conn->last_responsed = cur_time;
        conn->swin_start = ack->win_start;
        conn->swin_size = ack->win_size;

        rbuf_window_info(&conn->send_buf, &sendbuf_start, &sendbuf_size);
        release_size = conn->swin_start - sendbuf_start;
        if (release_size > 0)
            rbuf_release(&conn->send_buf, release_size);

        // check if retrans record missing
        if (ack->win_start != conn->send_offset && 
            find_retrans(host, flow, ack->win_start) == NULL) {
            LOG("Warning: flow %u, offset %u retrans record lost\n", flow,
                ack->win_start);
            uint32_t len = conn->send_offset - ack->win_start;
            if (len > MAX_DATA_SIZE)
                len = MAX_DATA_SIZE;
            create_retrans(host, flow, ack->win_start, len, cur_time);
        }
    }

    if (conn->notify_send && host->send_cb 
        && conn->status == CONN_ESTABLISHED) {
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
    DBG("recv close req: end_offset=%u\n", req->last_offset);

    if (conn->status == CONN_FIN_WAIT) {
        release_connection(host, flow);
        litedt_close_rsp(host, flow);
    } else if (conn->status != CONN_CLOSED) {
        uint32_t win_start, win_len, readable;
        conn->status = CONN_CLOSE_WAIT;
        rbuf_window_info(&conn->recv_buf, &win_start, &win_len);
        readable = rbuf_readable_bytes(&conn->recv_buf);
        if (win_start + readable == req->last_offset) {
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

void litedt_io_event(litedt_host_t *host, int64_t cur_time)
{
    int recv_len, ret = 0;
    uint32_t flow;
    static struct sockaddr_in addr;
    int hlen = sizeof(litedt_header_t);
    socklen_t addr_len = sizeof(addr);
    static char buf[2048];
    char ip[ADDRESS_MAX_LEN];
    litedt_header_t *header = (litedt_header_t *)buf;

    while ((recv_len = recvfrom(host->sockfd, buf, sizeof(buf), 0, 
            (struct sockaddr *)&addr, &addr_len)) >= 0) {
        if ((host->remote_online || host->lock_remote_addr)
            && addr.sin_addr.s_addr != host->remote_addr.sin_addr.s_addr) 
            continue;
        host->stat.recv_bytes_stat += recv_len;
        if (recv_len < hlen)
            continue;
        if (header->ver != LITEDT_VERSION)
            continue;
#ifdef ENABLE_LITEDT_CHECKSUM
        if (!verify_checksum(header, recv_len)) {
            inet_ntop(AF_INET, &addr.sin_addr, ip, ADDRESS_MAX_LEN);
            LOG("Warning: error packet from %s:%u, len: %u\n", ip, 
                ntohs(addr.sin_port), recv_len);
#ifdef DUMP_ERRPACK
            int efd = open("err_packet.dump", O_APPEND | O_WRONLY | O_CREAT, 0666);
            write(efd, buf, recv_len);
            close(efd);
#endif
            continue;
        }
#endif
        
        if (!host->remote_online) {
            inet_ntop(AF_INET, &addr.sin_addr, ip, ADDRESS_MAX_LEN);
            LOG("Remote host %s:%u is online and active\n", ip, 
                    ntohs(addr.sin_port));
            host->remote_online = 1;
            memcpy(&host->remote_addr, &addr, sizeof(struct sockaddr_in));

            if (host->conn_num > 0 && host->event_time_cb)
                host->event_time_cb(host, BUSY_INTERVAL);
        }

        flow = header->flow;
        switch (header->cmd) {
        case LITEDT_PING_REQ:
            if (recv_len < hlen + (int)sizeof(ping_req_t))
                break;
            ret = litedt_on_ping_req(host, (ping_req_t *)(buf + hlen));
            break;
        case LITEDT_PING_RSP:
            if (recv_len < hlen + (int)sizeof(ping_rsp_t))
                break;
            ret = litedt_on_ping_rsp(host, (ping_rsp_t *)(buf + hlen));
            break;
        case LITEDT_CONNECT_REQ:
            if (recv_len < hlen + (int)sizeof(conn_req_t))
                break;
            ret = litedt_on_conn_req(host, flow, (conn_req_t *)(buf + hlen));
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
                ret = litedt_on_data_recv(host, flow, data, cur_time);
                break;
            }
        case LITEDT_DATA_ACK: {
                data_ack_t *ack;
                ack = (data_ack_t *)(buf + hlen);
                if (recv_len < hlen + (int)sizeof(data_ack_t))
                    break;
                if (recv_len < hlen + (int)sizeof(data_ack_t)
                    + ack->ack_size * (int)sizeof(uint32_t))
                    break;
                host->stat.recv_bytes_ack += recv_len;
                ret = litedt_on_data_ack(host, flow, ack, cur_time);
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

        default:
            break;
        }
        if (ret != 0) {
            // connection error, send rst to client
            LOG("Connection %u error, reset\n", flow);
            litedt_conn_rst(host, flow);
        }
    }
}

void litedt_time_event(litedt_host_t *host, int64_t cur_time)
{
    int ret = 0, flow_ctrl = 1;
    hash_node_t *q_it, *q_start;

    // send ping request
    if (host->remote_online || host->lock_remote_addr) {
        if (cur_time - host->last_ping >= PING_INTERVAL_ONL) {
            if (host->remote_online || cur_time - host->last_ping 
                    >= PING_INTERVAL_OFFL) {
                litedt_ping_req(host);
                host->last_ping = cur_time;
            }
        }
    }

    if (!host->remote_online) 
        return;

    if (cur_time - host->clear_send_time >= FLOW_CTRL_UNIT) {
        host->send_bytes = 0;
        host->clear_send_time = cur_time;
    }
    
    uint32_t client_timeout = g_config.keepalive_timeout * 1000;
    if (cur_time - host->last_ping_rsp > client_timeout) {
        char ip[ADDRESS_MAX_LEN];
        uint16_t port = ntohs(host->remote_addr.sin_port);
        inet_ntop(AF_INET, &host->remote_addr.sin_addr, ip, ADDRESS_MAX_LEN);
        LOG("Remote host %s:%u is offline\n", ip, port);

        release_all_connections(host);
        host->remote_online = 0;
        if (host->event_time_cb)
            host->event_time_cb(host, IDLE_INTERVAL);
    }

    // check retrans list and retransfer package
    ret = 0;
    for (q_it = queue_first(&host->retrans_queue); !ret && q_it != NULL;) { 
        litedt_retrans_t *retrans 
            = (litedt_retrans_t *)queue_value(&host->retrans_queue, q_it);
        q_it = queue_next(&host->retrans_queue, q_it);

        if (retrans->retrans_time > cur_time) 
            break;
        ret = handle_retrans(host, retrans, cur_time);
    }
    
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
            && conn->status == CONN_ESTABLISHED) {
            int writable = rbuf_writable_bytes(&conn->send_buf);
            if (writable > 0)
                host->send_cb(host, conn->flow, writable);
        }
        // send ack msg to synchronize data window
        if (cur_time >= conn->next_ack_time) {
            if (conn->status == CONN_ESTABLISHED 
                || conn->status == CONN_CLOSE_WAIT)
                litedt_data_ack(host, conn->flow, conn->reack_times > 0);
            else if (conn->status == CONN_FIN_WAIT)
                litedt_close_req(host, conn->flow, conn->write_offset);
            else if (conn->status == CONN_REQUEST)
                litedt_conn_req(host, conn->flow, conn->map_id);
            else if (conn->status == CONN_CLOSED) {
                uint32_t readable = rbuf_readable_bytes(&conn->recv_buf);
                if (!readable) {
                    release_connection(host, conn->flow);
                    continue;
                }
            }
            if (conn->reack_times > 0) {
                --conn->reack_times;
                conn->next_ack_time = cur_time + REACK_DELAY;
            } else {
                conn->next_ack_time = cur_time + NORMAL_ACK_DELAY;
            }
        }
    }

    q_it = q_start = host->conn_send;
    do {
        if (q_it ==  NULL) {
            q_it = queue_first(&host->conn_queue);
            if (q_start == q_it)
                break;
        }
        litedt_conn_t *conn = (litedt_conn_t *)queue_value(&host->conn_queue,
                                                           q_it);
        // check send buffer and post data to network
        if (conn->status == CONN_ESTABLISHED || conn->status == CONN_FIN_WAIT) {
            while (conn->write_offset != conn->send_offset) {
                uint32_t bytes = conn->write_offset - conn->send_offset;
                uint32_t swin_end = conn->swin_start + conn->swin_size;
                if (bytes > swin_end - conn->send_offset)
                    bytes = swin_end - conn->send_offset;
                if (bytes > MAX_DATA_SIZE)
                    bytes = MAX_DATA_SIZE;
                if (0 == bytes)
                    break;
                uint32_t predict = bytes / 2 + 20;
                if (host->send_bytes + predict > host->send_bytes_limit) {
                    flow_ctrl = 0;
                    break;
                }
               
                ret = litedt_data_post(host, conn->flow, conn->send_offset, 
                                       bytes, cur_time);
                if (!ret) {
                    conn->send_offset += bytes;
                } else {
                    if (ret == SEND_FLOW_CONTROL)
                        flow_ctrl = 0;
                    break;
                }
            }
        }

        q_it = queue_next(&host->conn_queue, q_it);
    } while (q_it != q_start && flow_ctrl);
    // next time start from here
    host->conn_send = q_it;
    
}

litedt_stat_t* litedt_get_stat(litedt_host_t *host)
{
    host->stat.connection_num = host->conn_num;
    host->stat.rtt = host->rtt;
    return &host->stat;
}

void litedt_clear_stat(litedt_host_t *host)
{
    memset(&host->stat, 0, sizeof(litedt_stat_t));
}

void litedt_fini(litedt_host_t *host)
{
    close(host->sockfd);
    while (!queue_empty(&host->conn_queue)) {
        uint32_t ckey;
        litedt_conn_t *conn = (litedt_conn_t *)queue_front(&host->conn_queue, 
                                                           &ckey);
        release_connection(host, conn->flow);
    }
    while (!queue_empty(&host->retrans_queue)) {
        retrans_key_t rkey;
        litedt_retrans_t *retrans 
            = (litedt_retrans_t *)queue_front(&host->retrans_queue, &rkey);
        release_retrans(host, retrans->flow, retrans->offset);
    }
}

