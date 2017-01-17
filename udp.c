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
#include "udp.h"
#include "stat.h"
#include "util.h"
#include "hashqueue.h"
#include "liteflow.h"

#define BUFFER_SIZE 65536
#define UDP_HASH_SIZE 1013
#define ADDRESS_MAX_LEN 50

typedef struct _hsock_data {
    uint16_t local_port;
    uint16_t map_id;
    struct ev_io w_read;
} hsock_data_t;

typedef struct _udp_flow {
    struct ev_io w_read;
    int sock_fd;
    int host_fd;
    struct sockaddr_in sock_addr;
} udp_flow_t;

#pragma pack(1)
typedef struct _udp_key {
    uint32_t ip;
    uint16_t port;
} udp_key_t;
#pragma pack()

typedef struct _udp_bind {
    uint32_t flow;
    int64_t expire;
    int closed;
} udp_bind_t;

static struct ev_loop *g_loop;
static litedt_host_t *g_litedt;
static char buf[BUFFER_SIZE]; 
static hash_queue_t udp_tab;
static struct ev_timer udp_timeout_watcher;

void udp_host_recv(struct ev_loop *loop, struct ev_io *watcher, int revents);
void udp_local_recv(struct ev_loop *loop, struct ev_io *watcher, int revents);
void udp_remote_close(litedt_host_t *host, flow_info_t *flow);
void udp_remote_recv(litedt_host_t *host, flow_info_t *flow, int readable);
void udp_remote_send(litedt_host_t *host, flow_info_t *flow, int writable);

void udp_timeout_cb(struct ev_loop *loop, struct ev_timer *w, int revents)
{
    if (!(revents & EV_TIMER))
        return;

    hash_node_t *q_it;
    int64_t cur_time = ev_now(loop) * 1000;
    for (q_it = queue_first(&udp_tab); q_it != NULL;) {
        udp_bind_t *ubind = (udp_bind_t *)queue_value(&udp_tab, q_it);
        q_it = queue_next(&udp_tab, q_it);
        if (cur_time >= ubind->expire) {
            if (ubind->closed)
                continue; // udp map was already closed
            // udp map expired
            litedt_close(g_litedt, ubind->flow);
            ubind->closed = 1;
        } else {
            break;
        }
    }
}

uint32_t udp_hash(void *key)
{
    udp_key_t *uk = (udp_key_t *)key;
    return ((uint32_t)uk->port << 16) + uk->ip;
}

int create_udp_bind(struct sockaddr_in *addr, int host_fd, uint16_t map_id)
{
    udp_key_t ukey;
    udp_bind_t ubind;
    int ret;
    int64_t cur_time = ev_now(g_loop) * 1000;
    uint32_t flow;
    udp_flow_t *udp_ext = (udp_flow_t *)malloc(sizeof(udp_flow_t));
    if (NULL == udp_ext) {
        LOG("Warning: malloc failed\n");
        return -1;
    }

    flow = liteflow_flowid();
    ret = create_flow(flow);
    if (ret == 0) 
        ret = litedt_connect(g_litedt, flow, map_id);
    if (ret != 0) {
        release_flow(flow);
        free(udp_ext);
        return -1;
    }

    flow_info_t *info = find_flow(flow);
    info->ext = udp_ext;
    info->remote_recv_cb = udp_remote_recv;
    info->remote_send_cb = udp_remote_send;
    info->remote_close_cb = udp_remote_close;
    memcpy(&udp_ext->sock_addr, addr, sizeof(struct sockaddr_in));
    udp_ext->sock_fd = 0;
    udp_ext->host_fd = host_fd;
    litedt_set_notify_recv(g_litedt, flow, 0);
    litedt_set_notify_recvnew(g_litedt, flow, 1);

    ukey.ip = addr->sin_addr.s_addr;
    ukey.port = addr->sin_port;
    ubind.flow = flow;
    ubind.expire = cur_time + g_config.udp_timeout * 1000;
    ubind.closed = 0;
    ret = queue_append(&udp_tab, &ukey, &ubind);
    if (ret != 0) {
        release_flow(flow);
        free(udp_ext);
        return -1;
    }
    return 0;
}

int udp_init(struct ev_loop *loop, litedt_host_t *host)
{
    int ret;
    g_loop = loop;
    g_litedt = host;
    ev_timer_init(&udp_timeout_watcher, udp_timeout_cb, 1.0, 1.0);
    ev_timer_start(loop, &udp_timeout_watcher);
    ret = queue_init(&udp_tab, UDP_HASH_SIZE, sizeof(udp_key_t),
                     sizeof(udp_bind_t), udp_hash, 0);
    return ret;
}

int udp_local_init(struct ev_loop *loop, int port, int mapid)
{
    int sockfd, flag;
    struct sockaddr_in addr;
    hsock_data_t *host;

    if ((sockfd = socket(PF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("socket error");
        return -1;
    }
    flag = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &flag, sizeof(int))
            == -1) { 
        perror("setsockopt"); 
        close(sockfd);
        return -1;
    } 
    if (fcntl(sockfd, F_SETFL, fcntl(sockfd, F_GETFL) | O_NONBLOCK) < 0 ||
            fcntl(sockfd, F_SETFD, FD_CLOEXEC) < 0) { 
        perror("fcntl"); 
        close(sockfd);
        return -1;
    }

    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr(g_config.map_bind_addr);

    if (bind(sockfd, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
        perror("bind error");
        close(sockfd);
        return -2;
    }

    host = (hsock_data_t *)malloc(sizeof(hsock_data_t));
    if (NULL == host) {
        LOG("Warning: malloc failed\n");
        close(sockfd);
        return -4;
    }

    host->local_port = port;
    host->map_id = mapid;
    host->w_read.data = host;
    ev_io_init(&host->w_read, udp_host_recv, sockfd, EV_READ);
    ev_io_start(loop, &host->w_read);

    return 0;
}

void udp_host_recv(struct ev_loop *loop, struct ev_io *watcher, int revents)
{
    int read_len, writable, ret;
    uint32_t flow;
    udp_key_t ukey;
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);
    hsock_data_t *hsock = (hsock_data_t *)watcher->data;
    int64_t cur_time = ev_now(loop) * 1000;

    if (!(EV_READ & revents)) 
        return;

    do {
        read_len = BUFFER_SIZE;
        read_len = recvfrom(watcher->fd, buf, read_len, 0, 
            (struct sockaddr *)&addr, &addr_len);
        if (read_len < 0) 
            continue;

        ukey.ip = addr.sin_addr.s_addr;
        ukey.port = addr.sin_port;
        udp_bind_t *ubind = (udp_bind_t *)queue_get(&udp_tab, &ukey);
        if (NULL == ubind) {
            // udp bind record not found, create new flow
            ret = create_udp_bind(&addr, watcher->fd, hsock->map_id);
            if (ret != 0)
                continue;
            ubind = (udp_bind_t *)queue_get(&udp_tab, &ukey);
        } else {
            ubind->expire = cur_time + g_config.udp_timeout * 1000;
            queue_move_back(&udp_tab, &ukey);
        }
        flow = ubind->flow;
        writable = litedt_writable_bytes(g_litedt, flow);
        if (read_len + 2 > writable) {
            DBG("LiteDT Buffer is full, udp packet lost.\n");
            litedt_stat_t *stat = litedt_get_stat(g_litedt);
            ++stat->udp_lost;
            continue;
        }
        if (read_len > 0xFFFF) {
            LOG("Error: udp packet too large\n");
            continue;
        }
        // forward udp packet
        litedt_send(g_litedt, flow, (char *)&read_len, 2);
        litedt_send(g_litedt, flow, buf, read_len);
    } while (read_len >= 0);
}

void udp_local_recv(struct ev_loop *loop, struct ev_io *watcher, int revents)
{
    int read_len, writable;
    uint32_t flow = (uint32_t)(long)watcher->data;

    if (!(EV_READ & revents)) 
        return;

    do {
        read_len = BUFFER_SIZE;
        read_len = recv(watcher->fd, buf, read_len, 0);
        if (read_len < 0) 
            continue;

        writable = litedt_writable_bytes(g_litedt, flow);
        if (read_len + 2 > writable) {
            DBG("LiteDT Buffer is full, udp packet lost.\n");
            litedt_stat_t *stat = litedt_get_stat(g_litedt);
            ++stat->udp_lost;
            continue;
        }
        // forward udp packet
        litedt_send(g_litedt, flow, (char *)&read_len, 2);
        litedt_send(g_litedt, flow, buf, read_len);
    } while (read_len > 0);
}

int udp_remote_init(litedt_host_t *host, uint32_t flow, char *ip, int port)
{
    int sockfd, ret;
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(struct sockaddr);

    if ((sockfd = socket(PF_INET, SOCK_DGRAM, 0)) < 0) {
        LOG("Warning: create udp socket error");
        return -1;
    }
    if (fcntl(sockfd, F_SETFL, fcntl(sockfd, F_GETFL) | O_NONBLOCK) < 0 ||
            fcntl(sockfd, F_SETFD, FD_CLOEXEC) < 0) { 
        LOG("Warning: set socket nonblock faild\n");
        close(sockfd);
        return -1;
    }
    udp_flow_t *udp_ext = (udp_flow_t *)malloc(sizeof(udp_flow_t));
    if (NULL == udp_ext) {
        LOG("Warning: malloc failed\n");
        close(sockfd);
        return -1;
    }

    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr(ip);

    ret = create_flow(flow);
    if (ret != 0) {
        close(sockfd);
        return ret;
    }

    ret = connect(sockfd, (struct sockaddr*)&addr, addr_len);
    if (ret < 0 && errno != EINPROGRESS) {
        close(sockfd);
        return LITEFLOW_CONNECT_FAIL;
    }

    flow_info_t *info = find_flow(flow);
    info->ext = udp_ext;
    info->remote_recv_cb = udp_remote_recv;
    info->remote_send_cb = udp_remote_send;
    info->remote_close_cb = udp_remote_close;

    udp_ext->sock_fd = sockfd;
    udp_ext->w_read.data  = (void *)(long)flow;
    ev_io_init(&udp_ext->w_read, udp_local_recv, sockfd, EV_READ);
    ev_io_start(g_loop, &udp_ext->w_read);
    litedt_set_notify_recv(g_litedt, flow, 0);
    litedt_set_notify_recvnew(g_litedt, flow, 1);

    return 0;
}

void udp_remote_recv(litedt_host_t *host, flow_info_t *flow, int readable)
{
    int read_len;
    udp_flow_t *udp_ext = (udp_flow_t *)flow->ext;

    while (readable > 0) {
        read_len = 0;
        litedt_peek(host, flow->flow, (char *)&read_len, 2); // get udp length
        if (readable < read_len + 2)
            break;
        litedt_recv_skip(host, flow->flow, 2);
        litedt_recv(host, flow->flow, buf, read_len);
        if (udp_ext->sock_fd) {
            send(udp_ext->sock_fd, buf, read_len, 0);
        } else {
            sendto(udp_ext->host_fd, buf, read_len, 0, (struct sockaddr *)
                &udp_ext->sock_addr, sizeof(struct sockaddr));
        }
        readable -= read_len + 2;
    }
}

void udp_remote_send(litedt_host_t *host, flow_info_t *flow, int writable)
{
    // no need to wait flow become writable
    udp_flow_t *udp_ext = (udp_flow_t *)flow->ext;
    ev_io_start(g_loop, &udp_ext->w_read);
    litedt_set_notify_send(host, flow->flow, 0);
}

void udp_remote_close(litedt_host_t *host, flow_info_t *flow)
{
    if (flow->ext == NULL)
        return;
    udp_flow_t *udp_ext = (udp_flow_t *)flow->ext;

    if (udp_ext->sock_fd) {
        ev_io_stop(g_loop, &udp_ext->w_read);
        close(udp_ext->sock_fd);
    } else {
        char ip[ADDRESS_MAX_LEN];
        udp_key_t ukey;

        ukey.ip = udp_ext->sock_addr.sin_addr.s_addr;
        ukey.port = udp_ext->sock_addr.sin_port;
        queue_del(&udp_tab, &ukey);
        inet_ntop(AF_INET, &udp_ext->sock_addr.sin_addr, ip, ADDRESS_MAX_LEN);
        DBG("udp connection flow:%u, from %s:%u was expired.\n", 
            flow->flow, ip, ntohs(udp_ext->sock_addr.sin_port));
    }

    free(udp_ext);
    flow->ext = NULL;
}
