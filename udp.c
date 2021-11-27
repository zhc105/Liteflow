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
#include "udp.h"
#include "util.h"
#include "hashqueue.h"
#include "liteflow.h"

#define BUFFER_SIZE 65536
#define UDP_HASH_SIZE 1013

typedef struct _hsock_data {
    char local_addr[ADDRESS_MAX_LEN];
    uint16_t local_port;
    uint16_t tunnel_id;
    uint16_t peer_forward;
    struct ev_io w_read;
} hsock_data_t;

typedef struct _udp_flow {
    struct ev_io w_read;
    int sock_fd;
    int host_fd;
    struct sockaddr_in sock_addr;
    peer_info_t *peer;
    uint32_t flow;
} udp_flow_t;

#pragma pack(1)
typedef struct _udp_key {
    uint32_t ip;
    uint16_t port;
} udp_key_t;
#pragma pack()

typedef struct _udp_bind {
    peer_info_t     *peer;
    uint32_t        flow;
    litedt_time_t   expire;
    int             closed;
} udp_bind_t;

static struct ev_loop *g_loop;
static char buf[BUFFER_SIZE];
static hash_queue_t udp_tab;
static struct ev_timer udp_timeout_watcher;
static hsock_data_t* hsock_list[MAX_PORT_NUM + 1] = { 0 };
static int hsock_cnt = 0;

void udp_host_recv(struct ev_loop *loop, struct ev_io *watcher, int revents);
void udp_local_recv(struct ev_loop *loop, struct ev_io *watcher, int revents);
void udp_remote_close(litedt_host_t *host, flow_info_t *flow);
void udp_remote_recv(litedt_host_t *host, flow_info_t *flow, int readable);
void udp_remote_send(litedt_host_t *host, flow_info_t *flow, int writable);

void udp_timeout_cb(struct ev_loop *loop, struct ev_timer *w, int revents)
{
    if (!(revents & EV_TIMER))
        return;

    queue_node_t *q_it;
    litedt_time_t cur_time = get_curtime();
    for (q_it = queue_first(&udp_tab); q_it != NULL;) {
        udp_bind_t *ubind = (udp_bind_t *)queue_value(&udp_tab, q_it);
        q_it = queue_next(&udp_tab, q_it);
        if (cur_time >= ubind->expire) {
            if (ubind->closed)
                continue; // udp map was already closed
            // udp map expired
            litedt_close(&ubind->peer->dt, ubind->flow);
            ubind->closed = 1;
        } else {
            break;
        }
    }
}

uint32_t udp_hash(const void *key)
{
    udp_key_t *uk = (udp_key_t *)key;
    return ((uint32_t)uk->port << 16) + uk->ip;
}

int create_udp_bind(
    struct sockaddr_in *addr,
    int host_fd,
    uint16_t tunnel_id,
    uint16_t peer_forward)
{
    udp_key_t ukey;
    udp_bind_t ubind;
    int ret;
    litedt_time_t cur_time = get_curtime();
    uint32_t flow;
    peer_info_t *peer = NULL;
    udp_flow_t *udp_ext = NULL;

    if ((peer = find_peer(peer_forward)) == NULL) {
        LOG("Failed to forward connection: peer[%u] offline\n",
                peer_forward);
        return -1;
    }

    udp_ext = (udp_flow_t *)malloc(sizeof(udp_flow_t));
    if (NULL == udp_ext) {
        LOG("Warning: malloc failed\n");
        return -1;
    }

    flow = next_flow_id(peer);
    ret = create_flow(peer, flow);
    if (ret == 0)
        ret = litedt_connect(&peer->dt, flow, tunnel_id);
    if (ret != 0) {
        release_flow(peer, flow);
        free(udp_ext);
        return -1;
    }

    flow_info_t *info = find_flow(peer, flow);
    info->ext = udp_ext;
    info->remote_recv_cb = udp_remote_recv;
    info->remote_send_cb = udp_remote_send;
    info->remote_close_cb = udp_remote_close;
    memcpy(&udp_ext->sock_addr, addr, sizeof(struct sockaddr_in));
    udp_ext->sock_fd = 0;
    udp_ext->host_fd = host_fd;
    litedt_set_notify_recv(&peer->dt, flow, 0);
    litedt_set_notify_recvnew(&peer->dt, flow, 1);

    ukey.ip = addr->sin_addr.s_addr;
    ukey.port = addr->sin_port;
    ubind.flow = flow;
    ubind.peer = peer;
    ubind.expire = cur_time + g_config.service.udp_timeout * USEC_PER_SEC;
    ubind.closed = 0;
    ret = queue_append(&udp_tab, &ukey, &ubind);
    if (ret != 0) {
        release_flow(peer, flow);
        free(udp_ext);
        return -1;
    }

    return 0;
}

int udp_init(struct ev_loop *loop)
{
    int ret;

    g_loop = loop;
    ev_timer_init(&udp_timeout_watcher, udp_timeout_cb, 1.0, 1.0);
    ev_timer_start(loop, &udp_timeout_watcher);

    ret = queue_init(
        &udp_tab,
        UDP_HASH_SIZE,
        sizeof(udp_key_t),
        sizeof(udp_bind_t),
        udp_hash,
        0);

    return ret;
}

int udp_local_init(struct ev_loop *loop, entrance_rule_t *entrance)
{
    int sockfd, flag;
    struct sockaddr_in addr;
    hsock_data_t *host;

    if (hsock_cnt >= MAX_PORT_NUM) {
        LOG("Error: udp listen ports maximum number exceed\n");
        return -1;
    }

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
    addr.sin_port = htons(entrance->listen_port);
    addr.sin_addr.s_addr = inet_addr(entrance->listen_addr);

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

    bzero(host->local_addr, ADDRESS_MAX_LEN);
    strncpy(host->local_addr, entrance->listen_addr, ADDRESS_MAX_LEN - 1);
    host->local_port = entrance->listen_port;
    host->tunnel_id = entrance->tunnel_id;
    host->peer_forward = entrance->node_id;
    host->w_read.data = host;
    hsock_list[hsock_cnt++] = host;
    ev_io_init(&host->w_read, udp_host_recv, sockfd, EV_READ);
    ev_io_start(loop, &host->w_read);

    return 0;
}

int udp_local_reload(struct ev_loop *loop, entrance_rule_t *entrances)
{
    int i, exist;

    /* Release port that not exist in entrances rule */
    for (i = 0; i < hsock_cnt;) {
        exist = 0;
        for (; entrances->listen_port != 0; ++entrances) {
            if (entrances->protocol != PROTOCOL_UDP)
                continue;

            if (!strcmp(hsock_list[i]->local_addr, entrances->listen_addr)
                && hsock_list[i]->local_port == entrances->listen_port) {
                if (hsock_list[i]->tunnel_id != entrances->tunnel_id) {
                    LOG("[UDP]Update port %s:%u tunnel_id %u => %u\n",
                        hsock_list[i]->local_addr,
                        hsock_list[i]->local_port,
                        hsock_list[i]->tunnel_id,
                        entrances->tunnel_id);
                    hsock_list[i]->tunnel_id = entrances->tunnel_id;
                }

                exist = 1;
                break;
            }
        }

        if (!exist) {
            LOG("[UDP]Release %s:%u tunnel_id %u\n",
                hsock_list[i]->local_addr,
                hsock_list[i]->local_port,
                hsock_list[i]->tunnel_id);

            hsock_data_t *host = hsock_list[i];
            ev_io_stop(loop, &host->w_read);
            close(host->w_read.fd);
            free(host);

            if (i != hsock_cnt - 1) {
                hsock_list[i] = hsock_list[hsock_cnt - 1];
                hsock_list[hsock_cnt - 1] = NULL;
            } else {
                hsock_list[i] = NULL;
            }

            --hsock_cnt;
        } else {
            ++i;
        }
    }

    /* Binding new ports */
    for (; entrances->listen_port != 0; ++entrances) {
        if (entrances->protocol != PROTOCOL_UDP)
            continue;

        // Check whether local port exists
        exist = 0;
        for (i = 0; i < hsock_cnt; ++i) {
            if (!strcmp(hsock_list[i]->local_addr, entrances->listen_addr)
                && hsock_list[i]->local_port == entrances->listen_port) {
                exist = 1;
                break;
            }
        }

        if (!exist) {
            LOG("[UDP]Bind new tunnel[%u] on %s:%u\n",
                entrances->tunnel_id,
                entrances->listen_addr,
                entrances->listen_port);
            udp_local_init(loop, entrances);
        }
    }

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
    litedt_time_t cur_time = get_curtime();

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
            ret = create_udp_bind(
                &addr,
                watcher->fd,
                hsock->tunnel_id,
                hsock->peer_forward);
            if (ret != 0)
                continue;
            ubind = (udp_bind_t *)queue_get(&udp_tab, &ukey);
        } else {
            ubind->expire = cur_time
                + g_config.service.udp_timeout * USEC_PER_SEC;
            queue_move_back(&udp_tab, &ukey);
        }
        flow = ubind->flow;
        writable = litedt_writable_bytes(&ubind->peer->dt, flow);
        if (read_len + 2 > writable) {
            DBG("LiteDT Buffer is full, udp packet lost.\n");
            litedt_stat_t *stat = litedt_get_stat(&ubind->peer->dt);
            ++stat->udp_lost;
            continue;
        }
        if (read_len > 0xFFFF) {
            LOG("Error: udp packet too large\n");
            continue;
        }
        // forward udp packet
        litedt_send(&ubind->peer->dt, flow, (char *)&read_len, 2);
        litedt_send(&ubind->peer->dt, flow, buf, read_len);
    } while (read_len >= 0);
}

void udp_local_recv(struct ev_loop *loop, struct ev_io *watcher, int revents)
{
    int read_len, writable;
    udp_flow_t *udp_ext = (udp_flow_t *)watcher->data;

    if (!(EV_READ & revents))
        return;

    do {
        read_len = BUFFER_SIZE;
        read_len = recv(watcher->fd, buf, read_len, 0);
        if (read_len < 0)
            continue;

        writable = litedt_writable_bytes(&udp_ext->peer->dt, udp_ext->flow);
        if (read_len + 2 > writable) {
            DBG("LiteDT Buffer is full, udp packet lost.\n");
            litedt_stat_t *stat = litedt_get_stat(&udp_ext->peer->dt);
            ++stat->udp_lost;
            continue;
        }
        // forward udp packet
        litedt_send(&udp_ext->peer->dt, udp_ext->flow, (char *)&read_len, 2);
        litedt_send(&udp_ext->peer->dt, udp_ext->flow, buf, read_len);
    } while (read_len > 0);
}

int udp_remote_init(peer_info_t *peer, uint32_t flow, char *ip, int port)
{
    int sockfd = -1;
    int ret = 0;
    int flow_created = 0;
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(struct sockaddr);
    udp_flow_t *udp_ext = NULL;

    if ((sockfd = socket(PF_INET, SOCK_DGRAM, 0)) < 0) {
        LOG("Warning: create udp socket error");
        goto errout;
    }

    if (fcntl(sockfd, F_SETFL, fcntl(sockfd, F_GETFL) | O_NONBLOCK) < 0 ||
            fcntl(sockfd, F_SETFD, FD_CLOEXEC) < 0) {
        LOG("Warning: set socket nonblock faild\n");
        goto errout;
    }

    udp_ext = (udp_flow_t *)malloc(sizeof(udp_flow_t));
    if (NULL == udp_ext) {
        LOG("Warning: malloc failed\n");
        goto errout;
    }

    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr(ip);

    ret = create_flow(peer, flow);
    if (!ret)
        flow_created = 1;
    else
        goto errout;

    ret = connect(sockfd, (struct sockaddr*)&addr, addr_len);
    if (ret < 0 && errno != EINPROGRESS) {
        ret = LITEFLOW_CONNECT_FAIL;
        goto errout;
    }

    flow_info_t *info = find_flow(peer, flow);
    info->ext = udp_ext;
    info->remote_recv_cb = udp_remote_recv;
    info->remote_send_cb = udp_remote_send;
    info->remote_close_cb = udp_remote_close;

    udp_ext->sock_fd        = sockfd;
    udp_ext->peer           = peer;
    udp_ext->flow           = flow;
    udp_ext->w_read.data    = (void *)udp_ext;
    ev_io_init(&udp_ext->w_read, udp_local_recv, sockfd, EV_READ);
    ev_io_start(g_loop, &udp_ext->w_read);
    litedt_set_notify_recv(&peer->dt, flow, 0);
    litedt_set_notify_recvnew(&peer->dt, flow, 1);

    return 0;

errout:
    if (sockfd >= 0)
        close(sockfd);
    if (udp_ext != NULL)
        free(udp_ext);
    if (flow_created)
        release_flow(peer, flow);
    return ret;
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
