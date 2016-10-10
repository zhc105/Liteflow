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
#include "tcp.h"
#include "stat.h"
#include "util.h"
#include "liteflow.h"

#define BUFFER_SIZE 65536

typedef struct _hsock_data {
    uint16_t local_port;
    uint16_t map_id;
    struct ev_io w_accept;
} hsock_data_t;

typedef struct _tcp_flow {
    struct ev_io w_read;
    struct ev_io w_write;
    int sock_fd;
} tcp_flow_t;

static struct ev_loop *g_loop;
static litedt_host_t *g_litedt;
static char buf[BUFFER_SIZE]; 

void tcp_local_recv(struct ev_loop *loop, struct ev_io *watcher, int revents);
void tcp_local_send(struct ev_loop *loop, struct ev_io *watcher, int revents);
void host_accept_cb(struct ev_loop *loop, struct ev_io *watcher, int revents);
void tcp_remote_close(litedt_host_t *host, flow_info_t *flow);
void tcp_remote_recv(litedt_host_t *host, flow_info_t *flow, int readable);
void tcp_remote_send(litedt_host_t *host, flow_info_t *flow, int writable);

int tcp_init(struct ev_loop *loop, litedt_host_t *host)
{
    g_loop = loop;
    g_litedt = host;
    return 0;
}

int tcp_local_init(struct ev_loop *loop, int port, int mapid)
{
    int sockfd, flag;
    struct sockaddr_in addr;
    hsock_data_t *host;

    if ((sockfd = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
        perror("socket error");
        return -1;
    }
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
    if (listen(sockfd, 100) < 0) {
        perror("listen error");
        close(sockfd);
        return -3;
    }

    host = (hsock_data_t *)malloc(sizeof(hsock_data_t));
    if (NULL == host) {
        LOG("Warning: malloc failed\n");
        close(sockfd);
        return -4;
    }

    host->local_port = port;
    host->map_id = mapid;
    host->w_accept.data = host;
    ev_io_init(&host->w_accept, host_accept_cb, sockfd, EV_READ);
    ev_io_start(loop, &host->w_accept);

    return 0;
}

void tcp_local_recv(struct ev_loop *loop, struct ev_io *watcher, int revents)
{
    int read_len, writable;
    uint32_t flow = (uint32_t)(long)watcher->data;

    if (!(EV_READ & revents)) 
        return;

    do {
        read_len = BUFFER_SIZE;
        writable = litedt_writable_bytes(g_litedt, flow);
        if (writable <= 0) {
            DBG("flow %u sendbuf is full, waiting for liteflow become "
                "writable.\n", flow);
            litedt_set_notify_send(g_litedt, flow, 1);
            ev_io_stop(loop, watcher);
            break;
        }
        if (read_len > writable)
            read_len = writable;
        read_len = recv(watcher->fd, buf, read_len, 0);
        if (read_len > 0) {
            litedt_send(g_litedt, flow, buf, read_len);
        } else if (read_len < 0 && (errno == EAGAIN || errno == EWOULDBLOCK 
                    || errno == EINTR)) {
            // no data to recv
            break;
        } else {
            // TCP connection closed
            ev_io_stop(g_loop, watcher);
            litedt_close(g_litedt, flow);
            break;
        }
    } while (read_len > 0);
}

void tcp_local_send(struct ev_loop *loop, struct ev_io *watcher, int revents)
{
    int write_len, readable;
    uint32_t flow = (uint32_t)(long)watcher->data;

    if (!(EV_WRITE & revents)) 
        return;

    do {
        write_len = BUFFER_SIZE;
        readable = litedt_readable_bytes(g_litedt, flow);
        if (readable <= 0) {
            DBG("flow %u recvbuf is empty, waiting for udp side receive "
                "more data.\n", flow);
            litedt_set_notify_recv(g_litedt, flow, 1);
            ev_io_stop(loop, watcher);
            break;
        }
        if (write_len > readable)
            write_len = readable;
        litedt_peek(g_litedt, flow, buf, write_len);
        write_len = send(watcher->fd, buf, write_len, 0);
        if (write_len > 0) {
            litedt_recv_skip(g_litedt, flow, write_len);
        }
    } while (write_len > 0);
}

void host_accept_cb(struct ev_loop *loop, struct ev_io *watcher, int revents)
{
    hsock_data_t *hsock = (hsock_data_t *)watcher->data;
    struct sockaddr_in caddr;
    socklen_t clen = sizeof(caddr);
    int sockfd, ret;
    uint32_t flow;

    if (EV_READ & revents) {
        sockfd = accept(watcher->fd, (struct sockaddr *)&caddr, &clen);
        if (sockfd < 0) {
            LOG("Warning: tcp accept faild\n");
            return;
        }
        if (fcntl(sockfd, F_SETFL, fcntl(sockfd, F_GETFL) | O_NONBLOCK) < 0 ||
                fcntl(sockfd, F_SETFD, FD_CLOEXEC) < 0) { 
            LOG("Warning: set socket nonblock faild\n");
            close(sockfd);
            return;
        }

        tcp_flow_t *tcp_ext = (tcp_flow_t *)malloc(sizeof(tcp_flow_t));
        if (NULL == tcp_ext) {
            LOG("Warning: malloc failed\n");
            close(sockfd);
            return;
        }

        flow = liteflow_flowid();
        ret = create_flow(flow);
        if (ret == 0) 
            ret = litedt_connect(g_litedt, flow, hsock->map_id);
        if (ret != 0) {
            release_flow(flow);
            free(tcp_ext);
            close(sockfd);
            return;
        }
        
        flow_info_t *info = find_flow(flow);
        info->ext = tcp_ext;
        info->remote_recv_cb = tcp_remote_recv;
        info->remote_send_cb = tcp_remote_send;
        info->remote_close_cb = tcp_remote_close;

        tcp_ext->sock_fd = sockfd;
        tcp_ext->w_read.data  = (void *)(long)flow;
        tcp_ext->w_write.data = (void *)(long)flow;
        ev_io_init(&tcp_ext->w_read, tcp_local_recv, sockfd, EV_READ);
        ev_io_init(&tcp_ext->w_write, tcp_local_send, sockfd, EV_WRITE);
        ev_io_start(loop, &tcp_ext->w_read);
    }
}

int tcp_remote_init(litedt_host_t *host, uint32_t flow, char *ip, int port)
{
    int sockfd, ret;
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(struct sockaddr);

    if ((sockfd = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
        LOG("Warning: create tcp socket error");
        return -1;
    }
    if (fcntl(sockfd, F_SETFL, fcntl(sockfd, F_GETFL) | O_NONBLOCK) < 0 ||
            fcntl(sockfd, F_SETFD, FD_CLOEXEC) < 0) { 
        LOG("Warning: set socket nonblock faild\n");
        close(sockfd);
        return -1;
    }
    tcp_flow_t *tcp_ext = (tcp_flow_t *)malloc(sizeof(tcp_flow_t));
    if (NULL == tcp_ext) {
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
    info->ext = tcp_ext;
    info->remote_recv_cb = tcp_remote_recv;
    info->remote_send_cb = tcp_remote_send;
    info->remote_close_cb = tcp_remote_close;

    tcp_ext->sock_fd = sockfd;
    tcp_ext->w_read.data  = (void *)(long)flow;
    tcp_ext->w_write.data = (void *)(long)flow;
    ev_io_init(&tcp_ext->w_read, tcp_local_recv, sockfd, EV_READ);
    ev_io_init(&tcp_ext->w_write, tcp_local_send, sockfd, EV_WRITE);
    ev_io_start(g_loop, &tcp_ext->w_read);

    return 0;
}

void tcp_remote_recv(litedt_host_t *host, flow_info_t *flow, int readable)
{
    int read_len = BUFFER_SIZE, ret;
    tcp_flow_t *tcp_ext = (tcp_flow_t *)flow->ext;

    while (readable > 0) {
        if (read_len > readable)
            read_len = readable;
        litedt_peek(host, flow->flow, buf, read_len);
        ret = send(tcp_ext->sock_fd, buf, read_len, 0);
        if (ret > 0)
            litedt_recv_skip(host, flow->flow, ret);
        if (ret < read_len) {
            // partial send success, waiting for socket become writable
            DBG("flow %u tcp sendbuf is full, waiting for socket become "
                "writable.\n", flow->flow);
            ev_io_start(g_loop, &tcp_ext->w_write);
            litedt_set_notify_recv(host, flow->flow, 0);
            break;
        }
        readable -= ret;
    }
}

void tcp_remote_send(litedt_host_t *host, flow_info_t *flow, int writable)
{
    int write_len = BUFFER_SIZE, ret;
    tcp_flow_t *tcp_ext = (tcp_flow_t *)flow->ext;

    while (writable > 0) {
        if (write_len > writable)
            write_len = writable;
        ret = recv(tcp_ext->sock_fd, buf, write_len, 0);
        if (ret > 0) {
            litedt_send(host, flow->flow, buf, ret);
            writable -= ret;
        } else if (ret < 0 && (errno == EAGAIN || errno == EWOULDBLOCK 
                    || errno == EINTR)) {
            // no data to recv, waiting for socket become readable
            DBG("flow %u tcp recvbuf is empty, waiting for tcp side receive "
                "more data.\n", flow->flow);
            ev_io_start(g_loop, &tcp_ext->w_read);
            litedt_set_notify_send(host, flow->flow, 0);
            break;
        } else {
            // TCP connection closed
            ev_io_stop(g_loop, &tcp_ext->w_read);
            litedt_close(host, flow->flow);
            break;
        }
    }
}

void tcp_remote_close(litedt_host_t *host, flow_info_t *flow)
{
    if (flow->ext == NULL)
        return;

    tcp_flow_t *tcp_ext = (tcp_flow_t *)flow->ext;
    ev_io_stop(g_loop, &tcp_ext->w_read);
    ev_io_stop(g_loop, &tcp_ext->w_write);
    close(tcp_ext->sock_fd);

    free(tcp_ext);
    flow->ext = NULL;
}
