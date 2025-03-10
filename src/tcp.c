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
#include <netinet/tcp.h>
#include "tcp.h"
#include "util.h"
#include "liteflow.h"

#define BUFFER_SIZE 65536
#if defined(__APPLE__) && !defined(SOL_TCP)
#define SOL_TCP IPPROTO_TCP
#endif

typedef struct _hsock_data {
    char local_addr[ADDRESS_MAX_LEN];
    uint16_t local_port;
    uint16_t tunnel_id;
    uint16_t peer_forward;
    struct ev_io w_accept;
} hsock_data_t;

typedef struct _tcp_flow {
    struct ev_io w_read;
    struct ev_io w_write;
    int sock_fd;
    peer_info_t *peer;
    uint32_t flow;
} tcp_flow_t;

static struct ev_loop *g_loop;
static char buf[BUFFER_SIZE];
static hsock_data_t* hsock_list[MAX_PORT_NUM + 1] = { 0 };
static int hsock_cnt = 0;

void tcp_local_recv(struct ev_loop *loop, struct ev_io *watcher, int revents);
void tcp_local_send(struct ev_loop *loop, struct ev_io *watcher, int revents);
void host_accept_cb(struct ev_loop *loop, struct ev_io *watcher, int revents);
void tcp_remote_close(litedt_host_t *host, flow_info_t *flow);
void tcp_remote_recv(litedt_host_t *host, flow_info_t *flow, int readable);
void tcp_remote_send(litedt_host_t *host, flow_info_t *flow, int writable);

int tcp_init(struct ev_loop *loop)
{
    g_loop = loop;
    return 0;
}

int tcp_local_init(struct ev_loop *loop, entrance_rule_t *entrance)
{
    int sockfd, flag, af;
    struct sockaddr_storage storage;
    socklen_t addr_len;
    hsock_data_t *host;

    af = get_addr_family(entrance->listen_addr);
    if (af < 0 || (af != AF_INET && af != AF_INET6)) {
        LOG("Error: Failed to init tcp entrance, bad listen_addr: %s",
            entrance->listen_addr);
        return -1;
    }

    if ((sockfd = socket(af, SOCK_STREAM, 0)) < 0) {
        perror("socket error");
        return -1;
    }

    if (g_config.service.tcp_nodelay) {
        flag = 1;
        setsockopt(sockfd, SOL_TCP, TCP_NODELAY, &flag, sizeof(flag));
    }

#ifdef TCP_FASTOPEN
    if (g_config.service.tcp_fastopen) {
        int opt = g_config.service.tcp_fastopen;
        setsockopt(sockfd, SOL_TCP, TCP_FASTOPEN, &opt, sizeof(opt));
    }
#endif

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

    bzero(&storage, sizeof(storage));
    if (af == AF_INET) {
        struct sockaddr_in *addr = (struct sockaddr_in *)&storage;
        addr->sin_family = AF_INET;
        addr->sin_port = htons(entrance->listen_port);
        inet_pton(AF_INET, entrance->listen_addr, &(addr->sin_addr));
        addr_len = sizeof(struct sockaddr_in);
    } else {
        struct sockaddr_in6 *addr = (struct sockaddr_in6 *)&storage;
        addr->sin6_family = AF_INET6;
        addr->sin6_port = htons(entrance->listen_port);
        inet_pton(AF_INET6, entrance->listen_addr, &(addr->sin6_addr));
        addr_len = sizeof(struct sockaddr_in6);
    }

    if (bind(sockfd, (struct sockaddr*)&storage, addr_len) != 0) {
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
        LOG("Warning: malloc failed");
        close(sockfd);
        return -4;
    }

    bzero(host->local_addr, ADDRESS_MAX_LEN);
    strncpy(host->local_addr, entrance->listen_addr, ADDRESS_MAX_LEN - 1);
    host->local_port = entrance->listen_port;
    host->tunnel_id = entrance->tunnel_id;
    host->peer_forward = entrance->node_id;
    host->w_accept.data = host;
    hsock_list[hsock_cnt++] = host;
    ev_io_init(&host->w_accept, host_accept_cb, sockfd, EV_READ);
    ev_io_start(loop, &host->w_accept);

    return 0;
}

int tcp_local_reload(struct ev_loop *loop, entrance_rule_t *entrances)
{
    int i, exist;
    entrance_rule_t *entry;

    /* Release port that not exists in entrances rule */
    for (i = 0; i < hsock_cnt;) {
        exist = 0;
        for (entry = entrances; entry->listen_port != 0; ++entry) {
            if (entry->protocol != PROTOCOL_TCP)
                continue;

            if (!strcmp(hsock_list[i]->local_addr, entry->listen_addr)
                && hsock_list[i]->local_port == entry->listen_port) {
                if (hsock_list[i]->tunnel_id != entry->tunnel_id) {
                    LOG("[TCP]Update port [%s]:%u tunnel_id %u => %u",
                        hsock_list[i]->local_addr,
                        hsock_list[i]->local_port,
                        hsock_list[i]->tunnel_id,
                        entry->tunnel_id);
                    hsock_list[i]->tunnel_id = entry->tunnel_id;
                }

                exist = 1;
                break;
            }
        }

        if (!exist) {
            LOG("[TCP]Release [%s]:%u tunnel_id %u",
                hsock_list[i]->local_addr,
                hsock_list[i]->local_port,
                hsock_list[i]->tunnel_id);

            hsock_data_t *host = hsock_list[i];
            ev_io_stop(loop, &host->w_accept);
            close(host->w_accept.fd);
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
    for (entry = entrances; entry->listen_port != 0; ++entry) {
        if (entry->protocol != PROTOCOL_TCP)
            continue;

        // Check whether local port exists
        exist = 0;
        for (i = 0; i < hsock_cnt; ++i) {
            if (!strcmp(hsock_list[i]->local_addr, entry->listen_addr)
                && hsock_list[i]->local_port == entry->listen_port) {
                exist = 1;
                break;
            }
        }

        if (!exist) {
            LOG("[TCP]Bind new tunnel[%u] on [%s]:%u",
                entry->tunnel_id,
                entry->listen_addr,
                entry->listen_port);
            tcp_local_init(loop, entry);
        }
    }

    return 0;
}

void tcp_local_recv(struct ev_loop *loop, struct ev_io *watcher, int revents)
{
    int read_len, writable;
    tcp_flow_t *tcp_ext = (tcp_flow_t *)watcher->data;

    if (!(EV_READ & revents))
        return;

    do {
        read_len = BUFFER_SIZE;
        writable = litedt_writable_bytes(&tcp_ext->peer->dt, tcp_ext->flow);
        if (writable <= 0) {
            DBG("flow %u sendbuf is full, waiting for liteflow become "
                "writable.", tcp_ext->flow);
            litedt_set_notify_send(&tcp_ext->peer->dt, tcp_ext->flow, 1);
            ev_io_stop(loop, watcher);
            break;
        }
        if (read_len > writable)
            read_len = writable;
        read_len = recv(watcher->fd, buf, read_len, 0);
        if (read_len > 0) {
            litedt_send(&tcp_ext->peer->dt, tcp_ext->flow, buf, read_len);
        } else if (read_len < 0 && (errno == EAGAIN || errno == EWOULDBLOCK
                    || errno == EINTR)) {
            // no data to recv
            break;
        } else {
            // TCP connection closed
            ev_io_stop(g_loop, watcher);
            litedt_close(&tcp_ext->peer->dt, tcp_ext->flow);
            break;
        }
    } while (read_len > 0);
}

void tcp_local_send(struct ev_loop *loop, struct ev_io *watcher, int revents)
{
    int write_len, readable;
    tcp_flow_t *tcp_ext = (tcp_flow_t *)watcher->data;

    if (!(EV_WRITE & revents))
        return;

    do {
        write_len = BUFFER_SIZE;
        readable = litedt_readable_bytes(&tcp_ext->peer->dt, tcp_ext->flow);
        if (readable <= 0) {
            DBG("flow %u recvbuf is empty, waiting for udp side receive "
                "more data.", tcp_ext->flow);
            litedt_set_notify_recv(&tcp_ext->peer->dt, tcp_ext->flow, 1);
            ev_io_stop(loop, watcher);
            break;
        }
        if (write_len > readable)
            write_len = readable;
        litedt_peek(&tcp_ext->peer->dt, tcp_ext->flow, buf, write_len);
        write_len = send(watcher->fd, buf, write_len, 0);
        if (write_len > 0) {
            litedt_recv_skip(&tcp_ext->peer->dt, tcp_ext->flow, write_len);
        }
    } while (write_len > 0);
}

void host_accept_cb(struct ev_loop *loop, struct ev_io *watcher, int revents)
{
    hsock_data_t *hsock = (hsock_data_t *)watcher->data;
    peer_info_t *peer = NULL;
    struct sockaddr_storage storage;
    socklen_t addr_len = sizeof(storage);
    int sockfd, ret;
    uint32_t flow;

    if (EV_READ & revents) {
        sockfd = accept(watcher->fd, (struct sockaddr *)&storage, &addr_len);
        if (sockfd < 0) {
            LOG("Warning: tcp accept faild");
            return;
        }
        if (fcntl(sockfd, F_SETFL, fcntl(sockfd, F_GETFL) | O_NONBLOCK) < 0 ||
                fcntl(sockfd, F_SETFD, FD_CLOEXEC) < 0) {
            LOG("Warning: set socket nonblock faild");
            close(sockfd);
            return;
        }

        if ((peer = find_peer(hsock->peer_forward)) == NULL) {
            LOG("Failed to forward connection: peer[%u] offline",
                hsock->peer_forward);
            close(sockfd);
            return;
        }

        tcp_flow_t *tcp_ext = (tcp_flow_t *)malloc(sizeof(tcp_flow_t));
        if (NULL == tcp_ext) {
            LOG("Warning: malloc failed");
            close(sockfd);
            return;
        }

        flow = next_flow_id(peer);
        ret = create_flow(peer, flow);
        if (ret == 0)
            ret = litedt_connect(&peer->dt, flow, hsock->tunnel_id);
        if (ret != 0) {
            release_flow(peer, flow);
            free(tcp_ext);
            close(sockfd);
            return;
        }

        flow_info_t *info = find_flow(peer, flow);
        info->ext = tcp_ext;
        info->remote_recv_cb = tcp_remote_recv;
        info->remote_send_cb = tcp_remote_send;
        info->remote_close_cb = tcp_remote_close;

        tcp_ext->sock_fd        = sockfd;
        tcp_ext->peer           = peer;
        tcp_ext->flow           = flow;
        tcp_ext->w_read.data    = (void *)tcp_ext;
        tcp_ext->w_write.data   = (void *)tcp_ext;
        ev_io_init(&tcp_ext->w_read, tcp_local_recv, sockfd, EV_READ);
        ev_io_init(&tcp_ext->w_write, tcp_local_send, sockfd, EV_WRITE);
        ev_io_start(loop, &tcp_ext->w_read);
    }
}

int tcp_remote_init(peer_info_t *peer, uint32_t flow, char *ip, int port)
{
    int ret = 0, flow_created = 0, sockfd = -1, af;
    struct sockaddr_storage storage;
    socklen_t addr_len;
    tcp_flow_t *tcp_ext = NULL;

    af = get_addr_family(ip);
    if (af < 0 || (af != AF_INET && af != AF_INET6)) {
        LOG("Error: Failed to connect remote addr, bad address: %s", ip);
        ret = LITEFLOW_PARAMETER_ERROR;
        goto errout;
    }

    if ((sockfd = socket(af, SOCK_STREAM, 0)) < 0) {
        LOG("Warning: create tcp socket error");
        ret = LITEFLOW_INTERNAL_ERROR;
        goto errout;
    }

    if (g_config.service.tcp_nodelay) {
        int opt = 1;
        setsockopt(sockfd, SOL_TCP, TCP_NODELAY, &opt, sizeof(opt));
    }

#ifdef TCP_FASTOPEN_CONNECT
    if (g_config.service.tcp_fastopen_connect) {
        int opt = 1;
        setsockopt(sockfd, SOL_TCP, TCP_FASTOPEN_CONNECT, &opt, sizeof(opt));
    }
#endif

    if (fcntl(sockfd, F_SETFL, fcntl(sockfd, F_GETFL) | O_NONBLOCK) < 0 ||
            fcntl(sockfd, F_SETFD, FD_CLOEXEC) < 0) {
        LOG("Warning: set socket nonblock faild");
        ret = LITEFLOW_INTERNAL_ERROR;
        goto errout;
    }

    tcp_ext = (tcp_flow_t *)malloc(sizeof(tcp_flow_t));
    if (NULL == tcp_ext) {
        LOG("Warning: malloc failed");
        ret = LITEFLOW_MEM_ALLOC_ERROR;
        goto errout;
    }

    bzero(&storage, sizeof(storage));
    if (af == AF_INET) {
        struct sockaddr_in *addr = (struct sockaddr_in *)&storage;
        addr->sin_family = AF_INET;
        addr->sin_port = htons(port);
        inet_pton(AF_INET, ip, &(addr->sin_addr));
        addr_len = sizeof(struct sockaddr_in);
    } else {
        struct sockaddr_in6 *addr = (struct sockaddr_in6 *)&storage;
        addr->sin6_family = AF_INET6;
        addr->sin6_port = htons(port);
        inet_pton(AF_INET6, ip, &(addr->sin6_addr));
        addr_len = sizeof(struct sockaddr_in6);
    }

    ret = create_flow(peer, flow);
    if (!ret)
        flow_created = 1;
    else
        goto errout;

    ret = connect(sockfd, (struct sockaddr*)&storage, addr_len);
    if (ret < 0 && errno != EINPROGRESS) {
        ret = LITEFLOW_CONNECT_FAIL;
        goto errout;
    }

    flow_info_t *info = find_flow(peer, flow);
    info->ext = tcp_ext;
    info->remote_recv_cb = tcp_remote_recv;
    info->remote_send_cb = tcp_remote_send;
    info->remote_close_cb = tcp_remote_close;

    tcp_ext->sock_fd        = sockfd;
    tcp_ext->peer           = peer;
    tcp_ext->flow           = flow;
    tcp_ext->w_read.data    = (void *)tcp_ext;
    tcp_ext->w_write.data   = (void *)tcp_ext;
    ev_io_init(&tcp_ext->w_read, tcp_local_recv, sockfd, EV_READ);
    ev_io_init(&tcp_ext->w_write, tcp_local_send, sockfd, EV_WRITE);
    ev_io_start(g_loop, &tcp_ext->w_read);

    return 0;

errout:
    if (sockfd >= 0)
        close(sockfd);
    if (tcp_ext != NULL)
        free(tcp_ext);
    if (flow_created)
        release_flow(peer, flow);
    return ret;
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
                "writable.", flow->flow);
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
                "more data.", flow->flow);
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
