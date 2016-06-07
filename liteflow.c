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
#include <udns.h>
#include <ev.h>
#include "litedt.h"
#include "liteflow.h"
#include "stat.h"
#include "util.h"
#include "list.h"

#define FLOW_HASH_SIZE 1013
#define BUFFER_SIZE 65536

static list_head_t flow_tab[FLOW_HASH_SIZE];
static struct ev_loop *loop;
static litedt_host_t litedt_host;
static struct ev_io litedt_io_watcher;
static struct ev_io dns_io_watcher;
static struct ev_timer litedt_timeout_watcher;
static struct ev_timer domain_update_watcher, dns_timeout_watcher;
static struct ev_timer stat_watcher;
static uint32_t flow_seq;
static char buf[BUFFER_SIZE]; 

typedef struct _hsock_data {
    uint16_t local_port;
    uint16_t map_id;
    struct ev_io w_accept;
} hsock_data_t;

typedef struct _csock_data {
    uint64_t flow;
    int sockfd;
    struct ev_io w_read;
    struct ev_io w_write;
} csock_data_t;

typedef struct _flow_info {
    list_head_t hash_list;
    uint32_t flow;
    csock_data_t *csock;
} flow_info_t;

void litedt_io_cb(struct ev_loop *loop, struct ev_io *watcher, int revents);
void litedt_timeout_cb(struct ev_loop *loop, struct ev_timer *w, int revents);
void host_accept_cb(struct ev_loop *loop, struct ev_io *watcher, int revents);
void client_read_cb(struct ev_loop *loop, struct ev_io *watcher, int revents);
void client_write_cb(struct ev_loop *loop, struct ev_io *watcher, int revents);
int liteflow_on_connect(litedt_host_t *host, uint32_t flow, uint16_t map_id);
void liteflow_on_close(litedt_host_t *host, uint32_t flow);
void liteflow_on_receive(litedt_host_t *host, uint32_t flow, int readable);
void liteflow_on_send(litedt_host_t *host, uint32_t flow, int writable);
void dns_query_cb(struct dns_ctx *ctx, struct dns_rr_a4 *result, void *data);
void dns_io_cb(struct ev_loop *loop, struct ev_io *watcher, int revents);
void dns_timeout_cb(struct ev_loop *loop, struct ev_timer *w, int revents);
void domain_update_cb(struct ev_loop *loop, struct ev_timer *w, int revents);
void stat_timer_cb(struct ev_loop *loop, struct ev_timer *w, int revents);
void liteflow_set_eventtime(litedt_host_t *host, int64_t interval);


uint32_t get_flowid() 
{
    if (++flow_seq == 0)
        ++flow_seq;
    return flow_seq;
}

flow_info_t* find_flow(uint32_t flow)
{
    unsigned int hv = flow % FLOW_HASH_SIZE;
    list_head_t *list, *head = &flow_tab[hv];
    for (list = head->next; list != head; list = list->next) {
        flow_info_t *info = list_entry(list, flow_info_t, hash_list);
        if (info->flow == flow)
            return info;
    }
    return NULL;
}

int create_flow(uint32_t flow, csock_data_t *csock)
{
    flow_info_t *info;
    unsigned int hv = flow % FLOW_HASH_SIZE;
    if (find_flow(flow) != NULL)
        return LITEFLOW_RECORD_EXISTS;

    info = (flow_info_t *)malloc(sizeof(flow_info_t));
    if (NULL == info)
        return LITEFLOW_MEM_ALLOC_ERROR;

    info->flow = flow;
    info->csock = csock;
    list_add_tail(&info->hash_list, &flow_tab[hv]);

    return 0;
}

void release_flow(uint32_t flow)
{
    flow_info_t *info = find_flow(flow);
    if (NULL == info)
        return;
    list_del(&info->hash_list);
    free(info);
}

void client_socket_stop(csock_data_t *data)
{
    litedt_close(&litedt_host, data->flow);
    if (ev_is_active(&data->w_read))
        ev_io_stop(loop, &data->w_read);
    if (ev_is_active(&data->w_write))
        ev_io_stop(loop, &data->w_write);
}

void litedt_io_cb(struct ev_loop *loop, struct ev_io *watcher, int revents)
{
    litedt_host_t *host = (litedt_host_t *)watcher->data;
    if (revents & EV_READ) {
        int64_t cur_time = ev_now(loop) * 1000;
        litedt_io_event(host, cur_time);
    }
}

void litedt_timeout_cb(struct ev_loop *loop, struct ev_timer *w, int revents)
{
    if (revents & EV_TIMER) {
        int64_t cur_time = ev_now(loop) * 1000;
        litedt_time_event(&litedt_host, cur_time);
    }
}

void host_accept_cb(struct ev_loop *loop, struct ev_io *watcher, int revents)
{
    hsock_data_t *hsock = (hsock_data_t *)watcher->data;
    csock_data_t *csock;
    struct sockaddr_in caddr;
    socklen_t clen = sizeof(caddr);
    int sockfd, retry = 65536, ret;
    uint32_t flow;

    if (EV_READ & revents) {
        sockfd = accept(watcher->fd, (struct sockaddr *)&caddr, &clen);
        if (sockfd < 0) 
            return;
        if (fcntl(sockfd, F_SETFL, fcntl(sockfd, F_GETFL) | O_NONBLOCK) < 0 ||
                fcntl(sockfd, F_SETFD, FD_CLOEXEC) < 0) { 
            close (sockfd);
            return;
        }

        csock = (csock_data_t *)malloc(sizeof(csock_data_t));
        if (NULL == csock) {
            close(sockfd);
            return;
        }

        while (--retry >= 0) {
            flow = get_flowid();
            ret = create_flow(flow, csock);
            if (ret != LITEFLOW_RECORD_EXISTS)
                break;
        }
        if (ret == 0) 
            ret = litedt_connect(&litedt_host, flow, hsock->map_id);
        if (ret != 0) {
            close(sockfd);
            free(csock);
            release_flow(flow);
            return;
        }
        
        csock->flow = flow;
        csock->sockfd = sockfd;
        csock->w_read.data = csock;
        csock->w_write.data = csock;
        ev_io_init(&csock->w_read, client_read_cb, sockfd, EV_READ);
        ev_io_init(&csock->w_write, client_write_cb, sockfd, EV_WRITE);
        ev_io_start(loop, &csock->w_read);
    }
}

void client_read_cb(struct ev_loop *loop, struct ev_io *watcher, int revents)
{
    int read_len, writable;
    csock_data_t *data = (csock_data_t *)watcher->data;

    if (!(EV_READ & revents)) 
        return;

    do {
        read_len = BUFFER_SIZE;
        writable = litedt_writable_bytes(&litedt_host, data->flow);
        if (writable <= 0) {
            DBG("liteflow sendbuf is full, waiting for liteflow become "
                "writable.\n");
            litedt_set_notify_send(&litedt_host, data->flow, 1);
            ev_io_stop(loop, watcher);
            break;
        }
        if (read_len > writable)
            read_len = writable;
        read_len = recv(watcher->fd, buf, read_len, 0);
        if (read_len > 0) {
            litedt_send(&litedt_host, data->flow, buf, read_len);
        } else if (read_len < 0 && (errno == EAGAIN || errno == EWOULDBLOCK 
                    || errno == EINTR)) {
            // no data to recv
            break;
        } else {
            // TCP connection closed
            client_socket_stop(data);
        }
    } while (read_len > 0);
}

void client_write_cb(struct ev_loop *loop, struct ev_io *watcher, int revents)
{
    int write_len, readable;
    csock_data_t *data = (csock_data_t *)watcher->data;

    if (!(EV_WRITE & revents)) 
        return;

    do {
        write_len = BUFFER_SIZE;
        readable = litedt_readable_bytes(&litedt_host, data->flow);
        if (readable <= 0) {
            DBG("liteflow recvbuf is empty, waiting for udp side receive "
                "more data.\n");
            litedt_set_notify_recv(&litedt_host, data->flow, 1);
            ev_io_stop(loop, watcher);
            break;
        }
        if (write_len > readable)
            write_len = readable;
        litedt_peek(&litedt_host, data->flow, buf, write_len);
        write_len = send(watcher->fd, buf, write_len, 0);
        if (write_len > 0) {
            litedt_recv_skip(&litedt_host, data->flow, write_len);
        }
    } while (write_len > 0);
}


int liteflow_on_connect(litedt_host_t *host, uint32_t flow, uint16_t map_id)
{
    int sockfd, idx = 0, ret;
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(struct sockaddr);
    csock_data_t *csock;

    while (g_config.allow_list[idx].target_port) {
        allow_access_t *allow = &g_config.allow_list[idx++];
        if (allow->map_id != map_id) 
            continue;

        if ((sockfd = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
            perror("socket error");
            return -1;
        }
        if (fcntl(sockfd, F_SETFL, fcntl(sockfd, F_GETFL) | O_NONBLOCK) < 0 ||
                fcntl(sockfd, F_SETFD, FD_CLOEXEC) < 0) { 
            close(sockfd);
            return -1;
        }
        bzero(&addr, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(allow->target_port);
        addr.sin_addr.s_addr = inet_addr(allow->target_addr);

        ret = connect(sockfd, (struct sockaddr*)&addr, addr_len);
        if (ret < 0 && errno != EINPROGRESS) {
            close(sockfd);
            return LITEFLOW_CONNECT_FAIL;
        }

        csock = (csock_data_t *)malloc(sizeof(csock_data_t));
        if (NULL == csock) {
            close(sockfd);
            return LITEFLOW_MEM_ALLOC_ERROR;
        }
        ret = create_flow(flow, csock);
        if (ret != 0) {
            close(sockfd);
            free(csock);
            return ret;
        }
        csock->flow = flow;
        csock->sockfd = sockfd;
        csock->w_read.data = csock;
        csock->w_write.data = csock;
        ev_io_init(&csock->w_read, client_read_cb, sockfd, EV_READ);
        ev_io_init(&csock->w_write, client_write_cb, sockfd, EV_WRITE);
        ev_io_start(loop, &csock->w_read);

        return 0;
    }

    return LITEFLOW_ACCESS_DENIED;
}

void liteflow_on_close(litedt_host_t *host, uint32_t flow)
{
    flow_info_t *info = find_flow(flow);
    if (NULL == info)
        return;
    close(info->csock->sockfd);
    if (ev_is_active(&info->csock->w_read))
        ev_io_stop(loop, &info->csock->w_read);
    if (ev_is_active(&info->csock->w_write))
        ev_io_stop(loop, &info->csock->w_write);
    free(info->csock);
    release_flow(flow);
}

void liteflow_on_receive(litedt_host_t *host, uint32_t flow, int readable)
{
    int read_len = BUFFER_SIZE, ret;
    flow_info_t *info = find_flow(flow);
    if (NULL == info)
        return;

    while (readable > 0) {
        if (read_len > readable)
            read_len = readable;
        litedt_peek(&litedt_host, flow, buf, read_len);
        ret = send(info->csock->sockfd, buf, read_len, 0);
        if (ret > 0)
            litedt_recv_skip(&litedt_host, flow, ret);
        if (ret < read_len) {
            // partial send success, waiting for socket become writable
            DBG("tcp sendbuf is full, waiting for socket become writable.\n");
            ev_io_start(loop, &info->csock->w_write);
            litedt_set_notify_recv(host, flow, 0);
            break;
        }
        readable -= ret;
    }
}

void liteflow_on_send(litedt_host_t *host, uint32_t flow, int writable)
{
    int write_len = BUFFER_SIZE, ret;
    flow_info_t *info = find_flow(flow);
    if (NULL == info)
        return;

    while (writable > 0) {
        if (write_len > writable)
            write_len = writable;
        ret = recv(info->csock->sockfd, buf, write_len, 0);
        if (ret > 0) {
            litedt_send(&litedt_host, flow, buf, ret);
            writable -= ret;
        } else if (ret < 0 && (errno == EAGAIN || errno == EWOULDBLOCK 
                    || errno == EINTR)) {
            // no data to recv, waiting for socket become readable
            DBG("tcp recvbuf is empty, waiting for tcp side receive more "
                "data.\n");
            ev_io_start(loop, &info->csock->w_read);
            litedt_set_notify_send(host, flow, 0);
            break;
        } else {
            // TCP connection closed
            client_socket_stop(info->csock);
        }
    }
}

void dns_query_cb(struct dns_ctx *ctx, struct dns_rr_a4 *result, void *data)
{
    if (result && result->dnsa4_nrr >= 1) {
        char ip[ADDRESS_MAX_LEN];
        inet_ntop(AF_INET, result->dnsa4_addr, ip, ADDRESS_MAX_LEN);
        LOG("Remote host address updated -- %s:%u\n", ip, 
                g_config.udp_remote_port);
        litedt_set_remote_addr(&litedt_host, ip, g_config.udp_remote_port);
    } else {
        LOG("Domain resolv failed.\n");
    }
}

void dns_io_cb(struct ev_loop *loop, struct ev_io *watcher, int revents)
{
    if (revents & EV_READ) {
        dns_ioevent(NULL, ev_now(loop));
    }
}

void dns_timeout_cb(struct ev_loop *loop, struct ev_timer *w, int revents)
{
    int nwait;

    if (revents & EV_TIMER) {
        if (ev_is_active(&dns_timeout_watcher)) {
            ev_timer_stop(loop, &dns_timeout_watcher);
        }

        nwait = dns_timeouts(NULL, -1, ev_now(loop));
        if (nwait > 0) {
            ev_timer_set(&dns_timeout_watcher, 0.1, 0);
            ev_timer_start(loop, &dns_timeout_watcher);
        } else if (nwait == 0) {
            ev_timer_set(&dns_timeout_watcher, nwait, 0);
            ev_timer_start(loop, &dns_timeout_watcher);
        }
    }
}

void domain_update_cb(struct ev_loop *loop, struct ev_timer *w, int revents)
{
    int nwait;

    if (revents & EV_TIMER) {
        char *domain = g_config.udp_remote_addr;
        if (ev_is_active(&dns_timeout_watcher)) {
            ev_timer_stop(loop, &dns_timeout_watcher);
        }

        dns_submit_a4(NULL, domain, 0, dns_query_cb, NULL);

        nwait = dns_timeouts(NULL, -1, ev_now(loop));
        if (nwait > 0) {
            ev_timer_set(&dns_timeout_watcher, 0.1, 0);
            ev_timer_start(loop, &dns_timeout_watcher);
        } else if (nwait == 0) {
            ev_timer_set(&dns_timeout_watcher, nwait, 0);
            ev_timer_start(loop, &dns_timeout_watcher);
        }
    }
}

void stat_timer_cb(struct ev_loop *loop, struct ev_timer *w, int revents)
{
    static int stat_num = 0;
    if (revents & EV_TIMER) {
        litedt_stat_t stat;

        litedt_get_stat(&litedt_host, &stat);
        inc_stat(&stat);
        if (++stat_num >= 60) {
            print_stat();
            clear_stat();
            stat_num = 0;
        }
    }
}

void liteflow_set_eventtime(litedt_host_t *host, int64_t interval)
{
    double timeout = (double)interval / 1000;
    if (ev_is_active(&litedt_timeout_watcher)) {
        ev_timer_stop(loop, &litedt_timeout_watcher);
    }
    ev_timer_set(&litedt_timeout_watcher, timeout, timeout);
    ev_timer_start(loop, &litedt_timeout_watcher);
}

int start_domain_query(const char *domain)
{
    struct dns_query *query;
    int dns_fd = dns_init(NULL, 1), nwait;
    if (dns_fd < 0)
        return dns_fd;

    query = dns_submit_a4(NULL, domain, 0, dns_query_cb, NULL);
    if (NULL == query) 
        return -1;

    nwait = dns_timeouts(NULL, -1, 0);
    
    ev_io_init(&dns_io_watcher, dns_io_cb, dns_fd, EV_READ);
    ev_io_start(loop, &dns_io_watcher);
    ev_timer_init(&dns_timeout_watcher, dns_timeout_cb, nwait, 0);
    ev_timer_start(loop, &dns_timeout_watcher);
    ev_timer_init(&domain_update_watcher, domain_update_cb, 300.0, 300.0);
    ev_timer_start(loop, &domain_update_watcher);
    
    return 0;
}

int init_liteflow()
{
    int idx = 0, sockfd, flag, i;
    struct sockaddr_in addr;
    hsock_data_t *host;

    loop = ev_default_loop(0);
    flow_seq = rand();
    for (i = 0; i < FLOW_HASH_SIZE; i++)
        INIT_LIST_HEAD(&flow_tab[i]);

    while (g_config.listen_list[idx].local_port) {
        listen_port_t *listen_cfg = &g_config.listen_list[idx++];
        if ((sockfd = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
            perror("socket error");
            return -1;
        }
        if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &flag, sizeof(int))
                == -1) { 
            perror("setsockopt"); 
            return -1;
        } 
        if (fcntl(sockfd, F_SETFL, fcntl(sockfd, F_GETFL) | O_NONBLOCK) < 0 ||
                fcntl(sockfd, F_SETFD, FD_CLOEXEC) < 0) { 
            perror("fcntl"); 
            return -1;
        }
        bzero(&addr, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(listen_cfg->local_port);
        addr.sin_addr.s_addr = inet_addr(g_config.tcp_bind_addr);

        if (bind(sockfd, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
            perror("bind error");
            return -2;
        }
        if (listen(sockfd, 100) < 0) {
            perror("listen error");
            return -3;
        }

        host = (hsock_data_t *)malloc(sizeof(hsock_data_t));
        host->local_port = listen_cfg->local_port;
        host->map_id = listen_cfg->map_id;
        host->w_accept.data = host;
        ev_io_init(&host->w_accept, host_accept_cb, sockfd, EV_READ);
        ev_io_start(loop, &host->w_accept);
    }

    sockfd = litedt_init(&litedt_host);
    if (sockfd < 0) {
        perror("litedt init error");
        return sockfd;
    }

    if (g_config.udp_remote_addr[0]) {
        // checking whether udp_remote_addr is a IPv4 address
        if (inet_addr(g_config.udp_remote_addr) == 0xFFFFFFFF) {
            if (start_domain_query(g_config.udp_remote_addr) != 0) {
                LOG("Resolv domain failed.\n");
                litedt_fini(&litedt_host);
                return -4;
            }
        } else {
            litedt_set_remote_addr(&litedt_host, g_config.udp_remote_addr, 
                g_config.udp_remote_port);
        }
    }
    
    litedt_set_connect_cb(&litedt_host, liteflow_on_connect);
    litedt_set_receive_cb(&litedt_host, liteflow_on_receive);
    litedt_set_send_cb(&litedt_host, liteflow_on_send);
    litedt_set_close_cb(&litedt_host, liteflow_on_close);
    litedt_set_event_time_cb(&litedt_host, liteflow_set_eventtime);

    litedt_io_watcher.data = &litedt_host;
    ev_io_init(&litedt_io_watcher, litedt_io_cb, sockfd, EV_READ);
    ev_io_start(loop, &litedt_io_watcher);
    
    return 0;
}

void start_liteflow()
{
    clear_stat();
    ev_timer_init(&litedt_timeout_watcher, litedt_timeout_cb, 1.0, 1.0);
    ev_timer_start(loop, &litedt_timeout_watcher);
    ev_timer_init(&stat_watcher, stat_timer_cb, 1.0, 1.0);
    ev_timer_start(loop, &stat_watcher);
    
    while (1) {
        ev_loop(loop, 0);
    }
}
