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
#include <signal.h>
#include <assert.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <ares.h>
#include <netdb.h>
#include "litedt.h"
#include "hashqueue.h"
#include "liteflow.h"
#include "stat.h"
#include "util.h"
#include "tcp.h"
#include "udp.h"

#define FLOW_HASH_SIZE          1013
#define MAX_DNS_TIMEOUT         60.0
#define MIN_DNS_TIMEOUT         1.0
#define DNS_UPDATE_INTERVAL     300.0

#define TV_TO_FLOAT(tv) ((double)(tv).tv_sec + ((double)(tv).tv_usec / 1000000.0))

static hash_queue_t     flow_tab;
static struct ev_loop   *loop;
static litedt_host_t    litedt_host;
static struct ev_io     litedt_io_watcher;
static struct ev_io     dns_io_watcher;
static struct ev_timer  litedt_timeout_watcher;
static struct ev_timer  dns_update_watcher, dns_timeout_watcher;
static struct ev_timer  stat_watcher;
static uint32_t         flow_seq;
static uint32_t         mode;
static uint32_t         online_monitor = 0;
static volatile int     need_reload_conf = 0;
static ares_channel     g_channel;

void litedt_io_cb(struct ev_loop *loop, struct ev_io *watcher, int revents);
void litedt_timeout_cb(struct ev_loop *loop, struct ev_timer *w, int revents);
int  liteflow_on_connect(litedt_host_t *host, uint32_t flow, uint16_t map_id);
void liteflow_on_close(litedt_host_t *host, uint32_t flow);
void liteflow_on_receive(litedt_host_t *host, uint32_t flow, int readable);
void liteflow_on_send(litedt_host_t *host, uint32_t flow, int writable);
void ares_state_cb(void *data, int s, int read, int write);
void dns_query_cb(void *arg, int status, int timeouts, struct hostent *host);
void dns_io_cb(struct ev_loop *loop, struct ev_io *watcher, int revents);
void dns_timeout_cb(struct ev_loop *loop, struct ev_timer *w, int revents);
void dns_update_cb(struct ev_loop *loop, struct ev_timer *w, int revents);
void stat_timer_cb(struct ev_loop *loop, struct ev_timer *w, int revents);
void liteflow_set_eventtime(litedt_host_t *host, int64_t next_event_time);

uint32_t liteflow_flowid() 
{
    ++flow_seq;
    while (flow_seq == 0 || find_flow(flow_seq) != NULL)
        ++flow_seq;

    return flow_seq;
}

uint32_t flow_hash(void *key)
{
    return *(uint32_t *)key;
}

flow_info_t* find_flow(uint32_t flow)
{
    flow_info_t *info = (flow_info_t *)queue_get(&flow_tab, &flow);
    return info;
}

int create_flow(uint32_t flow)
{
    if (find_flow(flow) != NULL)
        return LITEFLOW_RECORD_EXISTS;
    flow_info_t info;

    memset(&info, 0, sizeof(flow_info_t));
    info.flow = flow;

    return queue_append(&flow_tab, &flow, &info);
}

void release_flow(uint32_t flow)
{
    queue_del(&flow_tab, &flow);
}

void litedt_io_cb(struct ev_loop *loop, struct ev_io *watcher, int revents)
{
    litedt_host_t *host = (litedt_host_t *)watcher->data;
    if (revents & EV_READ) {
        int64_t cur_time = ev_now(loop) * USEC_PER_SEC;
        litedt_io_event(host, cur_time);
    }
}

void litedt_timeout_cb(struct ev_loop *loop, struct ev_timer *w, int revents)
{
    int64_t cur_time = ev_now(loop) * USEC_PER_SEC;
    int64_t next_time = litedt_time_event(&litedt_host, cur_time);
    double after = (double)(next_time - cur_time) / (double)USEC_PER_SEC;

    if (ev_is_active(w)) {
        ev_timer_stop(loop, w);
    }

    if (after <= 0) {
        ev_timer_set(w, 0., 0.);
        ev_timer_start(loop, w);
    } else {
        ev_timer_set(w, after, 0.);
        ev_timer_start(loop, w);
    }
}

int liteflow_on_connect(litedt_host_t *host, uint32_t flow, uint16_t map_id)
{
    int idx = 0, ret;

    DBG("request connect: map_id=%u\n", map_id);
    while (g_config.allow_list[idx].target_port) {
        allow_access_t *allow = &g_config.allow_list[idx++];
        if (allow->map_id != map_id) 
            continue;
        switch (allow->protocol) {
        case PROTOCOL_TCP: {
                char *ip = allow->target_addr;
                int port = allow->target_port;
                ret = tcp_remote_init(host, flow, ip, port);
                return ret;
            }
        case PROTOCOL_UDP: {
                char *ip = allow->target_addr;
                int port = allow->target_port;
                ret = udp_remote_init(host, flow, ip, port);
                return ret;
            }
        }
    }

    return LITEFLOW_ACCESS_DENIED;
}

void liteflow_on_close(litedt_host_t *host, uint32_t flow)
{
    flow_info_t *info = find_flow(flow);
    if (NULL == info)
        return;
    info->remote_close_cb(host, info);
    release_flow(flow);
}

void liteflow_on_receive(litedt_host_t *host, uint32_t flow, int readable)
{
    flow_info_t *info = find_flow(flow);
    if (NULL == info)
        return;
    info->remote_recv_cb(host, info, readable);
}

void liteflow_on_send(litedt_host_t *host, uint32_t flow, int writable)
{
    flow_info_t *info = find_flow(flow);
    if (NULL == info)
        return;
    info->remote_send_cb(host, info, writable);
}

void ares_state_cb(void *data, int s, int read, int write)
{
    int events = (read ? EV_READ : 0) | (write ? EV_WRITE : 0);

    if (ev_is_active(&dns_io_watcher)) {
        ev_io_stop(loop, &dns_io_watcher);
    }
    
    if (events) {
        ev_io_set(&dns_io_watcher, s, events);
        ev_io_start(loop, &dns_io_watcher);
    } else {
        ev_io_set(&dns_io_watcher, -1, 0);
    }

    DBG("ares_state_cb: fd:%d read:%d write:%d\n", s, read, write);
}

void dns_query_cb(void *arg, int status, int timeouts, struct hostent *host)
{
    char ip[ADDRESS_MAX_LEN];

    if(!host || status != ARES_SUCCESS || !host->h_addr_list 
            || !host->h_addr_list[0]){
        LOG("Domain lookup failed (%s).\n", ares_strerror(status));
    } else {
        inet_ntop(host->h_addrtype, host->h_addr_list[0], ip, ADDRESS_MAX_LEN);
        LOG("Remote host address updated -- %s:%u\n", ip, 
                g_config.flow_remote_port);
        litedt_set_remote_addr(&litedt_host, ip, g_config.flow_remote_port);
    }

    // set next domain lookup time
    ev_timer_set(&dns_update_watcher, DNS_UPDATE_INTERVAL, 0.0);
    ev_timer_start(loop, &dns_update_watcher);
}

void dns_io_cb(struct ev_loop *loop, struct ev_io *watcher, int revents)
{
    ares_socket_t rfd = ARES_SOCKET_BAD, wfd = ARES_SOCKET_BAD;

    if (revents & EV_READ) {
        rfd = watcher->fd;
    }
    if (revents & EV_WRITE) {
        wfd = watcher->fd;
    }

    ares_process_fd(g_channel, rfd, wfd);
}

void dns_timeout_cb(struct ev_loop *loop, struct ev_timer *w, int revents)
{
    struct timeval *tvp, tv;
    double nwait = MAX_DNS_TIMEOUT;

    if (revents & EV_TIMER) {
        if (ev_is_active(&dns_timeout_watcher)) {
            ev_timer_stop(loop, &dns_timeout_watcher);
        }

        ares_process_fd(g_channel, ARES_SOCKET_BAD, ARES_SOCKET_BAD);
        tvp = ares_timeout(g_channel, NULL, &tv);
        nwait = TV_TO_FLOAT(tv);
        nwait = nwait < MIN_DNS_TIMEOUT ? MIN_DNS_TIMEOUT :
                (nwait > MAX_DNS_TIMEOUT ? MAX_DNS_TIMEOUT : nwait);

        ev_timer_set(&dns_timeout_watcher, nwait, 0);
        ev_timer_start(loop, &dns_timeout_watcher);
    }
}

void dns_update_cb(struct ev_loop *loop, struct ev_timer *w, int revents)
{
    struct timeval *tvp, tv;
    double nwait = MAX_DNS_TIMEOUT;

    if (revents & EV_TIMER) {
        char *domain = g_config.flow_remote_addr;
        if (ev_is_active(&dns_timeout_watcher)) {
            ev_timer_stop(loop, &dns_timeout_watcher);
        }

        ares_gethostbyname(g_channel, domain, AF_INET, dns_query_cb, NULL);
        tvp = ares_timeout(g_channel, NULL, &tv);
        nwait = TV_TO_FLOAT(tv);
        nwait = nwait < MIN_DNS_TIMEOUT ? MIN_DNS_TIMEOUT :
                (nwait > MAX_DNS_TIMEOUT ? MAX_DNS_TIMEOUT : nwait);

        ev_timer_set(&dns_timeout_watcher, nwait, 0);
        ev_timer_start(loop, &dns_timeout_watcher);
    }
}

void stat_timer_cb(struct ev_loop *loop, struct ev_timer *w, int revents)
{
    int ret = 0;
    static int stat_num = 0;
    if (revents & EV_TIMER) {
        litedt_stat_t *stat = litedt_get_stat(&litedt_host);
        inc_stat(stat);
        litedt_clear_stat(&litedt_host);
        if (++stat_num >= 60) {
            print_stat();
            clear_stat();
            stat_num = 0;
        }

        if (!litedt_online_status(&litedt_host)) {
            if (++online_monitor >= 120 && !g_config.flow_local_port) {
                // remote server keep offline over 120 seconds
                // try to reset local port
                int sockfd;

                litedt_shutdown(&litedt_host);
                sockfd = litedt_startup(&litedt_host);

                ev_io_stop(loop, &litedt_io_watcher);
                ev_io_init(&litedt_io_watcher, litedt_io_cb, sockfd, EV_READ);
                ev_io_start(loop, &litedt_io_watcher);
                online_monitor = 0;

                LOG("Notice: Local port has been reset.\n");
            }
        } else {
            online_monitor = 0;
        }

        if (need_reload_conf) {
            need_reload_conf = 0;
            LOG("Starting reload configuration.\n");
            if ((ret = reload_config_file()) == 0) {
                tcp_local_reload(loop, g_config.listen_list);
                udp_local_reload(loop, g_config.listen_list);
                LOG("Reload configuration success.\n");
            } else {
                LOG("Reload configuration failed: %d\n", ret);
            }
        }
    }
}

void liteflow_set_eventtime(litedt_host_t *host, int64_t next_event_time)
{
    double after = (double)next_event_time / (double)USEC_PER_SEC
        - ev_now(loop);

    if (ev_is_active(&litedt_timeout_watcher)) {
        ev_timer_stop(loop, &litedt_timeout_watcher);
    }

    if (after <= 0) {
        ev_timer_set(&litedt_timeout_watcher, 0., 0.);
        ev_timer_start(loop, &litedt_timeout_watcher);
    } else {
        ev_timer_set(&litedt_timeout_watcher, after, 0.);
        ev_timer_start(loop, &litedt_timeout_watcher);
    }
}

int start_domain_resolve(const char *domain)
{
    struct ares_options options;
    struct timeval *tvp, tv;
    int optmask = 0;
    int ret = 0;
    double nwait = MAX_DNS_TIMEOUT;

    ret = ares_library_init(ARES_LIB_INIT_ALL);
    if (ret != ARES_SUCCESS) {
        LOG("ares_library_init: %s\n", ares_strerror(ret));
        litedt_fini(&litedt_host);
        return -4;
    }

    options.sock_state_cb = ares_state_cb;
    optmask |= ARES_OPT_SOCK_STATE_CB;

    ret = ares_init_options(&g_channel, &options, optmask);
    if(ret != ARES_SUCCESS) {
        LOG("ares_init_options: %s\n", ares_strerror(ret));
        litedt_fini(&litedt_host);
        return -4;
    }

    if (g_config.dns_server_addr[0]) {
        ret = ares_set_servers_ports_csv(g_channel, g_config.dns_server_addr);
        if (ret != ARES_SUCCESS) {
            LOG("failed to set nameservers\n");
            litedt_fini(&litedt_host);
            return -4;
        }
    }

    ev_io_init(&dns_io_watcher, dns_io_cb, -1, EV_READ);
    ares_gethostbyname(g_channel, domain, AF_INET, dns_query_cb, NULL);

    tvp = ares_timeout(g_channel, NULL, &tv);
    nwait = TV_TO_FLOAT(tv);
    nwait = nwait < MIN_DNS_TIMEOUT ? MIN_DNS_TIMEOUT :
            (nwait > MAX_DNS_TIMEOUT ? MAX_DNS_TIMEOUT : nwait);
    
    ev_timer_init(&dns_timeout_watcher, dns_timeout_cb, nwait, 0);
    ev_timer_init(&dns_update_watcher, dns_update_cb, 0.0, 0.0);
    ev_timer_start(loop, &dns_timeout_watcher);
    
    return 0;
}

int init_liteflow()
{
    int idx = 0, sockfd, ret = 0;
    int64_t cur_time = ev_time() * USEC_PER_SEC;

    srand(time(NULL));
    loop = ev_default_loop(0);
    flow_seq = rand();

    queue_init(&flow_tab, FLOW_HASH_SIZE, sizeof(uint32_t), sizeof(flow_info_t),
               flow_hash, 0);

    // initialize protocol support
    tcp_init(loop, &litedt_host);
    udp_init(loop, &litedt_host);

    // binding local port
    while (g_config.listen_list[idx].local_port) {
        listen_port_t *listen_cfg = &g_config.listen_list[idx++];
        switch (listen_cfg->protocol) {
        case PROTOCOL_TCP: 
            ret = tcp_local_init(loop, listen_cfg->local_port, 
                listen_cfg->map_id);
            break;
        case PROTOCOL_UDP: 
            ret = udp_local_init(loop, listen_cfg->local_port, 
                listen_cfg->map_id);
            break;
        }
        if (ret != 0)
            break;
    }
    if (ret != 0) {
        LOG("Local port init failed\n");
        return ret;
    }

    sockfd = litedt_init(&litedt_host, cur_time);
    if (sockfd < 0) {
        LOG("litedt init error: %s\n", strerror(errno));
        return sockfd;
    }

    if (g_config.flow_remote_addr[0]) {
        mode = ACTIVE_MODE;
        // checking whether flow_remote_addr is a IPv4 address
        if (inet_addr(g_config.flow_remote_addr) == 0xFFFFFFFF) {
            if (start_domain_resolve(g_config.flow_remote_addr) != 0) {
                LOG("Domain lookup failed.\n");
                litedt_fini(&litedt_host);
                return -4;
            }
        } else {
            litedt_set_remote_addr(&litedt_host, g_config.flow_remote_addr, 
                g_config.flow_remote_port);
        }
    } else {
        mode = PASSIVE_MODE;
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

static void reload_conf_handler(int signum)
{
    need_reload_conf = 1;
}

void start_liteflow()
{
    clear_stat();
    ev_timer_init(&litedt_timeout_watcher, litedt_timeout_cb, 0., 0.);
    ev_timer_start(loop, &litedt_timeout_watcher);
    ev_timer_init(&stat_watcher, stat_timer_cb, 1., 1.);
    ev_timer_start(loop, &stat_watcher);

    struct sigaction sa = {};
    sa.sa_handler = reload_conf_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;

    sigaction(SIGUSR1, &sa, NULL);
    
    while (1) {
        ev_loop(loop, 0);
    }
}
