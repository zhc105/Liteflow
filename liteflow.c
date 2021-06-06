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
#define PEER_HASH_SIZE          101
#define MAX_DNS_TIMEOUT         60.0
#define MIN_DNS_TIMEOUT         1.0
#define DNS_UPDATE_INTERVAL     300.0

#define TV_TO_FLOAT(tv) ((double)(tv).tv_sec + ((double)(tv).tv_usec / 1000000.0))

typedef struct _client_info {
    struct ev_io    io_watcher;
    struct ev_timer time_watcher;
    uint8_t         is_outbound;
    litedt_host_t   dt;
    char            address[DOMAIN_MAX_LEN];
    uint16_t        port;
} client_info_t;

static hash_queue_t     flow_tab;
static hash_queue_t     outbound_peers;
static hash_queue_t     inbound_peers;
static struct ev_loop   *loop;
static litedt_host_t    litedt_host;
static struct ev_io     host_io_watcher;
static struct ev_io     dns_io_watcher;
static struct ev_timer  dns_timeout_watcher;
static struct ev_timer  stat_watcher;
static uint32_t         flow_seq;
static volatile int     need_reload_conf = 0;
static ares_channel     g_channel;

/*
 * libev callback that handling litedt socket IO
 */
static void 
litedt_io_cb(struct ev_loop *loop, struct ev_io *watcher, int revents);

/*
 * libev callback that handling litedt time event
 */
static void 
litedt_timeout_cb(struct ev_loop *loop, struct ev_timer *w, int revents);

/*
 * create new client and assign to litedt host
 */
static client_info_t*
new_client_in(uint16_t node_id, const struct sockaddr_in *peer_addr);

static client_info_t*
new_client_out(const char *address_port);

/*
 * release liteflow client
 */
static void
release_client(client_info_t *client);

/*
 * start to resolve domain for specified outbound client
 */
static void
resolve_outbound_client(client_info_t *client);

/*
 * start I/O and time event for specified liteflow client
 */
static void
start_client(
    client_info_t *client,
    const struct sockaddr_in *peer_addr,
    int reset_timer);

/*
 * litedt callback that handling new incoming client request
 */
static void
liteflow_on_accept(
    litedt_host_t *host, 
    uint16_t node_id, 
    const struct sockaddr_in *addr);

/*
 * litedt callback that monitoring litedt state change
 */
static void
liteflow_on_online(litedt_host_t *host, int online);

/*
 * litedt callback that handling new incoming flow
 */
static int
liteflow_on_connect(litedt_host_t *host, uint32_t flow, uint16_t tunnel_id);

/*
 * litedt callback that handling flow closed event
 */
static void
liteflow_on_close(litedt_host_t *host, uint32_t flow);

/*
 * litedt callback that notifying litedt radable
 */
static void
liteflow_on_receive(litedt_host_t *host, uint32_t flow, int readable);

/*
 * litedt callback that notifying litedt writable
 */
static void
liteflow_on_send(litedt_host_t *host, uint32_t flow, int writable);

/*
 * ares callback that handling state change
 */
static void 
ares_state_cb(void *data, int s, int read, int write);

/*
 * ares callback that handling dns query result
 */
static void
dns_query_cb(void *arg, int status, int timeouts, struct hostent *host);

/*
 * libev callback that handling c-ares socket IO
 */
static void
dns_io_cb(struct ev_loop *loop, struct ev_io *watcher, int revents);

/*
 * libev callback that handling c-ares time event
 */
static void
dns_timeout_cb(struct ev_loop *loop, struct ev_timer *w, int revents);

/*
 * libev callback that printing global statistic log
 */
static void
stat_timer_cb(struct ev_loop *loop, struct ev_timer *w, int revents);

/*
 * litedt callback that notify next litedt event time
 */
static void
liteflow_set_eventtime(litedt_host_t *host, int64_t next_event_time);


uint32_t liteflow_flowid() 
{
    ++flow_seq;
    while (flow_seq == 0 || find_flow(flow_seq) != NULL)
        ++flow_seq;

    return flow_seq;
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

static uint32_t flow_hash(void *key)
{
    return *(uint32_t*)key;
}

static uint32_t node_id_hash(void *key)
{
    return (uint32_t)(*(uint16_t*)key);
}

static uint32_t domain_hash(void *key)
{
    uint32_t hash = 5381;
    uint8_t *str = (uint8_t*)key;
    int c;

    while (c = *str++)
        hash = ((hash << 5) + hash) + c; /* hash * 33 + c */

    return hash;
}

/*
 * Parse peer endpoint string with format <domain|ip>:<port> and save in 
 * client->address, client->port
 */
static void 
parse_client_address_port(client_info_t *client, const char *address_port)
{
    char *pos;
    memset(client->address, 0, DOMAIN_MAX_LEN);
    client->port = DEFAULT_PORT;

    if (strnlen(address_port, DOMAIN_MAX_LEN) > DOMAIN_MAX_LEN - 1) {
        LOG("Warning: peer address length exceed\n");
        return;
    }

    if ((pos = strrchr(address_port, ':')) != NULL) {
        strncpy(client->address, address_port, pos - address_port);
        client->port = atoi(pos + 1);
    } else {
        strncpy(client->address, address_port, DOMAIN_MAX_LEN);
    }
}

static void 
litedt_io_cb(struct ev_loop *loop, struct ev_io *watcher, int revents)
{
    litedt_host_t *dt = (litedt_host_t*)watcher->data;
    if (revents & EV_READ) {
        litedt_io_event(dt);
    }
}

static void
litedt_timeout_cb(struct ev_loop *loop, struct ev_timer *w, int revents)
{
    client_info_t *client = (client_info_t *)w->data;
    int64_t next_time = litedt_time_event(&client->dt);

    if (next_time != -1) {
        double after = (double)(next_time - get_curtime()) / (double)USEC_PER_SEC;
        ev_timer_set(w, after <= 0 ? 0. : after, 0.);
        ev_timer_start(loop, w);
    }
}

static client_info_t*
new_client_in(uint16_t node_id, const struct sockaddr_in *peer_addr)
{
    client_info_t dummy, *client = NULL;
    int ret = 0;

    if ((ret = queue_append(&inbound_peers, &node_id, &dummy)) != 0) {
        LOG("Failed to create liteflow client: %d\n", ret);
        return NULL;
    }

    client = queue_get(&outbound_peers, &node_id);
    client->is_outbound = 0;
    litedt_init(&client->dt);
    litedt_set_ext(&client->dt, client);
    litedt_set_online_cb(&client->dt, liteflow_on_online);
    litedt_set_connect_cb(&client->dt, liteflow_on_connect);
    litedt_set_receive_cb(&client->dt, liteflow_on_receive);
    litedt_set_send_cb(&client->dt, liteflow_on_send);
    litedt_set_close_cb(&client->dt, liteflow_on_close);
    litedt_set_event_time_cb(&client->dt, liteflow_set_eventtime);

    ev_io_init(&client->io_watcher, litedt_io_cb, -1, EV_READ);
    client->io_watcher.data = &client->dt;
    ev_timer_init(&client->time_watcher, litedt_timeout_cb, 0., 0.);
    client->time_watcher.data = client;

    start_client(client, peer_addr, 1);
    return client;
}

static client_info_t* 
new_client_out(const char *address_port)
{
    client_info_t dummy, *client = NULL;
    char addr_buf[DOMAIN_MAX_LEN] = { 0 };
    int ret = 0;

    strncpy(addr_buf, address_port, DOMAIN_MAX_LEN);
    if ((ret = queue_append(&outbound_peers, addr_buf, &dummy)) != 0) {
        LOG("Failed to create liteflow client: %d\n", ret);
        return NULL;
    }

    client = queue_get(&outbound_peers, addr_buf);
    client->is_outbound = 1;
    parse_client_address_port(client, address_port);
    litedt_init(&client->dt);
    litedt_set_ext(&client->dt, client);
    litedt_set_online_cb(&client->dt, liteflow_on_online);
    litedt_set_connect_cb(&client->dt, liteflow_on_connect);
    litedt_set_receive_cb(&client->dt, liteflow_on_receive);
    litedt_set_send_cb(&client->dt, liteflow_on_send);
    litedt_set_close_cb(&client->dt, liteflow_on_close);
    litedt_set_event_time_cb(&client->dt, liteflow_set_eventtime);

    ev_io_init(&client->io_watcher, litedt_io_cb, -1, EV_READ);
    client->io_watcher.data = &client->dt;
    ev_timer_init(&client->time_watcher, litedt_timeout_cb, 1., 0.);
    client->time_watcher.data = client;

    resolve_outbound_client(client);
    return client;
}

static void
release_client(client_info_t *client)
{
    char addr_buf[DOMAIN_MAX_LEN + 10] = { 0 };
    if (!litedt_is_closed(&client->dt)) {
        litedt_shutdown(&client->dt);
    }
    
    if (client->is_outbound) {
        snprintf(addr_buf, DOMAIN_MAX_LEN + 10, "%s:%u", 
            client->address, client->port);
        queue_del(&outbound_peers, addr_buf);
    } else {
        uint16_t node_id = litedt_peer_node_id(&client->dt);
        queue_del(&inbound_peers, &node_id);
    }
}

static void
resolve_outbound_client(client_info_t *client)
{
    struct sockaddr_in addr = {};
    struct timeval *tvp, tv;
    double nwait = MAX_DNS_TIMEOUT;

    // checking whether client->address is a IPv4 address
    if (inet_addr(client->address) == 0xFFFFFFFF) {
        ares_gethostbyname(
            g_channel,
            client->address,
            AF_INET,
            dns_query_cb,
            client);

        tvp = ares_timeout(g_channel, NULL, &tv);
        nwait = TV_TO_FLOAT(tv);
        nwait = nwait < MIN_DNS_TIMEOUT ? MIN_DNS_TIMEOUT :
                (nwait > MAX_DNS_TIMEOUT ? MAX_DNS_TIMEOUT : nwait);

        if (ev_is_active(&dns_timeout_watcher)) {
            ev_timer_stop(loop, &dns_timeout_watcher);
        }
        ev_timer_set(&dns_timeout_watcher, nwait, 0);
        ev_timer_start(loop, &dns_timeout_watcher);
    } else {
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = inet_addr(client->address);
        addr.sin_port = htons(client->port);
        start_client(client, &addr, 1);
    }
}

static void
start_client(
    client_info_t *client,
    const struct sockaddr_in *peer_addr,
    int reset_timer)
{
    int sockfd = -1;
    litedt_set_remote_addr(&client->dt, peer_addr);
    sockfd = litedt_startup(&client->dt, 1, 0);
    if (sockfd < 0) {
        LOG("litedt_startup failed.\n");
        release_client(client);
        return;
    }

    ev_io_set(&client->io_watcher, sockfd, EV_READ);
    ev_io_start(loop, &client->io_watcher);
    if (reset_timer) {
        ev_timer_set(&client->time_watcher, 1., 0.);
        ev_timer_start(loop, &client->time_watcher);
    } 
}

static void 
liteflow_on_accept(
    litedt_host_t *host,
    uint16_t node_id,
    const struct sockaddr_in *addr)
{
    char ip[ADDRESS_MAX_LEN];
    client_info_t *client;
    uint16_t port = ntohs(addr->sin_port);

    inet_ntop(AF_INET, &addr->sin_addr, ip, ADDRESS_MAX_LEN);
    
    client = (client_info_t*)queue_get(&inbound_peers, &node_id);
    if (client != NULL) {
        LOG("Reassign node[%u] peer address to %s:%u\n", node_id, ip, port);
        if (ev_is_active(&client->io_watcher))
            ev_io_stop(loop, &client->io_watcher);
        litedt_shutdown(host);
        start_client(client, addr, 0);
    } else {
        if (queue_size(&inbound_peers) >= g_config.max_incoming_clients) {
            LOG("Failed to accept new node[%u]: Too Many Connections\n",
                node_id);
            return;
        }
        LOG("Accepted new node[%u] from %s:%u\n", node_id, ip, port);
        new_client_in(node_id, addr);
    }
}

static void
liteflow_on_online(litedt_host_t *host, int online)
{
    client_info_t *client = (client_info_t*)litedt_ext(host);

    if (!online) {
        if (ev_is_active(&client->io_watcher))
            ev_io_stop(loop, &client->io_watcher);
        if (ev_is_active(&client->time_watcher))
            ev_timer_stop(loop, &client->time_watcher);
        litedt_shutdown(host);

        if (client->is_outbound) {
            LOG("Notice: Reconnecting outbound peer %s:%u.\n",
                client->address, client->port);
            resolve_outbound_client(client);
        } else {
            release_client(client);
        }
    }
}

static int
liteflow_on_connect(litedt_host_t *host, uint32_t flow, uint16_t tunnel_id)
{
    int idx = 0, ret;

    DBG("request connect: tunnel_id=%u\n", tunnel_id);
    while (g_config.allow_list[idx].target_port) {
        allow_access_t *allow = &g_config.allow_list[idx++];
        if (allow->tunnel_id != tunnel_id) 
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

static void
liteflow_on_close(litedt_host_t *host, uint32_t flow)
{
    flow_info_t *info = find_flow(flow);
    if (NULL == info)
        return;
    info->remote_close_cb(host, info);
    release_flow(flow);
}

static void
liteflow_on_receive(litedt_host_t *host, uint32_t flow, int readable)
{
    flow_info_t *info = find_flow(flow);
    if (NULL == info)
        return;
    info->remote_recv_cb(host, info, readable);
}

static void
liteflow_on_send(litedt_host_t *host, uint32_t flow, int writable)
{
    flow_info_t *info = find_flow(flow);
    if (NULL == info)
        return;
    info->remote_send_cb(host, info, writable);
}

static void
ares_state_cb(void *data, int s, int read, int write)
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

static void
dns_query_cb(void *arg, int status, int timeouts, struct hostent *host)
{
    struct sockaddr_in addr = {};
    char ip[ADDRESS_MAX_LEN];
    client_info_t *client = (client_info_t*)arg;

    if(!host || status != ARES_SUCCESS || !host->h_addr_list 
            || !host->h_addr_list[0]){
        LOG("Domain lookup failed (%s).\n", ares_strerror(status));
        liteflow_on_online(&client->dt, 0);
    } else {
        inet_ntop(host->h_addrtype, host->h_addr_list[0], ip, ADDRESS_MAX_LEN);
        LOG("Domain resolve success %s => %s\n", client->address, ip);
       
        addr.sin_family = AF_INET;
        addr.sin_port = htons(client->port);
        memcpy(&addr.sin_addr, host->h_addr_list[0], host->h_length); 
        start_client(client, &addr, 1);
    }
}

static void 
dns_io_cb(struct ev_loop *loop, struct ev_io *watcher, int revents)
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

static void
dns_timeout_cb(struct ev_loop *loop, struct ev_timer *w, int revents)
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

static void
stat_timer_cb(struct ev_loop *loop, struct ev_timer *w, int revents)
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
    client_info_t *client = (client_info_t*)litedt_ext(host);
    double after = (double)(next_event_time - get_curtime()) 
        / (double)USEC_PER_SEC;

    if (ev_is_active(&client->time_watcher)) {
        ev_timer_stop(loop, &client->time_watcher);
    }

    ev_timer_set(&client->time_watcher, after > 0 ? after : 0., 0.);
    ev_timer_start(loop, &client->time_watcher);
}

int init_resolver()
{
    struct ares_options options;
    struct timeval *tvp, tv;
    int optmask = 0;
    int ret = 0;
    double nwait = MAX_DNS_TIMEOUT;

    ret = ares_library_init(ARES_LIB_INIT_ALL);
    if (ret != ARES_SUCCESS) {
        LOG("ares_library_init: %s\n", ares_strerror(ret));
        return -4;
    }

    options.sock_state_cb = ares_state_cb;
    optmask |= ARES_OPT_SOCK_STATE_CB;

    ret = ares_init_options(&g_channel, &options, optmask);
    if(ret != ARES_SUCCESS) {
        LOG("ares_init_options: %s\n", ares_strerror(ret));
        return -4;
    }

    if (g_config.dns_server_addr[0]) {
        ret = ares_set_servers_ports_csv(g_channel, g_config.dns_server_addr);
        if (ret != ARES_SUCCESS) {
            LOG("failed to set nameservers\n");
            return -4;
        }
    }

    ev_io_init(&dns_io_watcher, dns_io_cb, -1, EV_READ);
    ev_timer_init(&dns_timeout_watcher, dns_timeout_cb, 0., 0.);
    return 0;
}

int init_liteflow()
{
    int idx = 0, sockfd, ret = 0;
    struct sockaddr_in addr;
    int64_t cur_time = ev_time() * USEC_PER_SEC;

    loop = ev_default_loop(0);
    flow_seq = rand();

    queue_init(&flow_tab, FLOW_HASH_SIZE, sizeof(uint32_t), 
                sizeof(flow_info_t), flow_hash, 0);
    queue_init(&outbound_peers, FLOW_HASH_SIZE, DOMAIN_MAX_LEN,
                sizeof(client_info_t), domain_hash, 0);
    queue_init(&inbound_peers, FLOW_HASH_SIZE, sizeof(uint16_t),
                sizeof(client_info_t), node_id_hash, 0);
    
    if (init_resolver() != 0)
        return -1;

    // initialize entrance protocol support
    tcp_init(loop, &litedt_host);
    udp_init(loop, &litedt_host);

    // binding local port
    while (g_config.listen_list[idx].local_port) {
        listen_port_t *listen_cfg = &g_config.listen_list[idx++];
        switch (listen_cfg->protocol) {
        case PROTOCOL_TCP: 
            ret = tcp_local_init(loop, listen_cfg->local_port, 
                listen_cfg->tunnel_id);
            break;
        case PROTOCOL_UDP: 
            ret = udp_local_init(loop, listen_cfg->local_port, 
                listen_cfg->tunnel_id);
            break;
        }
        if (ret != 0)
            break;
    }
    if (ret != 0) {
        LOG("Local port init failed\n");
        return ret;
    }

    if (g_config.flow_remote_addr[0]) {
        new_client_out(g_config.flow_remote_addr);
    }

    if (g_config.max_incoming_clients > 0) {
        litedt_init(&litedt_host);
        sockfd = litedt_startup(&litedt_host, 0, 0);
        if (sockfd < 0) {
            LOG("litedt init error: %s\n", strerror(errno));
            return sockfd;
        }

        litedt_set_accept_cb(&litedt_host, liteflow_on_accept);

        ev_io_init(&host_io_watcher, litedt_io_cb, sockfd, EV_READ);
        host_io_watcher.data = &litedt_host;
        ev_io_start(loop, &host_io_watcher);
    }
    
    return 0;
}

static void reload_conf_handler(int signum)
{
    need_reload_conf = 1;
}

void start_liteflow()
{
    clear_stat();
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