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
#include "fnv.h"
#include "hashqueue.h"
#include "liteflow.h"
#include "util.h"
#include "tcp.h"
#include "udp.h"

#define PEER_HASH_SIZE          101
#define MAX_DNS_TIMEOUT         60.0
#define MIN_DNS_TIMEOUT         1.0
#define DNS_RETRY_INTERVAL      10.0

#define TV_TO_FLOAT(tv) \
    ((double)(tv).tv_sec + ((double)(tv).tv_usec / 1000000.0))

static hash_queue_t     peers_tab;
static hash_queue_t     peers_outbound;
static uint32_t         peers_inbound_cnt = 0;
static uint32_t         next_flow;
static struct ev_loop   *loop;
static litedt_host_t    litedt_host;
static struct ev_io     host_io_watcher;
static struct ev_io     dns_io_watcher;
static struct ev_timer  dns_timeout_watcher;
static struct ev_timer  monitor_watcher;
static litedt_time_t    last_stat_time = 0;
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
 * create new peer and assign to litedt host
 */
static peer_info_t*
new_peer_inbound(uint16_t node_id, const struct sockaddr *peer_addr,
    socklen_t addr_len);

static peer_info_t*
new_peer_outbound(const char *address_port);

static peer_info_t*
new_peer();

/*
 * release liteflow peer
 */
static void
release_peer(peer_info_t *peer);

/*
 * start to resolve domain for specified outbound peer
 */
static void
resolve_outbound_peer(peer_info_t *peer);

/*
 * start I/O and time event for specified liteflow peer
 */
static void
peer_start(peer_info_t *peer, const struct sockaddr *peer_addr,
    socklen_t addr_len);

/*
 * litedt callback that handling new incoming peer request
 */
static void
liteflow_on_accept(litedt_host_t *host, uint16_t node_id,
    const struct sockaddr *addr, socklen_t addr_len);

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
 * libev callback that dns resolve failed
 */
static void
dns_failed_cb(struct ev_loop *loop, struct ev_timer *w, int revents);

/*
 * libev callback that printing global statistic log
 */
static void
monitor_cb(struct ev_loop *loop, struct ev_timer *w, int revents);

/*
 * litedt callback that notify next litedt event time
 */
static void
liteflow_set_eventtime(litedt_host_t *host, litedt_time_t event_after);

/*
 * Print statistics log per minute
 */
static void
print_statistics();

/*
 * Return bandwidth string in human readable format
 */
static const char*
bw_human(uint32_t bw);

uint32_t next_flow_id(peer_info_t *peer)
{
    uint32_t flow;
    do {
        flow = next_flow++;
        flow = (g_config.transport.node_id < peer->peer_id ? 0 : 1)
                | (flow << 1) ;
    } while (!flow || find_flow(peer, flow) != NULL);
    return flow;
}

peer_info_t* find_peer(uint16_t peer_id)
{
    peer_info_t **info = NULL;
    if (peer_id)
        info = (peer_info_t **)queue_get(&peers_tab, &peer_id);
    else if (!queue_empty(&peers_tab))
        info = (peer_info_t **)queue_front(&peers_tab, NULL);
    return info ? *info : NULL;
}

flow_info_t* find_flow(peer_info_t *peer, uint32_t flow)
{
    return (flow_info_t *)treemap_get(&peer->flow_map, &flow);
}

int create_flow(peer_info_t *peer, uint32_t flow)
{
    if (find_flow(peer, flow) != NULL)
        return LITEFLOW_RECORD_EXISTS;
    flow_info_t info;

    memset(&info, 0, sizeof(flow_info_t));
    info.flow = flow;
    info.peer = peer;

    return treemap_insert(&peer->flow_map, &flow, &info);
}

void release_flow(peer_info_t *peer, uint32_t flow)
{
    treemap_delete(&peer->flow_map, &flow);
}

static uint32_t domain_hash(const void *key, size_t len)
{
    return fnv_32_str((const char*)key, FNV1_32_INIT);
}

/*
 * Parse peer endpoint string with format <domain|ip>:<port> and save in
 * peer->address, peer->port
 */
static void
parse_peer_address_port(peer_info_t *peer, const char *address_port)
{
    char *pos;
    size_t address_port_len = strnlen(address_port, DOMAIN_PORT_MAX_LEN);
    memset(peer->address, 0, DOMAIN_MAX_LEN);
    peer->port = DEFAULT_PORT;

    if (address_port_len > DOMAIN_PORT_MAX_LEN - 1) {
        LOG("Warning: peer address length exceed\n");
        return;
    }

    if ((pos = strrchr(address_port, ':')) != NULL) {
        if (pos - address_port >= DOMAIN_MAX_LEN) {
            LOG("Warning: peer address length exceed\n");
            return;
        }
        strncpy(peer->address, address_port, pos - address_port);
        peer->port = atoi(pos + 1);
    } else {
        if (address_port_len >= DOMAIN_MAX_LEN) {
            LOG("Warning: peer address length exceed\n");
            return;
        }
        strncpy(peer->address, address_port, DOMAIN_MAX_LEN);
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
    peer_info_t *peer = (peer_info_t *)w->data;
    litedt_time_t event_after = litedt_time_event(&peer->dt);

    if (event_after != -1) {
        double after = (double)event_after / (double)USEC_PER_SEC;
        ev_timer_set(w, after <= 0 ? 0. : after, 0.);
        ev_timer_start(loop, w);
    }
}

static peer_info_t*
new_peer_inbound(uint16_t node_id, const struct sockaddr *peer_addr,
    socklen_t addr_len)
{
    peer_info_t *peer = NULL;
    int ret = 0;

    peer = new_peer();
    if (peer == NULL) {
        LOG("Failed to create inbound peer\n");
        return NULL;
    }

    peer->is_outbound = 0;
    peer->peer_id = node_id;
    if ((ret = queue_append(&peers_tab, &node_id, &peer)) != 0) {
        LOG("Failed to create liteflow peer: %d\n", ret);
        return NULL;
    }

    peer_start(peer, peer_addr, addr_len);
    return peer;
}

static peer_info_t*
new_peer_outbound(const char *address_port)
{
    peer_info_t *peer = NULL;
    char addr_buf[DOMAIN_PORT_MAX_LEN] = { 0 };
    int ret = 0;

    strncpy(addr_buf, address_port, DOMAIN_PORT_MAX_LEN - 1);
    if (queue_get(&peers_outbound, addr_buf)) {
        LOG("Duplicated peer: %s\n", address_port);
        return NULL;
    }

    peer = new_peer();
    if (peer == NULL) {
        LOG("Failed to create outbound peer\n");
        return NULL;
    }

    peer->is_outbound = 1;
    peer->resolve_ipv6 = g_config.service.prefer_ipv6 ? 1 : 0;
    parse_peer_address_port(peer, address_port);
    if ((ret = queue_append(&peers_outbound, addr_buf, &peer)) != 0) {
        LOG("Failed to insert outbound peer: %d\n", ret);
        return NULL;
    }

    resolve_outbound_peer(peer);
    return peer;
}

static peer_info_t* new_peer()
{
    peer_info_t *peer = (peer_info_t*)malloc(sizeof(peer_info_t));
    if (peer == NULL) {
        return NULL;
    }

    if (litedt_init(&peer->dt) != 0)
        return NULL;

    litedt_set_ext(&peer->dt, peer);
    litedt_set_online_cb(&peer->dt, liteflow_on_online);
    litedt_set_connect_cb(&peer->dt, liteflow_on_connect);
    litedt_set_receive_cb(&peer->dt, liteflow_on_receive);
    litedt_set_send_cb(&peer->dt, liteflow_on_send);
    litedt_set_close_cb(&peer->dt, liteflow_on_close);
    litedt_set_event_time_cb(&peer->dt, liteflow_set_eventtime);

    treemap_init(&peer->flow_map, sizeof(uint32_t), sizeof(flow_info_t),
                seq_cmp);

    peer->io_watcher.data = &peer->dt;
    peer->time_watcher.data = peer;
    peer->peer_id = 0;
    peer->resolve_ipv6 = 0;

    return peer;
}

static void
release_peer(peer_info_t *peer)
{
    tree_node_t *it;
    flow_info_t *flow;
    char addr_buf[DOMAIN_PORT_MAX_LEN] = { 0 };
    if (!litedt_is_closed(&peer->dt)) {
        litedt_shutdown(&peer->dt);
    }

    if (peer->is_outbound) {
        snprintf(addr_buf, DOMAIN_PORT_MAX_LEN, "%s:%u",
            peer->address, peer->port);
        queue_del(&peers_outbound, addr_buf);
    } else {
        --peers_inbound_cnt;
    }

    if (peer->peer_id != 0)
        queue_del(&peers_tab, &peer->peer_id);

    for (it = treemap_first(&peer->flow_map); it != NULL;
        it = treemap_next(it)) {
        flow = (flow_info_t *)treemap_value(&peer->flow_map, it);
        flow->remote_close_cb(&flow->peer->dt, flow);
    }

    treemap_fini(&peer->flow_map);
    litedt_fini(&peer->dt);
    free(peer);
}

static void
resolve_outbound_peer(peer_info_t *peer)
{
    struct sockaddr_storage storage = {};
    struct timeval *tvp, tv;
    double nwait = MAX_DNS_TIMEOUT;
    int af = get_addr_family(peer->address);

    if (af == AF_INET) {
        // peer->address is a IPv4 address
        struct sockaddr_in *addr = (struct sockaddr_in *)&storage;
        socklen_t addr_len = sizeof(struct sockaddr_in);
        addr->sin_family = AF_INET;
        addr->sin_port = htons(peer->port);
        inet_pton(AF_INET, peer->address, &(addr->sin_addr));

        peer_start(peer, (struct sockaddr *)addr, addr_len);
    } else if (af == AF_INET6) {
        // peer->address is a IPv6 address
        struct sockaddr_in6 *addr = (struct sockaddr_in6 *)&storage;
        socklen_t addr_len = sizeof(struct sockaddr_in6);
        addr->sin6_family = AF_INET6;
        addr->sin6_port = htons(peer->port);
        inet_pton(AF_INET6, peer->address, &(addr->sin6_addr));

        peer_start(peer, (struct sockaddr *)addr, addr_len);
    } else {
        // peer->address is a domain
        ares_gethostbyname(
            g_channel,
            peer->address,
            peer->resolve_ipv6 ? AF_INET6 : AF_INET,
            dns_query_cb,
            peer);

        tvp = ares_timeout(g_channel, NULL, &tv);
        nwait = TV_TO_FLOAT(tv);
        nwait = nwait < MIN_DNS_TIMEOUT ? MIN_DNS_TIMEOUT :
                (nwait > MAX_DNS_TIMEOUT ? MAX_DNS_TIMEOUT : nwait);

        if (ev_is_active(&dns_timeout_watcher)) {
            ev_timer_stop(loop, &dns_timeout_watcher);
        }

        ev_timer_set(&dns_timeout_watcher, nwait, 0);
        ev_timer_start(loop, &dns_timeout_watcher);
    }
}

static void
peer_start(peer_info_t *peer, const struct sockaddr *peer_addr,
    socklen_t addr_len)
{
    int sockfd = -1;
    litedt_set_remote_addr(&peer->dt, peer_addr, addr_len);
    sockfd = litedt_startup(&peer->dt, 1, peer->peer_id);
    if (sockfd < 0) {
        LOG("litedt_startup failed.\n");
        release_peer(peer);
        return;
    }

    ev_io_init(&peer->io_watcher, litedt_io_cb, sockfd, EV_READ);
    ev_io_start(loop, &peer->io_watcher);
    ev_timer_init(&peer->time_watcher, litedt_timeout_cb, 0., 0.);
    ev_timer_start(loop, &peer->time_watcher);
}

static void
liteflow_on_accept(litedt_host_t *host, uint16_t node_id,
    const struct sockaddr *addr, socklen_t addr_len)
{
    char ip[ADDRESS_MAX_LEN];
    peer_info_t *peer, **peer_ptr;
    uint16_t port;

    get_ip_port(addr, ip, ADDRESS_MAX_LEN, &port);
    peer_ptr = (peer_info_t**)queue_get(&peers_tab, &node_id);
    if (peer_ptr != NULL) {
        peer = *peer_ptr;
        LOG("Reassign peer[%u] address to %s:%u\n", node_id, ip, port);
        if (ev_is_active(&peer->io_watcher))
            ev_io_stop(loop, &peer->io_watcher);
        if (ev_is_active(&peer->time_watcher))
            ev_timer_stop(loop, &peer->time_watcher);

        litedt_shutdown(&peer->dt);
        peer_start(peer, addr, addr_len);
    } else {
        if (peers_inbound_cnt >= g_config.service.max_incoming_peers) {
            LOG("Failed to accept new peer[%u]: Too Many Connections\n",
                node_id);
            return;
        }
        LOG("Accepted new peer[%u] from %s:%u\n", node_id, ip, port);
        ++peers_inbound_cnt;
        new_peer_inbound(node_id, addr, addr_len);
    }
}

static void
liteflow_on_online(litedt_host_t *host, int online)
{
    peer_info_t *peer = (peer_info_t*)litedt_ext(host);
    peer_info_t **ptr;

    if (online) {
        if (peer->is_outbound) {
            peer->peer_id = host->peer_node_id;
            ptr = queue_get(&peers_tab, &peer->peer_id);
            if (ptr == NULL) {
                queue_append(&peers_tab, &peer->peer_id, &peer);
            } else if (*ptr != peer) {
                LOG("Warning: Overwrite conflict peer[%u] from %s:%u",
                    peer->peer_id, peer->address, peer->port);
                release_peer(*ptr);
                *ptr = peer;
            }
        }
    } else {
        if (ev_is_active(&peer->io_watcher))
            ev_io_stop(loop, &peer->io_watcher);
        if (ev_is_active(&peer->time_watcher))
            ev_timer_stop(loop, &peer->time_watcher);
        litedt_shutdown(host);

        if (peer->is_outbound) {
            if (peer->peer_id) {
                queue_del(&peers_tab, &peer->peer_id);
                peer->peer_id = 0;
            }

            LOG("Notice: Reconnecting %s:%u.\n", peer->address, peer->port);
            resolve_outbound_peer(peer);
        } else {
            release_peer(peer);
        }
    }
}

static int
liteflow_on_connect(litedt_host_t *host, uint32_t flow, uint16_t tunnel_id)
{
    int idx = 0, ret;
    peer_info_t *peer = (peer_info_t*)litedt_ext(host);

    DBG("request connect: tunnel_id=%u\n", tunnel_id);
    while (g_config.forward_rules[idx].destination_port) {
        forward_rule_t *forward = &g_config.forward_rules[idx++];
        if (forward->tunnel_id != tunnel_id)
            continue;
        if (forward->node_id && forward->node_id != litedt_peer_node_id(host))
            continue;
        switch (forward->protocol) {
        case PROTOCOL_TCP: {
                char *ip = forward->destination_addr;
                int port = forward->destination_port;
                ret = tcp_remote_init(peer, flow, ip, port);
                return ret;
            }
        case PROTOCOL_UDP: {
                char *ip = forward->destination_addr;
                int port = forward->destination_port;
                ret = udp_remote_init(peer, flow, ip, port);
                return ret;
            }
        }
    }

    return LITEFLOW_ACCESS_DENIED;
}

static void
liteflow_on_close(litedt_host_t *host, uint32_t flow)
{
    peer_info_t *peer = (peer_info_t*)litedt_ext(host);
    flow_info_t *info = find_flow(peer, flow);
    if (NULL == info)
        return;
    info->remote_close_cb(host, info);
    release_flow(peer, flow);
}

static void
liteflow_on_receive(litedt_host_t *host, uint32_t flow, int readable)
{
    peer_info_t *peer = (peer_info_t*)litedt_ext(host);
    flow_info_t *info = find_flow(peer, flow);
    if (NULL == info)
        return;
    info->remote_recv_cb(host, info, readable);
}

static void
liteflow_on_send(litedt_host_t *host, uint32_t flow, int writable)
{
    peer_info_t *peer = (peer_info_t*)litedt_ext(host);
    flow_info_t *info = find_flow(peer, flow);
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
    struct sockaddr_storage storage = {};
    char ip[ADDRESS_MAX_LEN];
    peer_info_t *peer = (peer_info_t*)arg;

    if(!host || status != ARES_SUCCESS || !host->h_addr_list
            || !host->h_addr_list[0]){
        LOG("Domain resolve failed (%s).\n", ares_strerror(status));

        /* Sleep 10 seconds then retry resolve domain */
        if (ev_is_active(&peer->time_watcher))
            ev_timer_stop(loop, &peer->time_watcher);
        ev_timer_init(&peer->time_watcher, dns_failed_cb, DNS_RETRY_INTERVAL,
                    0.);
        ev_timer_start(loop, &peer->time_watcher);
    } else {
        inet_ntop(host->h_addrtype, host->h_addr_list[0], ip, ADDRESS_MAX_LEN);
        LOG("Domain resolve success %s => %s\n", peer->address, ip);

        if (host->h_addrtype == AF_INET) {
            struct sockaddr_in *addr = (struct sockaddr_in *)&storage;
            socklen_t addr_len = sizeof(struct sockaddr_in);
            addr->sin_family = AF_INET;
            addr->sin_port = htons(peer->port);
            memcpy(&addr->sin_addr, host->h_addr_list[0], host->h_length);

            peer_start(peer, (struct sockaddr *)addr, addr_len);
        } else {
            struct sockaddr_in6 *addr = (struct sockaddr_in6 *)&storage;
            socklen_t addr_len = sizeof(struct sockaddr_in6);
            addr->sin6_family = AF_INET6;
            addr->sin6_port = htons(peer->port);
            memcpy(&addr->sin6_addr, host->h_addr_list[0], host->h_length);

            peer_start(peer, (struct sockaddr *)addr, addr_len);
        }
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
dns_failed_cb(struct ev_loop *loop, struct ev_timer *w, int revents)
{
    peer_info_t *peer = (peer_info_t *)w->data;
    if (revents & EV_TIMER) {
        // resolver switch between ipv4 and ipv6 if prefer_ipv6 is set
        if (g_config.service.prefer_ipv6)
            peer->resolve_ipv6 = !peer->resolve_ipv6;

        liteflow_on_online(&peer->dt, 0);
    }
}

static void
monitor_cb(struct ev_loop *loop, struct ev_timer *w, int revents)
{
    int ret = 0;
    litedt_time_t cur_time = get_curtime();

    if (revents & EV_TIMER) {
        if (cur_time >= last_stat_time + 60 * USEC_PER_SEC) {
            print_statistics();
            last_stat_time = cur_time;
        }

        if (need_reload_conf) {
            need_reload_conf = 0;
            LOG("Starting reload configuration.\n");
            if ((ret = reload_config_file()) == 0) {
                tcp_local_reload(loop, g_config.entrance_rules);
                udp_local_reload(loop, g_config.entrance_rules);
                LOG("Reload configuration success.\n");
            } else {
                LOG("Reload configuration failed: %d\n", ret);
            }
        }
    }
}

static void
liteflow_set_eventtime(litedt_host_t *host, litedt_time_t event_after)
{
    peer_info_t *peer = (peer_info_t*)litedt_ext(host);
    double after = (double)event_after / (double)USEC_PER_SEC;

    if (ev_is_active(&peer->time_watcher)) {
        ev_timer_stop(loop, &peer->time_watcher);
    }

    ev_timer_set(&peer->time_watcher, after > 0 ? after : 0., 0.);
    ev_timer_start(loop, &peer->time_watcher);
}

static void
print_statistics()
{
    litedt_stat_t *stat = NULL;
    queue_node_t *it = queue_first(&peers_tab);

    LOG("|%-7s|%-10s|%-10s|%-10s|%-10s|%-10s|%-10s|%-10s|%-10s|%-10s|%-10s|\n",
        "NodeID", "In Bytes", "Out Bytes", "Sent Pkts", "Retrans", "FEC",
        "Connects", "TimeWaits", "RTT(ms)", "Bandwidth", "State");

    if (queue_empty(&peers_tab)) {
        LOG("| - No Active Peers -\n");
    }

    for (; it != NULL; it = queue_next(&peers_tab, it)) {
        peer_info_t *peer = *(peer_info_t **)queue_value(&peers_tab, it);
        stat = litedt_get_stat(&peer->dt);

        LOG("|%-7u|%-10u|%-10u|%-10u|%-10u|%-10u|%-10u|%-10u|%-10u|"
            "%-10s|%-10s|\n",
            peer->peer_id,
            stat->recv_bytes_stat,
            stat->send_bytes_stat,
            stat->data_packet_post,
            stat->retrans_packet_post,
            stat->fec_recover,
            stat->connection_num,
            stat->timewait_num,
            stat->rtt / MSEC_PER_SEC,
            bw_human(stat->bandwidth),
            litedt_ctrl_mode_name(&peer->dt));

        litedt_clear_stat(&peer->dt);
    }
}

static const char*
bw_human(uint32_t bw)
{
    static char bw_str[11] = {0};
    char digits[11] = {0};
    static const char *suffix[3] = {"bps", "Kbps", "Mbps"};
    int u = 0, len;
    double bits = (double)bw * g_config.transport.mtu * 8;

    while (bits > 9216. && u < 2) {
        bits /= 1024.;
        ++u;
    }

    len = snprintf(digits, sizeof(digits) - 1, "%.2lf", bits);
    if (len > 4 && digits[3] == '.')
        digits[3] = '\0';
    snprintf(bw_str, sizeof(bw_str) - 1, "%.4s %s", digits, suffix[u]);
    return bw_str;
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

    if (g_config.service.dns_server[0]) {
        ret = ares_set_servers_ports_csv(
            g_channel,
            g_config.service.dns_server);
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
    litedt_time_t cur_time = ev_time() * USEC_PER_SEC;

    next_flow = rand();
    loop = ev_default_loop(0);

    queue_init(
        &peers_tab,
        PEER_HASH_SIZE,
        sizeof(uint16_t),
        sizeof(peer_info_t*),
        NULL,
        0);

    queue_init(
        &peers_outbound,
        PEER_HASH_SIZE,
        DOMAIN_PORT_MAX_LEN,
        sizeof(peer_info_t*),
        domain_hash,
        0);

    if (init_resolver() != 0)
        return -1;

    // initialize entrance protocol support
    tcp_init(loop);
    udp_init(loop);

    // binding local port
    while (g_config.entrance_rules[idx].listen_port) {
        entrance_rule_t *entrance = &g_config.entrance_rules[idx++];
        switch (entrance->protocol) {
        case PROTOCOL_TCP:
            ret = tcp_local_init(loop, entrance);
            break;
        case PROTOCOL_UDP:
            ret = udp_local_init(loop, entrance);
            break;
        }
        if (ret != 0)
            break;
    }
    if (ret != 0) {
        LOG("Local port init failed\n");
        return ret;
    }

    for (idx = 0; g_config.service.connect_peers[idx][0]; idx++) {
        LOG("Adding new peer: %s\n", g_config.service.connect_peers[idx]);
        new_peer_outbound(g_config.service.connect_peers[idx]);
    }

    if (g_config.service.max_incoming_peers > 0) {
        if (litedt_init(&litedt_host) != 0) {
            LOG("litedt_host init failed.\n");
            return -1;
        }
        sockfd = litedt_startup(&litedt_host, 0, 0);
        if (sockfd < 0) {
            LOG("litedt_host startup failed: %s\n", strerror(errno));
            return -1;
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
    last_stat_time = get_curtime();
    ev_timer_init(&monitor_watcher, monitor_cb, 1., 1.);
    ev_timer_start(loop, &monitor_watcher);

    struct sigaction sa = {};
    sa.sa_handler = reload_conf_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;

    sigaction(SIGUSR1, &sa, NULL);

    while (1) {
        ev_loop(loop, 0);
    }
}