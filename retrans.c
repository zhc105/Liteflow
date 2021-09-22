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

#include <assert.h>
#include "litedt_internal.h"
#include "retrans.h"
#include "config.h"
#include "util.h"

#define RETRANS_HASH_SIZE 5003

typedef struct _packet_key {
    uint32_t flow;
    uint32_t seq;
} packet_key_t;

static packet_entry_t* find_retrans(retrans_mod_t *rtmod, uint32_t seq);

static int64_t get_retrans_time(retrans_mod_t *rtmod, int64_t cur_time);

static int handle_retrans(retrans_mod_t *rtmod, packet_entry_t *packet,
                        int64_t cur_time);

static void queue_retrans(retrans_mod_t *rtmod, packet_entry_t *packet,
                        int64_t cur_time);

static void release_packet_entry(retrans_mod_t *rtmod, packet_entry_t *packet,
                                rate_sample_t *rs);

static void packet_delivered(retrans_mod_t *rtmod, packet_entry_t *packet,
                            rate_sample_t *rs);

static void packet_abandon(retrans_mod_t *rtmod, packet_entry_t *packet);

static uint32_t packet_hash(const void *key);

int retrans_queue_init(litedt_host_t *host)
{
    return timerlist_init(
        &host->retrans_queue,
        RETRANS_HASH_SIZE,
        sizeof(packet_key_t),
        sizeof(packet_entry_t*),
        packet_hash);
}

void retrans_queue_send(litedt_host_t *host)
{
    int ret = 0;
    static uint32_t maxsize = 0;
    if (timerlist_size(&host->retrans_queue) > maxsize) {
        maxsize = timerlist_size(&host->retrans_queue);
    }

    while (!timerlist_empty(&host->retrans_queue) && !ret) {
        packet_entry_t *packet = *(packet_entry_t **)
            timerlist_top(&host->retrans_queue, NULL, NULL);

        ret = handle_retrans(packet->rtmod, packet, host->cur_time);
        if (!packet->is_ready) {
            timerlist_pop(&host->retrans_queue);
        }
    }
}

uint32_t retrans_packet_length(litedt_host_t *host)
{
    if (timerlist_empty(&host->retrans_queue))
        return 0;

    packet_entry_t *packet = *(packet_entry_t **)
            timerlist_top(&host->retrans_queue, NULL, NULL);
    return packet->length;
}

void retrans_queue_fini(litedt_host_t *host)
{
    timerlist_fini(&host->retrans_queue);
}

int retrans_mod_init(retrans_mod_t *rtmod, litedt_host_t *host,
                    litedt_conn_t *conn)
{
    rtmod->host = host;
    rtmod->conn = conn;
    treemap_init(
        &rtmod->packet_list, sizeof(uint32_t), sizeof(packet_entry_t),
        seq_cmp);
    INIT_LIST_HEAD(&rtmod->waiting_queue);
    return 0;
}

void retrans_mod_fini(retrans_mod_t *rtmod)
{
    tree_node_t *it;
    for (it = treemap_first(&rtmod->packet_list); it != NULL;
        it = treemap_next(it)) {
        packet_entry_t *packet = (packet_entry_t *)
            treemap_value(&rtmod->packet_list, it);
        packet_abandon(rtmod, packet);

        if (packet->is_ready) {
            // packet is in retrans queue, remove it before free
            packet_key_t pk = {.flow = rtmod->conn->flow, .seq = packet->seq};
            timerlist_del(&rtmod->host->retrans_queue, &pk);
        }
    }

    treemap_fini(&rtmod->packet_list);
}

int create_packet_entry(retrans_mod_t *rtmod, uint32_t seq, uint32_t length,
                        uint32_t fec_seq, uint8_t fec_index)
{
    int ret = 0;
    litedt_host_t *host = rtmod->host;
    packet_entry_t packet, *last = NULL;
    tree_node_t *it;
    int64_t cur_time = get_curtime();   // using accurate timestamp
    int64_t retrans_time = get_retrans_time(rtmod, cur_time);
    if (find_retrans(rtmod, seq) != NULL) 
        return RECORD_EXISTS;
    if (!list_empty(&rtmod->waiting_queue)) {
        last = list_entry(
            rtmod->waiting_queue.prev, packet_entry_t, waiting_list);
        if (retrans_time < last->retrans_time)
            retrans_time = last->retrans_time;
    }

    packet.rtmod            = rtmod;
    packet.send_time        = cur_time;
    packet.retrans_time     = retrans_time;
    packet.delivered_time   = host->delivered_time;
    packet.first_tx_time    = host->first_tx_time;
    packet.delivered        = host->delivered;
    packet.seq              = seq;
    packet.length           = length;
    packet.fec_seq          = fec_seq;
    packet.fec_index        = fec_index;
    packet.retrans_round    = 0;
    packet.is_ready         = 0;
    packet.is_app_limited   = host->app_limited ? 1 : 0;

    ++host->inflight;
    host->inflight_bytes += length;

    ret = treemap_insert2(&rtmod->packet_list, &seq, &packet, &it);
    if (ret == 0) {
        last = treemap_value(&rtmod->packet_list, it);
        list_add_tail(&last->waiting_list, &rtmod->waiting_queue);
    }
        
    return ret;
}

void release_packet_range(retrans_mod_t *rtmod, uint32_t seq_start,
                        uint32_t seq_end, rate_sample_t *rs)
{
    tree_node_t *it = treemap_lower_bound(&rtmod->packet_list, &seq_start);
    while (it != NULL) {
        packet_entry_t *packet 
            = (packet_entry_t *)treemap_value(&rtmod->packet_list, it);
        if (LESS_EQUAL(seq_end, packet->seq))
            break;
        it = treemap_next(it);
        release_packet_entry(rtmod, packet, rs);
    }
}

void retrans_checkpoint(retrans_mod_t *rtmod, uint32_t swnd_start,
                        rate_sample_t *rs) 
{
    tree_node_t *it = treemap_first(&rtmod->packet_list);
    while (it != NULL) {
        packet_entry_t *packet 
            = (packet_entry_t *)treemap_value(&rtmod->packet_list, it);
        if (LESS_EQUAL(swnd_start, packet->seq))
            break;
        release_packet_entry(rtmod, packet, rs);
        it = treemap_first(&rtmod->packet_list);
    }
}

int retrans_time_event(retrans_mod_t *rtmod, int64_t cur_time)
{
    int ret = 0;
    packet_entry_t *packet, *n;
    packet_key_t pk = {.flow = rtmod->conn->flow};

    if (rtmod->conn->state >= CONN_CLOSE_WAIT)
        return 0;   // the peer no longer receive any data

    list_for_each_entry_safe(packet, n, &rtmod->waiting_queue, waiting_list) {
        if (packet->retrans_time > cur_time)
            break;
        
        pk.seq = packet->seq;
        ret = timerlist_push(
            &rtmod->host->retrans_queue,
            packet->send_time,
            &pk,
            &packet);
        
        if (ret != 0)
            return ret;

        packet->is_ready = 1;
        list_del(&packet->waiting_list);
    }

    return 0;
}

uint32_t retrans_list_size(retrans_mod_t *rtmod)
{
    return treemap_size(&rtmod->packet_list);
}

int64_t retrans_next_event_time(retrans_mod_t *rtmod, int64_t cur_time)
{
    if (list_empty(&rtmod->waiting_queue))
        return cur_time + IDLE_INTERVAL;

    packet_entry_t *first = 
        list_entry(rtmod->waiting_queue.next, packet_entry_t, waiting_list);

    return first->retrans_time;
}

void generate_bandwidth(retrans_mod_t *rtmod, rate_sample_t *rs,
                        uint32_t newly_delivered)
{
    litedt_host_t *host = rtmod->host;
    int64_t cur_time = host->cur_time;
    uint32_t delivery_rate;
    uint32_t delivered;
    int64_t interval_us, snd_us, ack_us;

    if (host->app_limited && AFTER(host->delivered, host->app_limited))
        host->app_limited = 0;

    if (newly_delivered)
        host->delivered_time = cur_time;
    else
        return;
    
    if (LESS_EQUAL(host->next_rtt_delivered, host->delivered)) {
        host->next_rtt_delivered = host->delivered;
        ++host->rtt_round;
    }

    delivered = host->delivered - rs->prior_delivered;

    snd_us = rs->interval_us;
    ack_us = cur_time - rs->prior_mstamp;
    interval_us = MAX(snd_us, ack_us);

    if (interval_us <= 0)
        return;
    
    delivery_rate = (uint64_t)delivered * USEC_PER_SEC / interval_us;
    if (!rs->is_app_limited || delivery_rate > filter_get(&host->bw)) {
        filter_update_max(&host->bw, host->rtt_round, delivery_rate);
    }

    if (rs->rtt_us) {
        if (!host->srtt) {
            host->srtt = rs->rtt_us;
        } else {
            host->srtt = (host->srtt * SRTT_ALPHA 
                + rs->rtt_us * (SRTT_UNIT - SRTT_ALPHA)) / SRTT_UNIT;
        }
    }
}

static packet_entry_t* find_retrans(retrans_mod_t *rtmod, uint32_t seq)
{
    return (packet_entry_t *)treemap_get(&rtmod->packet_list, &seq);
}

static int64_t get_retrans_time(retrans_mod_t *rtmod, int64_t cur_time)
{
    litedt_host_t *host = rtmod->host;
    uint32_t rtt = host->srtt ? host->srtt : g_config.transport.max_rtt;

    if (rtt > g_config.transport.max_rtt)
        return cur_time 
            + (int)(g_config.transport.max_rtt * g_config.transport.rto_ratio);
    else if (rtt < g_config.transport.min_rtt)
        return cur_time 
            + (int)(g_config.transport.min_rtt * g_config.transport.rto_ratio);
    else
        return cur_time + (int)(rtt * g_config.transport.rto_ratio);
}

static int handle_retrans(retrans_mod_t *rtmod, packet_entry_t *packet,
                        int64_t cur_time)
{
    int ret = 0;
    litedt_host_t *host = rtmod->host;
    litedt_conn_t *conn = rtmod->conn;
    uint32_t flow = conn->flow;
    if (conn->state >= CONN_CLOSE_WAIT ||
        AFTER(conn->swin_start, packet->seq)) {
        // This packet was no longer needed for retrans
        queue_retrans(rtmod, packet, cur_time);
        return 0;
    }

    if (packet->length + LITEDT_MAX_HEADER <= host->pacing_credit) {
        ++host->stat.retrans_packet_post;
        ret = litedt_data_post(
            host,
            flow,
            packet->seq,
            packet->length,
            packet->fec_seq,
            packet->fec_index,
            cur_time,
            0);

        queue_retrans(rtmod, packet, cur_time);
    } else {
        ret = SEND_FLOW_CONTROL;
    }

    if (ret == SEND_FLOW_CONTROL)
        return ret;
    return 0;
}

static void queue_retrans(retrans_mod_t *rtmod, packet_entry_t *packet,
                        int64_t cur_time)
{
    assert(packet->is_ready != 0);
    packet_entry_t *last;
    int64_t retrans_time = get_retrans_time(rtmod, cur_time);
    if (!list_empty(&rtmod->waiting_queue)) {
        last = list_entry(
            rtmod->waiting_queue.prev, packet_entry_t, waiting_list);
        if (retrans_time < last->retrans_time)
            retrans_time = last->retrans_time;
    }
    
    packet->retrans_time = retrans_time;
    if (packet->retrans_round < 65535)
        ++packet->retrans_round;
    if (packet->retrans_round >= 10) {
        DBG("flow: %u, seq: %u, retrans %d times.\n",
            rtmod->conn->flow, packet->seq, packet->retrans_round);
    }

    packet->is_ready = 0;
    list_add_tail(&packet->waiting_list, &rtmod->waiting_queue);
}

static void release_packet_entry(retrans_mod_t *rtmod, packet_entry_t *packet,
                                rate_sample_t *rs)
{
    litedt_host_t *host = rtmod->host;
    ++host->stat.data_packet_post_succ;
    packet_delivered(rtmod, packet, rs);
    if (packet->is_ready) {
        packet_key_t pk = {.flow = rtmod->conn->flow, .seq = packet->seq};
        timerlist_del(&rtmod->host->retrans_queue, &pk);
    } else {
        list_del(&packet->waiting_list);
    }
    treemap_delete(&rtmod->packet_list, &packet->seq);
}

static void packet_delivered(retrans_mod_t *rtmod, packet_entry_t *packet,
                            rate_sample_t *rs)
{
    litedt_host_t *host = rtmod->host;
    int64_t cur_time = get_curtime();   // using accurate timestamp

    --host->inflight;
    host->inflight_bytes -= packet->length;
    host->delivered_bytes += packet->length;
    host->delivered = (host->delivered + 1) ? : 1;

    if (!packet->retrans_round) {
        //printf("rtt = %ld\n", cur_time - packet->send_time);
        if (!rs->rtt_us || cur_time - packet->send_time < rs->rtt_us) {
            rs->rtt_us = (uint32_t)(cur_time - packet->send_time);
        }
    }

    if (!rs->prior_delivered ||
        AFTER(packet->delivered, rs->prior_delivered)) {
        rs->prior_delivered = packet->delivered;
        rs->prior_mstamp = packet->delivered_time;
        rs->is_app_limited = packet->is_app_limited;
        
        /* Record send time of most recently ACKed packet: */
        host->first_tx_time = packet->send_time;
        /* Find the duration of the "send phase" of this window: */
        rs->interval_us = packet->send_time - packet->first_tx_time;
    }
}

// abandon packet without increase delivered counter
static void packet_abandon(retrans_mod_t *rtmod, packet_entry_t *packet)
{
    litedt_host_t *host = rtmod->host;
    --host->inflight;
    host->inflight_bytes -= packet->length;
    --host->app_limited;
    return;
}

static uint32_t packet_hash(const void *key)
{
    packet_key_t *pk = (packet_key_t *)key;
    return (pk->flow >> 16) ^ (pk->seq & 0xFFFF) | 
        (pk->flow << 16) ^ (pk->seq & 0xFFFF0000);
}