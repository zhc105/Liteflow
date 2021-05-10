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
#include "retrans.h"
#include "litedt.h"
#include "config.h"
#include "util.h"

static packet_entry_t* find_retrans(retrans_mod_t *rtmod, uint32_t seq);
static int64_t get_retrans_time(retrans_mod_t *rtmod, int64_t cur_time);
static void queue_retrans(
    retrans_mod_t *rtmod, packet_entry_t *packet, int64_t cur_time);
static void release_packet_entry(
    retrans_mod_t *rtmod, packet_entry_t *packet);
int handle_retrans(
    retrans_mod_t *rtmod, packet_entry_t *packet, int64_t cur_time);
static void packet_delivered(
    retrans_mod_t *rtmod, packet_entry_t *packet, int ignore);

int retrans_mod_init(
    retrans_mod_t *rtmod, litedt_host_t *host, litedt_conn_t *conn)
{
    rtmod->host = host;
    rtmod->conn = conn;
    treemap_init(
        &rtmod->packet_list, sizeof(uint32_t), sizeof(packet_entry_t),
        seq_cmp);
    treemap_init(
        &rtmod->ready_queue, sizeof(uint32_t), sizeof(packet_entry_t *),
        seq_cmp);
    INIT_LIST_HEAD(&rtmod->waiting_queue);
    return 0;
}

void retrans_mod_fini(retrans_mod_t *rtmod)
{
    tree_node_t *it;
    for (it = treemap_first(&rtmod->packet_list); it != NULL; 
        it = treemap_next(it)) {
        packet_entry_t *packet 
            = (packet_entry_t *)treemap_value(&rtmod->packet_list, it);
        packet_delivered(rtmod, packet, 1);
    }
    treemap_fini(&rtmod->packet_list);
    treemap_fini(&rtmod->ready_queue);
}

int create_packet_entry(
    retrans_mod_t *rtmod, uint32_t seq, uint32_t length, 
    uint32_t fec_seq, uint8_t fec_index, int64_t cur_time)
{
    int ret = 0;
    packet_entry_t packet, *last = NULL;
    tree_node_t *it;
    int64_t retrans_time = get_retrans_time(rtmod, cur_time);
    if (find_retrans(rtmod, seq) != NULL) 
        return RECORD_EXISTS;
    if (!list_empty(&rtmod->waiting_queue)) {
        last = list_entry(
            rtmod->waiting_queue.prev, packet_entry_t, waiting_list);
        if (retrans_time < last->retrans_time)
            retrans_time = last->retrans_time;
    }

    packet.send_time        = cur_time;
    packet.retrans_time     = retrans_time;
    packet.delivered_time   = rtmod->host->delivered_time;
    packet.first_tx_time    = rtmod->host->first_tx_time;
    packet.delivered        = rtmod->host->delivered_bytes;
    packet.seq              = seq;
    packet.length           = length;
    packet.fec_seq          = fec_seq;
    packet.fec_index        = fec_index;
    packet.retrans_count    = 0;
    packet.is_ready         = 0;

    ret = treemap_insert2(&rtmod->packet_list, &seq, &packet, &it);
    if (ret == 0) {
        last = treemap_value(&rtmod->packet_list, it);
        list_add_tail(&last->waiting_list, &rtmod->waiting_queue);
    }
        
    return ret;
}

void release_packet_range(
    retrans_mod_t *rtmod, uint32_t seq_start, uint32_t seq_end)
{
    tree_node_t *it = treemap_lower_bound(&rtmod->packet_list, &seq_start);
    while (it != NULL) {
        packet_entry_t *packet 
            = (packet_entry_t *)treemap_value(&rtmod->packet_list, it);
        if (LESS_EQUAL(seq_end, packet->seq))
            break;
        it = treemap_next(it);
        release_packet_entry(rtmod, packet);
    }
}

void retrans_checkpoint(retrans_mod_t *rtmod, uint32_t swnd_start) 
{
    tree_node_t *it = treemap_first(&rtmod->packet_list);
    while (it != NULL) {
        packet_entry_t *packet 
            = (packet_entry_t *)treemap_value(&rtmod->packet_list, it);
        if (LESS_EQUAL(swnd_start, packet->seq))
            break;
        release_packet_entry(rtmod, packet);
        it = treemap_first(&rtmod->packet_list);
    }
}

int retrans_time_event(retrans_mod_t *rtmod, int64_t cur_time)
{
    int ret = 0;
    list_head_t *it, *next;
    tree_node_t *tit;
    packet_entry_t *packet;
    for (it = rtmod->waiting_queue.next; it != &rtmod->waiting_queue; ) {
        packet = (packet_entry_t *)list_entry(
            it, packet_entry_t, waiting_list);
        next = it->next;
        if (packet->retrans_time > cur_time)
            break;
        packet->is_ready = 1;
        treemap_insert(&rtmod->ready_queue, &packet->seq, &packet);
        list_del(it);
        it = next;
    }

    for (tit = treemap_first(&rtmod->ready_queue); !ret && tit != NULL; ) {
        packet_entry_t *packet = *(packet_entry_t **)treemap_value(
            &rtmod->ready_queue, tit);
        tit = treemap_next(tit);
        ret = handle_retrans(rtmod, packet, cur_time);
    }

    return ret;
}

int handle_retrans(
    retrans_mod_t *rtmod, packet_entry_t *packet, int64_t cur_time)
{
    int ret = 0;
    litedt_conn_t *conn = rtmod->conn;
    uint32_t flow = conn->flow;
    if (conn->status >= CONN_CLOSE_WAIT || 
        !LESS_EQUAL(conn->swin_start, packet->seq)) {
        DBG("remove invalid retrans record, flow=%u, seq=%u\n", flow,
            packet->seq);
        release_packet_entry(rtmod, packet);
        return 0;
    }
    //DBG("retrans: seq=%u, length=%u, cur_time=%"PRId64"\n", 
    //        rt->seq, rt->length, cur_time);
    if (rtmod->host->send_bytes + packet->length / 2 + 20
        <= rtmod->host->send_bytes_limit) {
        ++rtmod->host->stat.retrans_packet_post;
        ret = litedt_data_post(
            rtmod->host, flow, packet->seq, packet->length, 
            packet->fec_seq, packet->fec_index, cur_time, 0);
        queue_retrans(rtmod, packet, cur_time);
    }

    if (ret == SEND_FLOW_CONTROL)
        return ret;
    return 0;
}

static packet_entry_t* find_retrans(retrans_mod_t *rtmod, uint32_t seq)
{
    return (packet_entry_t *)treemap_get(&rtmod->packet_list, &seq);
}

static int64_t get_retrans_time(retrans_mod_t *rtmod, int64_t cur_time)
{
    if (rtmod->host->rtt > g_config.max_rtt)
        return cur_time + (int)(g_config.max_rtt * g_config.timeout_rtt_ratio);
    else if (rtmod->host->rtt < g_config.min_rtt)
        return cur_time + (int)(g_config.min_rtt * g_config.timeout_rtt_ratio);
    else
        return cur_time + (int)(rtmod->host->rtt * g_config.timeout_rtt_ratio);
}

static void queue_retrans(
    retrans_mod_t *rtmod, packet_entry_t *packet, int64_t cur_time)
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
    if (packet->retrans_count < 65535)
        ++packet->retrans_count;
    if (packet->retrans_count >= 10) {
        DBG("flow: %u, seq: %u, retrans %d times.\n", 
            rtmod->conn->flow, packet->seq, packet->retrans_count);
    }

    packet->is_ready = 0;
    treemap_delete(&rtmod->ready_queue, &packet->seq);
    list_add_tail(&packet->waiting_list, &rtmod->waiting_queue);
}

static void release_packet_entry(
    retrans_mod_t *rtmod, packet_entry_t *packet)
{
    ++rtmod->host->stat.data_packet_post_succ;
    ++rtmod->host->ctrl.packet_post_succ;
    rtmod->host->ctrl.bytes_post_succ += packet->length;
    packet_delivered(rtmod, packet, 0);
    if (packet->is_ready)
        treemap_delete(&rtmod->ready_queue, &packet->seq);
    else
        list_del(&packet->waiting_list);
    treemap_delete(&rtmod->packet_list, &packet->seq);
}

static void packet_delivered(
    retrans_mod_t *rtmod, packet_entry_t *packet, int ignore)
{
    litedt_host_t *host = rtmod->host;
    int64_t cur_time = host->cur_time;
    int64_t gap;
    uint32_t delivery_rate;

    if (ignore) {
        // drop packet without increase delivered counter
    } else {
        host->delivered_bytes += packet->length;
        ++host->delivered_pkts;
        host->delivered_time = cur_time;
        gap = cur_time - MIN(packet->delivered_time, packet->first_tx_time);
        if (gap == 0)
            gap = 1;
        delivery_rate = (uint64_t)(host->delivered_bytes - packet->delivered) 
            * USEC_PER_SEC / gap;
        //printf("%u %ld\n", host->delivered_bytes - packet->delivered, gap);
        filter_update_max(&host->bw, host->rtt_round, delivery_rate);
    }
}