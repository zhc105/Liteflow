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

static retrans_entry_t* find_retrans(retrans_mod_t *rtmod, uint32_t seq);
static int64_t get_retrans_time(retrans_mod_t *rtmod, int64_t cur_time);
static void queue_retrans(
    retrans_mod_t *rtmod, retrans_entry_t *retrans, int64_t cur_time);
static void release_retrans_internal(
    retrans_mod_t *rtmod, retrans_entry_t *retrans);
static void retrans_fini(retrans_mod_t *rtmod, retrans_entry_t *retrans);

int retrans_mod_init(
    retrans_mod_t *rtmod, litedt_host_t *host, litedt_conn_t *conn)
{
    rtmod->host = host;
    rtmod->conn = conn;
    treemap_init(
        &rtmod->retrans_list, sizeof(uint32_t), sizeof(retrans_entry_t),
        seq_cmp);
    treemap_init(
        &rtmod->ready_queue, sizeof(uint32_t), sizeof(retrans_entry_t *),
        seq_cmp);
    INIT_LIST_HEAD(&rtmod->waiting_queue);
    return 0;
}

void retrans_mod_fini(retrans_mod_t *rtmod)
{
    tree_node_t *it;
    for (it = treemap_first(&rtmod->retrans_list); it != NULL; 
        it = treemap_next(it)) {
        retrans_entry_t *retrans 
            = (retrans_entry_t *)treemap_value(&rtmod->retrans_list, it);
        retrans_fini(rtmod, retrans);
    }
    treemap_fini(&rtmod->retrans_list);
    treemap_fini(&rtmod->ready_queue);
}

int create_retrans(
    retrans_mod_t *rtmod, uint32_t seq, uint32_t length, 
    uint32_t fec_seq, uint8_t fec_index, int64_t cur_time)
{
    int ret = 0;
    retrans_entry_t retrans, *last = NULL;
    tree_node_t *it;
    int64_t retrans_time = get_retrans_time(rtmod, cur_time);
    if (find_retrans(rtmod, seq) != NULL) 
        return RECORD_EXISTS;
    if (!list_empty(&rtmod->waiting_queue)) {
        last = list_entry(
            rtmod->waiting_queue.prev, retrans_entry_t, waiting_list);
        if (retrans_time < last->retrans_time)
            retrans_time = last->retrans_time;
    }
        
    retrans.retrans_time    = retrans_time;
    retrans.seq             = seq;
    retrans.length          = length;
    retrans.fec_seq         = fec_seq;
    retrans.fec_index       = fec_index;
    retrans.turn            = 0;
    retrans.is_ready        = 0;

    ret = treemap_insert2(&rtmod->retrans_list, &seq, &retrans, &it);
    if (ret == 0) {
        last = treemap_value(&rtmod->retrans_list, it);
        list_add_tail(&last->waiting_list, &rtmod->waiting_queue);
    }
        
    return ret;
}

void release_retrans_range(
    retrans_mod_t *rtmod, uint32_t seq_start, uint32_t seq_end)
{
    tree_node_t *it = treemap_lower_bound(&rtmod->retrans_list, &seq_start);
    while (it != NULL) {
        retrans_entry_t *retrans 
            = (retrans_entry_t *)treemap_value(&rtmod->retrans_list, it);
        if (!LESS_EQUAL(retrans->seq, seq_end))
            break;
        it = treemap_next(it);
        release_retrans_internal(rtmod, retrans);
    }
}

void retrans_checkpoint(retrans_mod_t *rtmod, uint32_t swnd_start) 
{
    tree_node_t *it = treemap_first(&rtmod->retrans_list);
    while (it != NULL) {
        retrans_entry_t *retrans 
            = (retrans_entry_t *)treemap_value(&rtmod->retrans_list, it);
        if (!LESS_EQUAL(swnd_start, retrans->seq))
            release_retrans_internal(rtmod, retrans);
        else
            break;
        it = treemap_first(&rtmod->retrans_list);
    }
}

int retrans_time_event(retrans_mod_t *rtmod, int64_t cur_time)
{
    int ret = 0;
    list_head_t *it, *next;
    tree_node_t *tit;
    retrans_entry_t *retrans;
    for (it = rtmod->waiting_queue.next; it != &rtmod->waiting_queue; ) {
        retrans = (retrans_entry_t *)list_entry(
            it, retrans_entry_t, waiting_list);
        next = it->next;
        if (retrans->retrans_time > cur_time)
            break;
        retrans->is_ready = 1;
        treemap_insert(&rtmod->ready_queue, &retrans->seq, &retrans);
        list_del(it);
        it = next;
    }

    for (tit = treemap_first(&rtmod->ready_queue); !ret && tit != NULL; ) {
        retrans_entry_t *retrans = *(retrans_entry_t **)treemap_value(
            &rtmod->ready_queue, tit);
        tit = treemap_next(tit);
        ret = handle_retrans(rtmod, retrans, cur_time);
    }

    return ret;
}

int handle_retrans(retrans_mod_t *rtmod, retrans_entry_t *rt, int64_t cur_time)
{
    int ret = 0;
    litedt_conn_t *conn = rtmod->conn;
    uint32_t flow = conn->flow;
    if (conn->status >= CONN_CLOSE_WAIT || 
        !LESS_EQUAL(conn->swin_start, rt->seq)) {
        DBG("remove invalid retrans record, flow=%u, seq=%u\n", flow,
            rt->seq);
        release_retrans_internal(rtmod, rt);
        return 0;
    }
    //DBG("retrans: seq=%u, length=%u, cur_time=%"PRId64"\n", 
    //        rt->seq, rt->length, cur_time);
    if (rtmod->host->send_bytes + rt->length / 2 + 20 <= 
        rtmod->host->send_bytes_limit) {
        ++rtmod->host->stat.retrans_packet_post;
        ret = litedt_data_post(rtmod->host, flow, rt->seq, rt->length, 
                               rt->fec_seq, rt->fec_index, cur_time, 0);
        queue_retrans(rtmod, rt, cur_time);
    }

    if (ret == SEND_FLOW_CONTROL)
        return ret;
    return 0;
}

static retrans_entry_t* find_retrans(retrans_mod_t *rtmod, uint32_t seq)
{
    return (retrans_entry_t *)treemap_get(&rtmod->retrans_list, &seq);
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
    retrans_mod_t *rtmod, retrans_entry_t *retrans, int64_t cur_time)
{
    assert(retrans->is_ready != 0);
    retrans_entry_t *last;
    int64_t retrans_time = get_retrans_time(rtmod, cur_time);
    if (!list_empty(&rtmod->waiting_queue)) {
        last = list_entry(
            rtmod->waiting_queue.prev, retrans_entry_t, waiting_list);
        if (retrans_time < last->retrans_time)
            retrans_time = last->retrans_time;
    }
    
    retrans->retrans_time = retrans_time;
    if (retrans->turn < 65535)
        ++retrans->turn;
    if (retrans->turn >= 10) {
        DBG("flow: %u, seq: %u, retrans %d times.\n", 
            rtmod->conn->flow, retrans->seq, retrans->turn);
    }

    retrans->is_ready = 0;
    treemap_delete(&rtmod->ready_queue, &retrans->seq);
    list_add_tail(&retrans->waiting_list, &rtmod->waiting_queue);
}

static void release_retrans_internal(
    retrans_mod_t *rtmod, retrans_entry_t *retrans)
{
    retrans_fini(rtmod, retrans);
    if (retrans->is_ready)
        treemap_delete(&rtmod->ready_queue, &retrans->seq);
    else
        list_del(&retrans->waiting_list);
    treemap_delete(&rtmod->retrans_list, &retrans->seq);
}

static void retrans_fini(retrans_mod_t *rtmod, retrans_entry_t *retrans)
{
    ++rtmod->host->stat.data_packet_post_succ;
    ++rtmod->host->ctrl.packet_post_succ;
    rtmod->host->ctrl.bytes_post_succ += retrans->length;
}