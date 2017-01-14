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

#include "retrans.h"
#include "litedt.h"
#include "config.h"
#include "util.h"

int64_t  get_retrans_time(retrans_mod_t *rtmod, int64_t cur_time);
uint32_t retrans_hash(void *key);

int retrans_mod_init(retrans_mod_t *rtmod, litedt_host_t *host)
{
    int ret = 0;
    rtmod->host = host;
    ret = queue_init(&rtmod->retrans_queue, RETRANS_HASH_SIZE, 
                     sizeof(retrans_key_t), sizeof(litedt_retrans_t), 
                     retrans_hash);
    return ret;
}

void retrans_mod_fini(retrans_mod_t *rtmod)
{
    while (!queue_empty(&rtmod->retrans_queue)) {
        retrans_key_t rkey;
        litedt_retrans_t *retrans 
            = (litedt_retrans_t *)queue_front(&rtmod->retrans_queue, &rkey);
        release_retrans(rtmod, retrans->flow, retrans->offset);
    }
}

litedt_retrans_t* find_retrans(retrans_mod_t *rtmod, uint32_t flow, 
                                uint32_t offset)
{
    litedt_retrans_t *rt;
    retrans_key_t rk;

    rk.flow = flow;
    rk.offset = offset;
    rt = (litedt_retrans_t *)queue_get(&rtmod->retrans_queue, &rk);

    return rt;
}

int create_retrans(retrans_mod_t *rtmod, uint32_t flow, uint32_t offset, 
                   uint32_t length, uint32_t fec_offset, uint8_t fec_index,
                   int64_t cur_time)
{
    litedt_retrans_t retrans, *last;
    retrans_key_t rk;
    int64_t retrans_time = get_retrans_time(rtmod, cur_time);
    if (find_retrans(rtmod, flow, offset) != NULL) 
        return RECORD_EXISTS;

    last = (litedt_retrans_t *)queue_back(&rtmod->retrans_queue, &rk);
    if (last && retrans_time < last->retrans_time)
        retrans_time = last->retrans_time;

    retrans.turn            = 0;
    retrans.retrans_time    = retrans_time;
    retrans.flow            = flow;
    retrans.offset          = offset;
    retrans.length          = length;
    retrans.fec_offset      = fec_offset;
    retrans.fec_index       = fec_index;

    rk.flow = flow;
    rk.offset = offset;
    return queue_append(&rtmod->retrans_queue, &rk, &retrans);
}

void update_retrans(retrans_mod_t *rtmod, litedt_retrans_t *retrans, 
                    int64_t cur_time)
{
    litedt_retrans_t *last;
    retrans_key_t rk;
    int64_t retrans_time = get_retrans_time(rtmod, cur_time);
    last = (litedt_retrans_t *)queue_back(&rtmod->retrans_queue, &rk);
    if (last && retrans_time < last->retrans_time)
        retrans_time = last->retrans_time;

    ++retrans->turn;
    retrans->retrans_time = retrans_time;

    if (retrans->turn >= 10) {
        DBG("flow: %u, offset: %u, retrans %d times.\n", retrans->flow, 
            retrans->offset, retrans->turn);
    }
    
    rk.flow = retrans->flow;
    rk.offset = retrans->offset;
    queue_move_back(&rtmod->retrans_queue, &rk);
}

void release_retrans(retrans_mod_t *rtmod, uint32_t flow, uint32_t offset)
{
    retrans_key_t rk;
    rk.flow = flow;
    rk.offset = offset;
    queue_del(&rtmod->retrans_queue, &rk);
}

void retrans_time_event(retrans_mod_t *rtmod, int64_t cur_time)
{
    int ret = 0;
    hash_node_t *q_it;
    for (q_it = queue_first(&rtmod->retrans_queue); !ret && q_it != NULL;) { 
        litedt_retrans_t *retrans 
            = (litedt_retrans_t *)queue_value(&rtmod->retrans_queue, q_it);
        q_it = queue_next(&rtmod->retrans_queue, q_it);

        if (retrans->retrans_time > cur_time) 
            break;
        ret = handle_retrans(rtmod, retrans, cur_time);
    }
}

int handle_retrans(retrans_mod_t *rtmod, litedt_retrans_t *rt, int64_t cur_time)
{
    int ret = 0;
    uint32_t flow = rt->flow;
    litedt_conn_t *conn;
    if ((conn = find_connection(rtmod->host, flow)) == NULL
        || conn->status >= CONN_CLOSE_WAIT) {
        // invalid retrans record
        DBG("remove invalid retrans record, flow=%u, offset=%u\n", flow,
            rt->offset);
        release_retrans(rtmod, flow, rt->offset);
        return 0;
    }
    if (!LESS_EQUAL(conn->swin_start, rt->offset)) {
        // retrans record has expired
        release_retrans(rtmod, flow, rt->offset);
        return 0;
    }
    //DBG("retrans: offset=%u, length=%u, cur_time=%"PRId64"\n", 
    //        rt->offset, rt->length, cur_time);
    if (rtmod->host->send_bytes + rt->length / 2 + 20 <= 
        rtmod->host->send_bytes_limit) {
        ++rtmod->host->stat.retrans_packet_post;
        ret = litedt_data_post(rtmod->host, flow, rt->offset, rt->length, 
                               rt->fec_offset, rt->fec_index, cur_time, 0);
        update_retrans(rtmod, rt, cur_time);
    }

    if (ret == SEND_FLOW_CONTROL)
        return ret;
    return 0;
}


int64_t get_retrans_time(retrans_mod_t *rtmod, int64_t cur_time)
{
    if (rtmod->host->rtt > g_config.max_rtt)
        return cur_time + (int)(g_config.max_rtt * g_config.timeout_rtt_ratio);
    else if (rtmod->host->rtt < g_config.min_rtt)
        return cur_time + (int)(g_config.min_rtt * g_config.timeout_rtt_ratio);
    else
        return cur_time + (int)(rtmod->host->rtt * g_config.timeout_rtt_ratio);
}

uint32_t retrans_hash(void *key)
{
    retrans_key_t *retrans = (retrans_key_t *)key;
    return (retrans->flow << 4) + retrans->offset;
}

