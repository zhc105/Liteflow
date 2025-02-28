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

#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "fec.h"
#include "litedt_internal.h"
#include "util.h"

#define FEC_ISSET(idx, map)     ((map)[(idx) >> 5] & (1 << ((idx) & 31)))
#define FEC_SET(idx, map)       ((map)[(idx) >> 5] |= 1 << ((idx) & 31))

int fec_mod_init(fec_mod_t *fecmod, litedt_host_t *host, uint32_t flow)
{
    int ret = 0;
    fecmod->host                = host;
    fecmod->flow                = flow;
    fecmod->current_fec_seq     = 0;
    fecmod->current_fec_end     = 0;
    fecmod->current_fec_index   = 0;
    fecmod->current_fec_members = g_config.transport.fec_group_size;
    fecmod->fec_recv_start      = 0;
    fecmod->fec_recv_end        = g_config.transport.buffer_size;
    fecmod->fec_len              = 0;
    memset(fecmod->fec_buf, 0, sizeof(fecmod->fec_buf));

    ret = queue_init(
        &fecmod->fec_queue,
        FEC_BUCKET_SIZE,
        sizeof(uint32_t),
        sizeof(litedt_fec_t),
        NULL,
        0);

    return ret;
}

void fec_mod_fini(fec_mod_t *fecmod)
{
    while (!queue_empty(&fecmod->fec_queue)) {
        uint32_t fec_key;
        litedt_fec_t *fec = (litedt_fec_t *)queue_front(
            &fecmod->fec_queue, &fec_key);
        fec_delete(fecmod, fec->fec_seq);
    }
    queue_fini(&fecmod->fec_queue);
}

void get_fec_header(fec_mod_t *fecmod, uint32_t *fec_seq, uint8_t *fec_index)
{
    *fec_seq    = fecmod->current_fec_seq;
    *fec_index  = fecmod->current_fec_index;
}

void fec_push_data(fec_mod_t *fecmod, data_post_t *data)
{
    size_t fec_size = sizeof(data_post_t) + data->len;
    size_t cur      = 0;
    uint8_t *ds     = (uint8_t*)data;
    uint8_t *fec    = (uint8_t*)fecmod->fec_buf;

    for (; cur + 8 <= fec_size; cur += 8) {
        *(uint64_t*)(fec + cur) ^= *(uint64_t*)(ds + cur);
    }
    for (; cur + 4 <= fec_size; cur += 4) {
        *(uint32_t*)(fec + cur) ^= *(uint32_t*)(ds + cur);
    }
    for (; cur < fec_size; cur++) {
        *(fec + cur) ^= *(ds + cur);
    }
    fecmod->fec_len = MAX(fecmod->fec_len, fec_size);
    fecmod->current_fec_end = data->seq + data->len;

    if (++fecmod->current_fec_index >= fecmod->current_fec_members) {
        // FEC group is full, post FEC packet and reset group
        fec_post(fecmod);
    }
}

void fec_checkpoint(fec_mod_t *fecmod, uint32_t recv_start)
{
    litedt_fec_t *fec1, *fec2;
    queue_node_t *q_1st, *q_2nd;

    q_1st = queue_first(&fecmod->fec_queue);
    while (q_1st != NULL) {
        q_2nd = queue_next(&fecmod->fec_queue, q_1st);
        if (q_2nd == NULL)
            break;
        fec1 = (litedt_fec_t *)queue_value(&fecmod->fec_queue, q_1st);
        fec2 = (litedt_fec_t *)queue_value(&fecmod->fec_queue, q_2nd);
        if (LESS_EQUAL(fec2->fec_seq, recv_start)) {
            fecmod->fec_recv_start = fec2->fec_seq;
            fec_delete(fecmod, fec1->fec_seq);
            q_1st = q_2nd;
        } else {
            break;
        }
    }
    fecmod->fec_recv_end = recv_start + g_config.transport.buffer_size;
}

int fec_post(fec_mod_t *fecmod)
{
    char buf[LITEDT_MTU_MAX + LITEDT_MAX_HEADER];
    litedt_header_t *header = (litedt_header_t *)buf;
    data_fec_t *fec = (data_fec_t*)(buf + sizeof(litedt_header_t));
    uint32_t plen;

    if (!fecmod->current_fec_index)
        return 0;

    build_litedt_header(header, LITEDT_DATA_FEC, fecmod->flow);

    fec->fec_seq     = fecmod->current_fec_seq;
    fec->fec_members    = fecmod->current_fec_index;
    fec->fec_len        = fecmod->fec_len;
    memcpy(fec->fec_data, fecmod->fec_buf, fecmod->fec_len);

    plen = sizeof(litedt_header_t) + sizeof(data_fec_t) + fec->fec_len;
    socket_send(fecmod->host, buf, plen, 1);
    ++fecmod->host->stat.fec_packet_post;

    // reset FEC group
    fecmod->current_fec_seq     = fecmod->current_fec_end;
    fecmod->current_fec_index   = 0;
    fecmod->current_fec_members = g_config.transport.fec_group_size;
    fecmod->fec_len             = 0;
    memset(fecmod->fec_buf, 0, sizeof(fecmod->fec_buf));

    return 0;
}

int fec_insert(
    fec_mod_t *fecmod, uint32_t fseq, uint8_t fidx, uint8_t fmems,
    const char *buf, size_t buf_len)
{
    litedt_fec_t tmp, *fec;
    queue_node_t *q_it, *q_last;
    data_post_t *dp;
    int ret;
    uint32_t cur    = 0;
    uint32_t rstart = fecmod->fec_recv_start;
    uint32_t rend   = fecmod->fec_recv_end;

    if (fseq - rstart >= rend - rstart)
        return 1;   // FEC packet out of range
    if (!fmems || fmems > FEC_MEMBERS_MAX ||
        (fidx < FEC_MEMBERS_MAX && fidx >= fmems) || !buf_len)
        return 0;
    if (buf_len > LITEDT_MTU_MAX) {
        LOG("Warning, FEC data size exceed. flow: %u, pack_len=%zu.",
            fecmod->flow, buf_len);
        return 0;
    }

    fec = (litedt_fec_t*)queue_get(&fecmod->fec_queue, &fseq);
    if (fec == NULL) {
        // initialize FEC fec
        tmp.fec_seq     = fseq;
        tmp.fec_end     = fseq;
        tmp.fec_members = fmems;
        tmp.fec_finish  = 0;
        tmp.fec_sum     = 0;
        memset(tmp.fec_map, 0, sizeof(tmp.fec_map));
        memset(tmp.fec_buf, 0, sizeof(tmp.fec_buf));
        ret = queue_append(&fecmod->fec_queue, &fseq, &tmp);
        if (ret != 0)
            return ret;
        fec = (litedt_fec_t*)queue_get(&fecmod->fec_queue, &fseq);
        assert(fec != NULL);
        // Arrange fec queue by ascending order
        q_it = q_last = queue_last(&fecmod->fec_queue);
        while ((q_it = queue_prev(&fecmod->fec_queue, q_it)) != NULL) {
            litedt_fec_t *prec;
            prec = (litedt_fec_t *)queue_value(&fecmod->fec_queue, q_it);
            if (!LESS_EQUAL(fseq, prec->fec_seq)) {
                queue_move_to(q_last, q_it);
                break;
            }
        }
        if (q_it == NULL) {
            queue_move_front(&fecmod->fec_queue, &fseq);
        }
    }

    if (fidx > FEC_MEMBERS_MAX) {
        if (fec->fec_sum)
            return 1;
        fec->fec_members = fmems;
        fec->fec_sum = 1;
    } else {
        dp = (data_post_t*)buf;
        if (FEC_ISSET(fidx, fec->fec_map))
            return 1;
        FEC_SET(fidx, fec->fec_map);
        if (LESS_EQUAL(fec->fec_end, dp->seq + dp->len))
            fec->fec_end = dp->seq + dp->len;    // update fec_end
    }

    for (; cur + 8 <= buf_len; cur += 8) {
        *(uint64_t*)(fec->fec_buf + cur) ^= *(uint64_t*)(buf + cur);
    }
    for (; cur + 4 <= buf_len; cur += 4) {
        *(uint32_t*)(fec->fec_buf + cur) ^= *(uint32_t*)(buf + cur);
    }
    for (; cur < buf_len; cur++) {
        *(fec->fec_buf + cur) ^= *(buf + cur);
    }

    if (++fec->fec_finish == fec->fec_members && fec->fec_sum) {
        // lost data frame has been recovered
        dp = (data_post_t*)fec->fec_buf;
        uint8_t ridx = dp->fec_index;
        if (dp->fec_seq == fseq && !FEC_ISSET(ridx, fec->fec_map)) {
            FEC_SET(ridx, fec->fec_map);
            if (LESS_EQUAL(fec->fec_end, dp->seq + dp->len))
                fec->fec_end = dp->seq + dp->len;    // update fec_end
            fecmod->fec_recv_start = fec->fec_end;

            //DBG("recover success seq=%u", dp->seq);
            litedt_on_data_recv(fecmod->host, fecmod->flow, dp, 1);
            ++fecmod->host->stat.fec_recover;
            // Caution: pointer fec might be invalid now
        } else {
            LOG("Warning, FEC data recover failed flow: %u.", fecmod->flow);
        }
    }

    return 0;
}

int fec_insert_data(fec_mod_t *fecmod, data_post_t *data)
{
    uint32_t fec_seq    = data->fec_seq;
    uint8_t fec_index   = data->fec_index;
    uint8_t fec_members = FEC_MEMBERS_MAX;
    char *buf           = (char*)data;
    size_t buf_len      = sizeof(data_post_t) + data->len;

    return fec_insert(
        fecmod, fec_seq, fec_index, fec_members, buf, buf_len);
}

int fec_insert_sum(fec_mod_t *fecmod, data_fec_t *fec)
{
    uint32_t fec_seq    = fec->fec_seq;
    uint8_t  fec_index  = FEC_MEMBERS_MAX + 1;
    uint8_t fec_members = fec->fec_members;
    char *buf           = fec->fec_data;
    size_t buf_len      = fec->fec_len;

    return fec_insert(
        fecmod, fec_seq, fec_index, fec_members, buf, buf_len);
}

void fec_delete(fec_mod_t *fecmod, uint32_t fec_seq)
{
    queue_del(&fecmod->fec_queue, &fec_seq);
}
