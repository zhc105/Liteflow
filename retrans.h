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

#ifndef _RETRANS_H_
#define _RETRANS_H_

#include "litedt_messages.h"
#include "litedt_fwd.h"
#include "list.h"
#include "rbuffer.h"
#include "treemap.h"

#define RETRANS_HASH_BUCKET_SIZE    10007

typedef struct _lretrans_entry {
    list_head_t waiting_list;
    int64_t     retrans_time;
    uint32_t    seq;
    uint32_t    length;
    uint32_t    fec_seq;
    uint8_t     fec_index;
    uint8_t     is_ready;
    uint16_t    turn;
} retrans_entry_t;

typedef struct _retrans_mod {
    litedt_host_t   *host;
    litedt_conn_t   *conn;
    treemap_t       retrans_list;
    treemap_t       ready_queue;
    list_head_t     waiting_queue;
} retrans_mod_t;

int retrans_mod_init(
    retrans_mod_t *rtmod, litedt_host_t *host, litedt_conn_t *conn);
void retrans_mod_fini(retrans_mod_t *rtmod);

int create_retrans(
    retrans_mod_t *rtmod, uint32_t seq, uint32_t length, 
    uint32_t fec_seq, uint8_t fec_index, int64_t cur_time);
void release_retrans_range(
    retrans_mod_t *rtmod, uint32_t seq_start, uint32_t seq_end);

void retrans_checkpoint(retrans_mod_t *rtmod, uint32_t swnd_start);
int retrans_time_event(
    retrans_mod_t *rtmod, int64_t cur_time);
int  handle_retrans(
    retrans_mod_t *rtmod, retrans_entry_t *rt, int64_t cur_time);

#endif
