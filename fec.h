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

#ifndef _FEC_H_
#define _FEC_H_

#include "litedt_messages.h"
#include "litedt_fwd.h"
#include "hashqueue.h"
#include "rbuffer.h"

#define FEC_BUCKET_SIZE     1003
#define FEC_MEMBERS_MAX     127

typedef struct _litedt_fec {
    uint32_t    fec_seq;
    uint32_t    fec_end;
    uint8_t     fec_members;
    uint8_t     fec_finish;
    uint8_t     fec_sum;
    uint32_t    fec_map[4];
    uint8_t     fec_buf[LITEDT_MTU];
} litedt_fec_t;

typedef struct _fec_mod {
    litedt_host_t   *host;
    uint32_t        flow;
    uint32_t        current_fec_seq;
    uint32_t        current_fec_end;
    uint8_t         current_fec_index;
    uint8_t         current_fec_members;
    uint32_t        fec_recv_start;
    uint32_t        fec_recv_end;
    hash_queue_t    fec_queue;
    uint16_t        fec_len;
    uint8_t         fec_buf[LITEDT_MTU];
} fec_mod_t;

int  fec_mod_init(fec_mod_t *fecmod, litedt_host_t *host, uint32_t flow);
void fec_mod_fini(fec_mod_t *fecmod);

void get_fec_header(fec_mod_t *fecmod, uint32_t *fec_seq, uint8_t *fec_index);
void fec_push_data(fec_mod_t *fecmod, data_post_t *data);
void fec_checkpoint(fec_mod_t *fecmod, uint32_t recv_start);

int  fec_post(fec_mod_t *fecmod);

int  fec_insert(fec_mod_t *fecmod, uint32_t fec_seq, uint8_t fec_index, 
                uint8_t fec_members, const char *buf, size_t buf_len);
int  fec_insert_data(fec_mod_t *fecmod, data_post_t *data);
int  fec_insert_sum(fec_mod_t *fecmod, data_fec_t *data);
void fec_delete(fec_mod_t *fecmod, uint32_t fec_seq);

#endif
