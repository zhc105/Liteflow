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
#include "timerlist.h"
#include "treemap.h"

typedef struct _retrans_mod {
    litedt_host_t   *host;
    litedt_conn_t   *conn;
    treemap_t       packet_list;
    list_head_t     waiting_queue;
} retrans_mod_t;

typedef struct _packet_entry {
    list_head_t     waiting_list;
    retrans_mod_t   *rtmod;

    int64_t     send_time;
    int64_t     retrans_time;
    int64_t     delivered_time;
    int64_t     first_tx_time;
    uint32_t    delivered;
    uint32_t    seq;
    uint32_t    length;
    uint32_t    fec_seq;
    uint8_t     fec_index;
    uint8_t     is_ready: 1,
                is_app_limited: 1,
                unused: 6;
    uint16_t    retrans_round;
} packet_entry_t;

typedef struct _rate_sample {
	int64_t     prior_mstamp;
	uint32_t    prior_delivered;
	uint32_t    delivered;
	int64_t     interval_us;
	uint32_t    rtt_us;
	int         is_app_limited;
} rate_sample_t;

int  retrans_queue_init(litedt_host_t *host);

void retrans_queue_send(litedt_host_t *host);

uint32_t retrans_packet_length(litedt_host_t *host);

void retrans_queue_fini(litedt_host_t *host);

int retrans_mod_init(retrans_mod_t *rtmod, litedt_host_t *host,
                    litedt_conn_t *conn);

void retrans_mod_fini(retrans_mod_t *rtmod);

int create_packet_entry(
    retrans_mod_t *rtmod,
    uint32_t seq,
    uint32_t length,
    uint32_t fec_seq,
    uint8_t fec_index);

void release_packet_range(
    retrans_mod_t *rtmod,
    uint32_t seq_start,
    uint32_t seq_end,
    rate_sample_t *rs);

void generate_bandwidth(
    retrans_mod_t *rtmod,
    rate_sample_t *rs,
    uint32_t newly_delivered);

void retrans_checkpoint(
    retrans_mod_t *rtmod,
    uint32_t swnd_start,
    rate_sample_t *rs);

int retrans_time_event(retrans_mod_t *rtmod, int64_t cur_time);

uint32_t retrans_list_size(retrans_mod_t *rtmod);

int64_t retrans_next_event_time(retrans_mod_t *rtmod, int64_t cur_time);

#endif
