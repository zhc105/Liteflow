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

#ifndef _CTRL_H_
#define _CTRL_H_

#include <stdint.h>
#include "litedt_fwd.h"
#include "retrans.h"

typedef struct _ctrl_mod {
    litedt_host_t   *host;
    uint32_t        bbr_mode;
    uint32_t        prior_rtt_round;
    uint32_t        full_bw;
    uint32_t        full_bdp;
    uint32_t        min_rtt_us;
	uint32_t        min_rtt_stamp;
    uint32_t        probe_rtt_done_stamp;
    uint32_t        probe_rtt_cwnd_target;
    uint32_t        probe_rtt_round_done;
    uint32_t        prior_bw;
    uint8_t         full_bw_reached:1, 
		            full_bw_cnt:2,
                    round_start:1,
		            unused_b:5;
} ctrl_mod_t;

void ctrl_mod_init(ctrl_mod_t *ctrl, litedt_host_t *host);

void ctrl_time_event(ctrl_mod_t *ctrl);
void ctrl_io_event(ctrl_mod_t *ctrl, const rate_sample_t *rs);
const char* get_ctrl_mode_name(ctrl_mod_t *ctrl);

#endif
