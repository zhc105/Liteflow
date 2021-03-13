/* * Copyright (c) 2021, Moonflow <me@zhc105.net> * All rights reserved.
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

#include "ctrl.h"
#include "litedt.h"
#include "util.h"

#define FEC_GROUP_MAX   30
#define FEC_GROUP_MIN   3
#define CTRL_THRESHOLD  1000

void ctrl_mod_init(ctrl_mod_t *ctrlmod, litedt_host_t *host)
{
    ctrlmod->host = host;
    ctrl_clear_stat(ctrlmod);
}

void ctrl_time_event(ctrl_mod_t *ctrlmod)
{
    double succ_rate = 1.0;

    if (ctrlmod->packet_post < CTRL_THRESHOLD) 
        return;

    if (ctrlmod->packet_post > ctrlmod->packet_post_succ) {
        succ_rate = (double)ctrlmod->packet_post_succ;
        succ_rate /= (double)ctrlmod->packet_post;
    }

    // Automatically adjust FEC group size
    if (g_config.fec_group_size) {
        // FEC group size is fixed, nothing to do
    } else if (succ_rate > 0.98) {
        if (ctrlmod->host->fec_group_size_ctrl < FEC_GROUP_MAX) {
            ++ctrlmod->host->fec_group_size_ctrl;
            DBG("FEC group size adjust to %u\n", 
                ctrlmod->host->fec_group_size_ctrl);
        }
    } else if (succ_rate < 0.95) {
        if (ctrlmod->host->fec_group_size_ctrl > FEC_GROUP_MIN) {
            --ctrlmod->host->fec_group_size_ctrl;
            DBG("FEC group size adjust to %u\n", 
                ctrlmod->host->fec_group_size_ctrl);
        }
    }
    ctrl_clear_stat(ctrlmod);
}

void ctrl_clear_stat(ctrl_mod_t *ctrlmod)
{
    ctrlmod->packet_post        = 0;
    ctrlmod->packet_post_succ   = 0;
    ctrlmod->bytes_post         = 0;
    ctrlmod->bytes_post_succ    = 0;
}
