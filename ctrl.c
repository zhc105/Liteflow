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

#define BBR_SCALE 8
#define BBR_UNIT (1 << BBR_SCALE)

enum bbr_mode {
	BBR_STARTUP,
	BBR_DRAIN,
	BBR_PROBE_BW,
	BBR_PROBE_RTT,
};

static const int bbr_pacing_gain[] = {
	BBR_UNIT * 5 / 4,
	BBR_UNIT * 3 / 4,
	BBR_UNIT, BBR_UNIT, BBR_UNIT,
	BBR_UNIT, BBR_UNIT, BBR_UNIT
};

static const int bbr_high_gain  = BBR_UNIT * 2885 / 1000 + 1;
static const int bbr_drain_gain = BBR_UNIT * 1000 / 2885;
static const int bbr_cwnd_gain  = BBR_UNIT * 2;
static const uint32_t bbr_full_bw_thresh = BBR_UNIT * 5 / 4;
static const uint32_t bbr_cwnd_min_target = 4;
static const uint32_t bbr_full_bw_cnt = 3;

uint32_t get_bw(ctrl_mod_t *ctrl);
uint32_t get_bdp(ctrl_mod_t *ctrl);
void update_pacing_rate(ctrl_mod_t *ctrl);
void check_full_bw_reached(ctrl_mod_t *ctrl, rate_sample_t *rs);
void check_drain(ctrl_mod_t *ctrl);

void ctrl_mod_init(ctrl_mod_t *ctrl, litedt_host_t *host)
{
    ctrl->host = host;
    ctrl->bbr_mode = BBR_PROBE_BW;
    ctrl->prior_rtt_round = UINT32_MAX;
    ctrl->full_bw = 0;
    ctrl->full_bdp = 0;
    ctrl->full_bw_reached = 0;
    ctrl->full_bw_cnt = 0;
    ctrl->round_start = 0;
}

void ctrl_time_event(ctrl_mod_t *ctrl)
{
    litedt_host_t *host = ctrl->host;
    if (host->rtt_round == ctrl->prior_rtt_round)
        return;

    ctrl->round_start = 1;
    check_drain(ctrl);
    update_pacing_rate(ctrl);

    ctrl->prior_rtt_round = host->rtt_round;
}

void ctrl_io_event(ctrl_mod_t *ctrl, rate_sample_t *rs)
{
    check_full_bw_reached(ctrl, rs);
    ctrl->round_start = 0;
}

uint32_t get_bw(ctrl_mod_t *ctrl)
{
    uint32_t bw = filter_get(&ctrl->host->bw) 
        ? : g_config.send_bytes_per_sec / LITEDT_MTU;
    return bw;
}

uint32_t get_bdp(ctrl_mod_t *ctrl)
{
    litedt_host_t *host = ctrl->host;
    uint32_t bw = get_bw(ctrl);
    uint32_t rtt_min = filter_get(&host->rtt_min) ? : g_config.max_rtt;
    return (uint32_t)((uint64_t)bw * (uint64_t)rtt_min / USEC_PER_SEC);
}

void update_pacing_rate(ctrl_mod_t *ctrl)
{
    litedt_host_t *host = ctrl->host;
    
    uint64_t cwnd = MAX(get_bdp(ctrl), bbr_cwnd_min_target);
    uint64_t bw_bytes = (uint64_t)get_bw(ctrl) * LITEDT_MTU;
    bw_bytes = 512 * 1024;

    switch (ctrl->bbr_mode)
    {
    case BBR_STARTUP:
        host->pacing_rate = bw_bytes * bbr_high_gain >> BBR_SCALE;
        host->snd_cwnd = cwnd * bbr_high_gain >> BBR_SCALE;
        break;
    case BBR_DRAIN:
        host->pacing_rate = bw_bytes * bbr_drain_gain >> BBR_SCALE;
        host->snd_cwnd = cwnd * bbr_high_gain >> BBR_SCALE;
        break;
    case BBR_PROBE_BW:
        host->pacing_rate = bw_bytes * (uint64_t)bbr_pacing_gain[host->rtt_round & 0x7] >> BBR_SCALE;
        host->snd_cwnd = cwnd * bbr_cwnd_gain >> BBR_SCALE;
        break;
    case BBR_PROBE_RTT:
        host->pacing_rate = bw_bytes * bbr_drain_gain >> BBR_SCALE;
        host->snd_cwnd = cwnd * bbr_cwnd_gain >> BBR_SCALE;
        break;
    default:
        LOG("Warning: ctrl bad mode: %u\n", ctrl->bbr_mode);
        break;
    }
    //printf("pacing rate = %u\n", host->pacing_rate);
}

void check_full_bw_reached(ctrl_mod_t *ctrl, rate_sample_t *rs)
{
    litedt_host_t *host = ctrl->host;
    uint32_t bw_thresh;

    if (ctrl->full_bw_reached || !ctrl->round_start || rs->is_app_limited)
		return;

    printf("test: %u %u\n", ctrl->full_bw_cnt, ctrl->full_bw);

    bw_thresh = (uint64_t)ctrl->full_bw * bbr_full_bw_thresh >> BBR_SCALE;
	if (filter_get(&host->bw) >= bw_thresh) {
		ctrl->full_bw = filter_get(&host->bw);
		ctrl->full_bw_cnt = 0;
		return;
	}
	++ctrl->full_bw_cnt;
	ctrl->full_bw_reached = ctrl->full_bw_cnt >= bbr_full_bw_cnt;
}

void check_drain(ctrl_mod_t *ctrl)
{
    litedt_host_t *host = ctrl->host;

    if (ctrl->bbr_mode == BBR_STARTUP && ctrl->full_bw_reached) {
	    ctrl->bbr_mode = BBR_DRAIN;
        ctrl->full_bdp = get_bdp(ctrl);
		DBG("enter drain mode, bdp=%u\n", ctrl->full_bdp);
	}

    if (ctrl->bbr_mode == BBR_DRAIN && host->inflight <= ctrl->full_bdp) {
        ctrl->bbr_mode = BBR_PROBE_BW;
        DBG("enter probe_bw mode, inflight=%u\n", host->inflight);
    }
}