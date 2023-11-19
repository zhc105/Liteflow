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
#include "ctrl.h"
#include "litedt_internal.h"
#include "util.h"

#define BBR_SCALE           8
#define BBR_UNIT            (1 << BBR_SCALE)

#define AGGREGATION_TIME    20000

enum bbr_mode {
    BBR_STARTUP,
    BBR_DRAIN,
    BBR_PROBE_BW,
    BBR_PROBE_RTT,
};

static const char* bbr_mode_name[] = {
    "STARTUP",
    "DRAIN",
    "PROBE_BW",
    "PROBE_RTT"
};

static const int bbr_pacing_gain[] = {
    BBR_UNIT * 5 / 4,
    BBR_UNIT * 3 / 4,
    BBR_UNIT, BBR_UNIT, BBR_UNIT,
    BBR_UNIT, BBR_UNIT, BBR_UNIT
};

static const int bbr_high_gain  = BBR_UNIT * 2885 / 1000 + 1;
static const int bbr_drain_gain = BBR_UNIT * 1000 / 2885;
static const int bbr_probe_rtt_gain = BBR_UNIT / 2;
static const int bbr_cwnd_gain  = BBR_UNIT * 2;
static const uint32_t bbr_full_bw_thresh = BBR_UNIT * 5 / 4;
static const uint32_t bbr_cwnd_min_target = 4;
static const uint32_t bbr_full_bw_cnt = 3;
static const uint32_t bbr_probe_rtt_mode_us = 200000;
static const uint32_t bbr_min_rtt_win_sec = 10;
static const uint32_t bbr_bdp_min_rtt = 1500;

static uint32_t get_bw(ctrl_mod_t *ctrl);
static uint32_t get_bdp(ctrl_mod_t *ctrl, uint32_t bw);
static uint32_t get_ack_aggregation_cwnd(uint32_t bw);
static uint32_t get_pacing_rate_fec(ctrl_mod_t *ctrl, uint32_t pacing_rate);
static void update_pacing_rate(ctrl_mod_t *ctrl);
static void update_min_rtt(ctrl_mod_t *ctrl, const rate_sample_t *rs);
static void check_full_bw_reached(ctrl_mod_t *ctrl, const rate_sample_t *rs);
static void check_probe_rtt_done(ctrl_mod_t *ctrl);
static void check_drain(ctrl_mod_t *ctrl);
static void pacing_rate_postcheck(ctrl_mod_t *ctrl);

void ctrl_mod_init(ctrl_mod_t *ctrl, litedt_host_t *host)
{
    litedt_time_t cur_time_s = host->cur_time / USEC_PER_SEC;
    ctrl->host = host;
    ctrl->bbr_mode = BBR_STARTUP;
    ctrl->prior_rtt_round = UINT32_MAX;
    ctrl->full_bw = 0;
    ctrl->full_bdp = 0;
    ctrl->min_rtt_us = 0;
    ctrl->min_rtt_stamp = cur_time_s - (litedt_time_t)bbr_min_rtt_win_sec - 1;
    ctrl->probe_rtt_done_stamp = 0;
    ctrl->probe_rtt_cwnd_target = 0;
    ctrl->probe_rtt_round_done = 0;
    ctrl->prior_bw = 0;
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
    pacing_rate_postcheck(ctrl);
    ctrl->prior_rtt_round = host->rtt_round;
}

void ctrl_io_event(ctrl_mod_t *ctrl, const rate_sample_t *rs)
{
    check_full_bw_reached(ctrl, rs);
    update_min_rtt(ctrl, rs);
    ctrl->round_start = 0;
}

const char* get_ctrl_mode_name(ctrl_mod_t *ctrl)
{
    return bbr_mode_name[ctrl->bbr_mode];
}

static uint32_t get_bw(ctrl_mod_t *ctrl)
{
    uint32_t bw = filter_get(&ctrl->host->bw)
        ? : g_config.transport.transmit_rate_init / g_config.transport.mtu;
    return bw;
}

static uint32_t get_bdp(ctrl_mod_t *ctrl, uint32_t bw)
{
    litedt_host_t *host = ctrl->host;
    uint32_t rtt_min = filter_get(&host->rtt_min)
        ? : g_config.transport.max_rtt;
    rtt_min = rtt_min < bbr_bdp_min_rtt ? bbr_bdp_min_rtt : rtt_min;
    return (uint32_t)((uint64_t)bw * (uint64_t)rtt_min / USEC_PER_SEC);
}

static uint32_t get_ack_aggregation_cwnd(uint32_t bw)
{
    return (uint64_t)bw * (uint64_t)AGGREGATION_TIME / USEC_PER_SEC;
}

static uint32_t get_pacing_rate_fec(ctrl_mod_t *ctrl, uint32_t pacing_rate)
{
    litedt_host_t *host = ctrl->host;
    if (!g_config.transport.fec_group_size)
        return 0;
    return pacing_rate / g_config.transport.fec_group_size;
}

static void update_pacing_rate(ctrl_mod_t *ctrl)
{
    litedt_host_t *host = ctrl->host;

    uint32_t bw = MAX(get_bw(ctrl),
        g_config.transport.transmit_rate_min / g_config.transport.mtu);
    uint64_t cwnd = MAX(get_bdp(ctrl, bw), bbr_cwnd_min_target);
    uint64_t bw_bytes = (uint64_t)bw * g_config.transport.mtu;

    switch (ctrl->bbr_mode)
    {
    case BBR_STARTUP:
        cwnd += get_ack_aggregation_cwnd(bw);
        host->pacing_rate = bw_bytes * bbr_high_gain >> BBR_SCALE;
        host->snd_cwnd = cwnd * bbr_high_gain >> BBR_SCALE;
        break;
    case BBR_DRAIN:
        host->pacing_rate = bw_bytes * bbr_drain_gain >> BBR_SCALE;
        host->snd_cwnd = cwnd * bbr_high_gain >> BBR_SCALE;
        break;
    case BBR_PROBE_BW:
        cwnd += get_ack_aggregation_cwnd(bw);
        host->pacing_rate = bw_bytes * bbr_pacing_gain[host->rtt_round & 0x7]
            >> BBR_SCALE;
        host->snd_cwnd = cwnd * bbr_cwnd_gain >> BBR_SCALE;
        break;
    case BBR_PROBE_RTT:
        host->pacing_rate = bw_bytes * BBR_UNIT >> BBR_SCALE;
        host->snd_cwnd = cwnd * bbr_probe_rtt_gain >> BBR_SCALE;
        break;
    default:
        LOG("Fatal: ctrl bad mode: %u\n", ctrl->bbr_mode);
        assert(0);
        break;
    }

    host->pacing_rate += get_pacing_rate_fec(ctrl, host->pacing_rate);
}

static void update_min_rtt(ctrl_mod_t *ctrl, const rate_sample_t *rs)
{
    litedt_host_t *host = ctrl->host;
    litedt_time_t cur_time = host->cur_time;
    litedt_time_t cur_time_s = cur_time / USEC_PER_SEC;
    uint64_t cwnd;
    uint32_t bw;
    int filter_expired;

    if (rs->rtt_us) {
        if (filter_get(&host->rtt_min))
            filter_update_min(&host->rtt_min, cur_time_s, rs->rtt_us);
        else
            filter_reset(&host->rtt_min, cur_time_s, rs->rtt_us);
    }

    filter_expired = AFTER(cur_time_s,
        ctrl->min_rtt_stamp + (litedt_time_t)bbr_min_rtt_win_sec);

    if (rs->rtt_us && (rs->rtt_us < ctrl->min_rtt_us || filter_expired)) {
        ctrl->min_rtt_us = rs->rtt_us;
        ctrl->min_rtt_stamp = cur_time_s;
    }

    if (bbr_probe_rtt_mode_us > 0 && filter_expired
        && ctrl->bbr_mode == BBR_PROBE_BW) {
        bw = filter_get(&host->bw);
        cwnd = MAX(get_bdp(ctrl, bw), bbr_cwnd_min_target);
        ctrl->bbr_mode = BBR_PROBE_RTT;
        ctrl->prior_bw = bw;
        ctrl->probe_rtt_cwnd_target = cwnd * bbr_probe_rtt_gain >> BBR_SCALE;
        ctrl->probe_rtt_done_stamp = 0;
        DBG("enter probe_rtt mode, min_rtt=%u\n", ctrl->min_rtt_us);
    }

    if (ctrl->bbr_mode == BBR_PROBE_RTT) {
        /* Ignore low rate samples during this mode. */
        host->app_limited = (host->delivered + host->inflight) ? : 1;
        /* Maintain min packets in flight for max(200 ms, 1 round). */
        if (!ctrl->probe_rtt_done_stamp &&
            host->inflight <= ctrl->probe_rtt_cwnd_target) {
            ctrl->probe_rtt_done_stamp = cur_time +
                (litedt_time_t)bbr_probe_rtt_mode_us;
            ctrl->probe_rtt_round_done = 0;
            host->next_rtt_delivered = host->delivered;
        } else if (ctrl->probe_rtt_done_stamp) {
            if (ctrl->round_start)
                ctrl->probe_rtt_round_done = 1;
            if (ctrl->probe_rtt_round_done)
                check_probe_rtt_done(ctrl);
        }
    }
}

static void check_full_bw_reached(ctrl_mod_t *ctrl, const rate_sample_t *rs)
{
    litedt_host_t *host = ctrl->host;
    uint32_t bw_thresh;

    if (ctrl->full_bw_reached || !ctrl->round_start || rs->is_app_limited)
        return;

    bw_thresh = (uint64_t)ctrl->full_bw * bbr_full_bw_thresh >> BBR_SCALE;
    if (filter_get(&host->bw) >= bw_thresh) {
        ctrl->full_bw = filter_get(&host->bw);
        ctrl->full_bw_cnt = 0;
        return;
    }
    ++ctrl->full_bw_cnt;
    ctrl->full_bw_reached = ctrl->full_bw_cnt >= bbr_full_bw_cnt;
}

static void check_probe_rtt_done(ctrl_mod_t *ctrl)
{
    litedt_host_t *host = ctrl->host;
    litedt_time_t cur_time = host->cur_time;
    litedt_time_t cur_time_s = cur_time / USEC_PER_SEC;
    uint64_t cwnd;

    if (!(ctrl->probe_rtt_done_stamp &&
          AFTER(cur_time, ctrl->probe_rtt_done_stamp)))
        return;

    ctrl->min_rtt_stamp = cur_time_s;
    cwnd = MAX(get_bdp(ctrl, ctrl->prior_bw), bbr_cwnd_min_target);
    cwnd += get_ack_aggregation_cwnd(ctrl->prior_bw);
    host->pacing_rate = ctrl->prior_bw * g_config.transport.mtu;
    host->pacing_rate += get_pacing_rate_fec(ctrl, host->pacing_rate);
    host->snd_cwnd = cwnd * bbr_cwnd_gain >> BBR_SCALE;
    ctrl->bbr_mode = BBR_PROBE_BW;
    pacing_rate_postcheck(ctrl);
}

static void check_drain(ctrl_mod_t *ctrl)
{
    litedt_host_t *host = ctrl->host;
    uint32_t cwnd;

    if (ctrl->bbr_mode == BBR_STARTUP && ctrl->full_bw_reached) {
        ctrl->bbr_mode = BBR_DRAIN;
        ctrl->full_bdp = get_bdp(ctrl, ctrl->full_bw);
        DBG("enter drain mode, bdp=%u\n", ctrl->full_bdp);
    }

    if (ctrl->bbr_mode == BBR_DRAIN) {
        host->app_limited = (host->delivered + host->inflight) ? : 1;
        if (host->inflight <= ctrl->full_bdp) {
            ctrl->bbr_mode = BBR_PROBE_BW;
            // recover full bw and cwnd
            cwnd = MAX(ctrl->full_bdp, bbr_cwnd_min_target);
            cwnd += get_ack_aggregation_cwnd(ctrl->full_bw);
            host->pacing_rate = ctrl->full_bw * g_config.transport.mtu;
            host->pacing_rate += get_pacing_rate_fec(ctrl, host->pacing_rate);
            host->snd_cwnd = cwnd * bbr_cwnd_gain >> BBR_SCALE;
            DBG("enter probe_bw mode, inflight=%u\n", host->inflight);
        }
    }
}

static void pacing_rate_postcheck(ctrl_mod_t *ctrl)
{
    litedt_host_t *host = ctrl->host;
    host->pacing_rate = MAX(host->pacing_rate,
                            g_config.transport.transmit_rate_min);
    host->pacing_rate = MIN(host->pacing_rate,
                            g_config.transport.transmit_rate_max);
}