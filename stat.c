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

#include <string.h>
#include "stat.h"
#include "util.h"
#include "config.h"

#define MIN(a, b) ((a) < (b) ? (a) : (b))
#define MAX(a, b) ((a) > (b) ? (a) : (b))

static int stat_num = 0;
litedt_stat_t stat_now;
litedt_stat_t stat_total;
litedt_stat_t stat_max;
litedt_stat_t stat_min;

void inc_stat(const litedt_stat_t *stat)
{
    unsigned int offset = 0;
    while (offset < sizeof(litedt_stat_t)) {
        uint32_t *elem = (uint32_t *)((char *)stat + offset);
        uint32_t *total = (uint32_t *)((char *)&stat_total + offset);
        uint32_t *min = (uint32_t *)((char *)&stat_min + offset);
        uint32_t *max = (uint32_t *)((char *)&stat_max + offset);
        *total += *elem;
        *min = MIN(*min, *elem);
        *max = MAX(*max, *elem);
        offset += sizeof(uint32_t);
    }
    memcpy(&stat_now, stat, sizeof(litedt_stat_t));
    ++stat_num;
}

void clear_stat()
{
    stat_num = 0;
    memset(&stat_total, 0, sizeof(litedt_stat_t));
    memset(&stat_max, 0, sizeof(litedt_stat_t));
    memset(&stat_min, 0xFF, sizeof(litedt_stat_t));
}

void print_stat()
{
    uint32_t data_post, post_succ, fec_post;
    double loss_rate = 0.0;
    double effective = 1.0;
    if (!stat_num)
        ++stat_num;

    data_post = stat_total.data_packet_post;
    post_succ = stat_total.data_packet_post_succ;
    fec_post  = stat_total.fec_packet_post;
    if (data_post > post_succ) {
        loss_rate = (double)(data_post - post_succ) / (double)data_post;
    }
    if (data_post + fec_post > post_succ) {
        effective = (double)post_succ / (double)(data_post + fec_post);
    }

    LOG("\n------------------------------------------------------------------\n"
        "|Service Statistics\n"
        "------------------------------------------------------------------\n"
        "|%-12s|%-12s|%-12s|%-12s|%-12s|\n"
        "------------------------------------------------------------------\n"
        "|%-12s|%-12u|%-12u|%-12u|%-12u|\n"
        "|%-12s|%-12u|%-12u|%-12u|%-12u|\n"
        "|%-12s|%-12u|%-12u|%-12u|%-12u|\n"
        "|%-12s|%-12u|%-12u|%-12u|%-12u|\n"
        "|%-12s|%-12u|%-12u|%-12u|%-12u|\n"
        "|%-12s|%-12u|%-12u|%-12u|%-12u|\n"
        "|%-12s|%-12u|%-12u|%-12u|%-12u|\n"
        "|%-12s|%-12u|%-12u|%-12u|%-12u|\n"
        "|%-12s|%-12u|%-12u|%-12u|%-12u|\n"
        "|%-12s|%-12u|%-12u|%-12u|%-12u|\n"
        "------------------------------------------------------------------\n"
        "|Network Statistics\n"
        "-----------------------------------------------------\n"
        "|%-12s|%-12s|%-12s|%-12s|\n"
        "-----------------------------------------------------\n"
        "|%8uKbps|%11.1f%%|%12u|%11.1f%%|\n"
        "-----------------------------------------------------\n",
        "Name", "Total", "Avg", "Max", "Min",
        "Flow Out", stat_total.send_bytes_stat, stat_total.send_bytes_stat / stat_num, stat_max.send_bytes_stat, stat_min.send_bytes_stat,
        "Flow In", stat_total.recv_bytes_stat, stat_total.recv_bytes_stat / stat_num, stat_max.recv_bytes_stat, stat_min.recv_bytes_stat,
        "Packet Send", stat_total.data_packet_post, stat_total.data_packet_post / stat_num, stat_max.data_packet_post, stat_min.data_packet_post,
        "Retrans", stat_total.retrans_packet_post, stat_total.retrans_packet_post / stat_num, stat_max.retrans_packet_post, stat_min.retrans_packet_post,
        "Packet Dup", stat_total.repeat_packet_recv, stat_total.repeat_packet_recv / stat_num, stat_max.repeat_packet_recv, stat_min.repeat_packet_recv,
        "FEC Recover", stat_total.fec_recover, stat_total.fec_recover / stat_num, stat_max.fec_recover, stat_min.fec_recover,
        "UDP Lost", stat_total.udp_lost, stat_total.udp_lost / stat_num, stat_max.udp_lost, stat_min.udp_lost,
        "Connections", stat_now.connection_num, stat_total.connection_num / stat_num, stat_max.connection_num, stat_min.connection_num,
        "Time-Wait", stat_now.timewait_num, stat_total.timewait_num / stat_num, stat_max.timewait_num, stat_min.timewait_num,
        "RTT", stat_now.rtt, stat_total.rtt / stat_num, stat_max.rtt, stat_min.rtt,
        "Bandwidth", "Packet Loss", "FEC Group", "Effective",
        g_config.send_bytes_per_sec * 8 / 1024, loss_rate * 100, 
        stat_now.fec_group_size, effective * 100);

        
}
