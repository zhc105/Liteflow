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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include "litedt.h"
#include "config.h"
#include "util.h"

FILE *tfile;
int connected = 0, mode = 0, set_send_notify = 1, sock = -1;
char buf[104857600];

void usage(char *argv0)
{
    printf("A simple file transfer demo based on liteflow protocol\n"
            "Usage: \n"
            "  sender   - %s -s[6] <filename>\n"
            "  receiver - %s -c <sender_ip> <sender_port>\n",
            argv0, argv0);
}

int on_connect(litedt_host_t *host, uint32_t flow, uint16_t tunnel_id)
{
    connected = 1;
    printf("connection %u, tunnel_id %u established.\n", flow, tunnel_id);
    return 0;
}

void on_close(litedt_host_t *host, uint32_t flow)
{
    connected = 0;
    printf("connection %u closed.\n", flow);
    fclose(tfile);
    exit(0);
}

void on_receive(litedt_host_t *host, uint32_t flow, int readable)
{
    static char buf[5001];
    if (readable > (int)sizeof(buf))
        readable = sizeof(buf);
    int ret = litedt_recv(host, 123456, buf, readable);
    if (ret > 0) {
        fwrite(buf, ret, 1, tfile);
    }
}

void on_send(litedt_host_t *host, uint32_t flow, int writable)
{
    static int send_size = 0, ret;
    if (!feof(tfile)) {
        size_t s = fread(buf, 1, writable, tfile);
        ret = litedt_send(host, 123456, buf, s);
        if (ret != 0)
            printf("seq %d send failed\n", send_size);
        send_size += s;
    } else if (connected) {
        printf("transfer finish %d bytes.\n", send_size);
        connected = 0;
        litedt_close(host, 123456);
    }
}

void on_online(litedt_host_t *host, int online)
{
    if (online) {
        litedt_connect(host, 123456, 1000);
        connected = 1;
    }
}

void on_accept(litedt_host_t *host, uint16_t node_id,
    const struct sockaddr *addr, socklen_t addr_len)
{
    char ip[ADDRESS_MAX_LEN];
    uint16_t port;

    get_ip_port(addr, ip, ADDRESS_MAX_LEN, &port);
    printf("Accepted incoming node: %u from [%s]:%u\n", node_id, ip, port);

    litedt_shutdown(host);
    litedt_set_remote_addr(host, addr, addr_len);
    litedt_set_accept_cb(host, NULL);
    litedt_set_connect_cb(host, on_connect);
    litedt_set_close_cb(host, on_close);
    litedt_set_send_cb(host, on_send);
    sock = litedt_startup(host, 1, node_id);
}

int main(int argc, char *argv[])
{
    struct timeval tv = {0, 0};
    fd_set fds;
    litedt_host_t host;
    litedt_time_t cur_time, wait_time, print_time = 0;
    global_config_init();
    g_config.service.debug_log = 1;

    if (argc < 2) {
        usage(argv[0]);
        return 1;
    }

    litedt_init(&host);

    if (argc >= 4 && !strcmp(argv[1], "-c")) {
        if (strchr(argv[2], ':') == NULL) {
            litedt_set_remote_addr_v4(&host, argv[2], atoi(argv[3]));
        } else {
            litedt_set_remote_addr_v6(&host, argv[2], atoi(argv[3]));
        }

        sock = litedt_startup(&host, 1, 0);
        tfile = fopen("test.out", "wb");
        mode = 0;
    } else if (argc >= 3 && !strncmp(argv[1], "-s", 2)) {
        if (argv[1][2] == '6')
            strncpy(g_config.transport.listen_addr, "::", ADDRESS_MAX_LEN);
        g_config.transport.listen_port = 19210;
        sock = litedt_startup(&host, 0, 0);
        tfile = fopen(argv[2], "rb");
        mode = 1;
    } else {
        usage(argv[0]);
        return 1;
    }

    if (sock < 0) {
        printf("litedt init error: %s\n", strerror(errno));
        return 2;
    }

    if (mode == 0) {
        litedt_set_connect_cb(&host, on_connect);
        litedt_set_close_cb(&host, on_close);
        litedt_set_receive_cb(&host, on_receive);
        litedt_set_online_cb(&host, on_online);
    } else {
        litedt_set_accept_cb(&host, on_accept);
    }

    while (1) {
        cur_time = get_curtime();
        FD_ZERO(&fds);
        FD_SET(sock, &fds);

        int num = select(sock + 1, &fds, NULL, NULL, &tv);
        if (num > 0)
            litedt_io_event(&host);
        wait_time = litedt_time_event(&host);

        if (wait_time >= 0) {
            tv.tv_sec = wait_time / USEC_PER_SEC;
            tv.tv_usec = wait_time % USEC_PER_SEC;
        } else {
            tv.tv_sec = 1;
            tv.tv_usec = 0;
        }

        if (!connected)
            continue;
        if (mode == 1 && set_send_notify) {
            litedt_set_notify_send(&host, 123456, 1);
            set_send_notify = 0;
        }

        if (cur_time - print_time >= USEC_PER_SEC) {
            uint32_t send_win, send_win_len, recv_win, recv_win_len;
            uint32_t readable, writable, write_pos, rtt_min, bw;
            time_t now = time(NULL);
            char rwin_buf[64], swin_buf[64], timestr[21];
            litedt_conn_t *conn = (litedt_conn_t *)
                timerlist_top(&host.conn_queue, NULL, NULL);
            rbuf_window_info(&conn->send_buf, &send_win, &send_win_len);
            rbuf_window_info(&conn->recv_buf, &recv_win, &recv_win_len);
            readable = rbuf_readable_bytes(&conn->recv_buf);
            writable = rbuf_writable_bytes(&conn->send_buf);
            write_pos = rbuf_write_pos(&conn->send_buf);
            rtt_min = filter_get(&host.rtt_min);
            bw = filter_get(&host.bw);
            snprintf(rwin_buf, 63, "%u:%u", recv_win, recv_win_len);
            snprintf(swin_buf, 63, "%u:%u", send_win, send_win_len);
            strftime(timestr, 21, "%Y-%m-%d %H:%M:%S", localtime(&now));

            litedt_stat_t *stat = litedt_get_stat(&host);
            printf(
                "------------------------------%s------------------------------\n"
                "%-11s %-9u|%-11s %-9u|%-11s %-9u|%-11s %-31s|%-11s %-31s|\n"
                "%-11s %-9u|%-11s %-9u|%-11s %-9u|%-11s %-9u|%-11s %-9u|"
                "%-11s %-9u|%-11s %-9u|\n"
                "%-11s %-9u|%-11s %-9u|%-11s %-9u|%-11s %-9u|%-11s %-9u|"
                "%-11s %-9u|%-11s %-9u|\n"
                "%-11s %-9u|%-11s %-9u|%-11s %-9s|\n", timestr,
                "SRtt", host.srtt, "RttMin", rtt_min, "PingRtt", host.ping_rtt,
                "SndWin", swin_buf, "RcvWin", rwin_buf,
                "Readable", readable, "Writeable", writable,
                "WritePos", write_pos, "RcvBytes", stat->recv_bytes_stat,
                "SndBytes", stat->send_bytes_stat,
                "SndPkts", stat->data_packet_post,
                "RetransPkts", stat->retrans_packet_post,
                "SndErr", host.stat.send_error, "SndCwnd", stat->cwnd,
                "RcvDupPkts", stat->dup_packet_recv,
                "SndSeq", conn->send_seq, "FecRecover", stat->fec_recover,
                "EstimateBw", bw, "Inflight", stat->inflight,
                "AppLimited", host.app_limited,
                "RqSize", timerlist_size(&host.retrans_queue),
                "State", get_ctrl_mode_name(&host.ctrl));
            litedt_clear_stat(&host);

            print_time = cur_time;
        }
    }

    litedt_fini(&host);
    return 0;
}
