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
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "litedt.h"
#include "config.h"
#include "util.h"

FILE *tfile;
int connected = 0, mode = 0, set_send_notify = 1, litedt_sock = -1;
char buf[104857600];
struct sockaddr_storage remote_addr = {};
socklen_t remote_addr_len = 0;

void usage(char *argv0)
{
    printf("A simple file transfer demo based on liteflow protocol\n"
            "Usage: \n"
            "  sender   - %s -s[6] <filename>\n"
            "  receiver - %s -c <sender_ip> <sender_port>\n",
            argv0, argv0);
}

int sys_send(litedt_host_t *host, const void *buf, size_t len)
{
    return sendto(litedt_sock, buf, len, 0, (struct sockaddr *)&remote_addr,
        remote_addr_len);
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
        printf("receive online event\n");
        litedt_connect(host, 123456, 1000);
        connected = 1;
    }
}

static int init_litedt_sock(int ipv6, int port)
{
    struct sockaddr_storage storage;
    socklen_t addr_len;
    int flag = 1, ret, sock;
    int bufsize = 524288;

    if ((sock = socket(ipv6 ? AF_INET6 : AF_INET, SOCK_DGRAM, 0)) < 0)
        return -1;

    ret = setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &flag, sizeof(int));
    if (ret < 0) {
        close(sock);
        return -1;
    }

    if (fcntl(sock, F_SETFL, fcntl(sock, F_GETFL) | O_NONBLOCK) < 0 ||
        fcntl(sock, F_SETFD, FD_CLOEXEC) < 0) {
        close(sock);
        return -1;
    }

    if (setsockopt(sock, SOL_SOCKET, SO_RCVBUF, (const char*)&bufsize,
                    sizeof(int)) < 0) {
        close(sock);
        return -1;
    }

    if (setsockopt(sock, SOL_SOCKET, SO_SNDBUF, (const char*)&bufsize,
                    sizeof(int)) < 0) {
        close(sock);
        return -1;
    }

    if (port > 0) {
        bzero(&storage, sizeof(storage));
        if (ipv6) {
            struct sockaddr_in6 *addr = (struct sockaddr_in6 *)&storage;
            addr->sin6_family = AF_INET6;
            addr->sin6_port = htons(port);
            inet_pton(AF_INET6, "::", &(addr->sin6_addr));
            addr_len = sizeof(struct sockaddr_in6);
        } else {
            struct sockaddr_in *addr = (struct sockaddr_in *)&storage;
            addr->sin_family = AF_INET;
            addr->sin_port = htons(port);
            inet_pton(AF_INET, "0.0.0.0", &(addr->sin_addr));
            addr_len = sizeof(struct sockaddr_in);
        }

        if (bind(sock, (struct sockaddr*)&storage, addr_len) < 0) {
            close(sock);
            return -1;
        }
    }

    litedt_sock = sock;
    return 0;
}

void set_remote_addr_v4(char *addr, uint16_t port)
{
    bzero(&remote_addr, sizeof(remote_addr));
    struct sockaddr_in *saddr = (struct sockaddr_in *)&remote_addr;
    saddr->sin_family = AF_INET;
    saddr->sin_port = htons(port);
    inet_pton(AF_INET, addr, &(saddr->sin_addr));
    remote_addr_len = sizeof(struct sockaddr_in);
}

void set_remote_addr_v6(litedt_host_t *host, char *addr, uint16_t port)
{
    bzero(&remote_addr, sizeof(remote_addr));
    struct sockaddr_in6 *saddr = (struct sockaddr_in6 *)&remote_addr;
    saddr->sin6_family = AF_INET6;
    saddr->sin6_port = htons(port);
    inet_pton(AF_INET6, addr, &(saddr->sin6_addr));
    remote_addr_len = sizeof(struct sockaddr_in6);
}

int main(int argc, char *argv[])
{
    struct timeval tv = {0, 0};
    fd_set fds;
    litedt_host_t host;
    litedt_time_t cur_time, wait_time, print_time = 0;
    char buf[2048];
    int ipv6 = 0;
    global_config_init();
    g_config.service.debug_log = 1;

    if (argc < 2) {
        usage(argv[0]);
        return 1;
    }

    if (argc >= 4 && !strcmp(argv[1], "-c")) {
        init_litedt_sock(ipv6, 19211);
        litedt_init(&host, 2);
        if (strchr(argv[2], ':') == NULL) {
            set_remote_addr_v4(argv[2], atoi(argv[3]));
        } else {
            set_remote_addr_v6(&host, argv[2], atoi(argv[3]));
            ipv6 = 1;
        }

        tfile = fopen("test.out", "wb");
        mode = 0;
    } else if (argc >= 3 && !strncmp(argv[1], "-s", 2)) {
        if (argv[1][2] == '6') {
            ipv6 = 1;
        }

        init_litedt_sock(ipv6, 19210); 
        litedt_init(&host, 1);
        tfile = fopen(argv[2], "rb");
        mode = 1;
    } else {
        usage(argv[0]);
        return 1;
    }

    if (litedt_sock < 0) {
        printf("litedt init error: %s\n", strerror(errno));
        return 2;
    }

    litedt_set_sys_send_cb(&host, sys_send);
    litedt_set_connect_cb(&host, on_connect);
    litedt_set_close_cb(&host, on_close);
    if (mode == 0) {
        litedt_set_receive_cb(&host, on_receive);
        litedt_set_online_cb(&host, on_online);
    } else {
        litedt_set_send_cb(&host, on_send);
    }

    while (1) {
        cur_time = get_curtime();
        FD_ZERO(&fds);
        FD_SET(litedt_sock, &fds);

        int num = select(litedt_sock + 1, &fds, NULL, NULL, &tv);
        if (num > 0) {
            int ret;
            struct sockaddr_storage storage;
            struct sockaddr *addr = (struct sockaddr *)&storage;
            socklen_t addr_len = sizeof(storage);

            while ((ret = recvfrom(litedt_sock, buf, sizeof(buf), 0, addr, &addr_len)) > 0) {
                if (remote_addr_len == 0) {
                    // if it's the first time to receive data, set remote address
                    // will reply to the sender in the future
                    remote_addr_len = addr_len;
                    memcpy(&remote_addr, addr, addr_len);
                }

                litedt_io_event(&host, buf, ret);
            }
        }
            
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
