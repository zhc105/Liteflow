#include "litedt.h"
#include "config.h"
#include "util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

FILE *tfile;
int connected = 0, mode = 0;
char buf[104857600];

int on_connect(litedt_host_t *host, uint64_t flow, uint16_t port)
{
    connected = 1;
    printf("connection %"PRIu64", port %u established.\n", flow, port);
    return 0;
}

void on_close(litedt_host_t *host, uint64_t flow)
{
    connected = 0;
    printf("connection %"PRIu64" closed.\n", flow);
    fclose(tfile);
    exit(0);
}

void on_receive(litedt_host_t *host, uint64_t flow, int readable)
{
    static char buf[5001];
    if (readable > (int)sizeof(buf))
        readable = sizeof(buf);
    int ret = litedt_recv(host, 123456, buf, readable);
    if (ret > 0) {
        fwrite(buf, ret, 1, tfile);
    }
}

void on_send(litedt_host_t *host, uint64_t flow, int writable)
{
    static int send_size = 0, ret;
    if (!feof(tfile)) {
        size_t s = fread(buf, 1, writable, tfile);
        ret = litedt_send(host, 123456, buf, s);
        if (ret != 0)
            printf("offset %d send failed\n", send_size);
        send_size += s;
    } else if (connected) {
        printf("transfer finish %d bytes.\n", send_size);
        connected = 0;
        litedt_close(host, 123456);
    }
}

int main(int argc, char *argv[])
{
    struct timeval tv = {0, 0}; 
    fd_set fds;
    int sock;
    litedt_host_t host;
    int64_t cur_time, print_time = 0;
    global_config_init("");

    if (argc >= 3) {
        strncpy(g_config.host_addr, argv[1], 128);
        g_config.host_port = atoi(argv[2]);
        tfile = fopen("test.out", "wb");
        mode = 0;
    } else {
        tfile = fopen(argv[1], "rb");
        mode = 1;
    }

    sock = litedt_init(&host);
    if (sock < 0) {
        printf("litedt init error: %s\n", strerror(errno));
    }

    litedt_set_connect_cb(&host, on_connect);
    litedt_set_close_cb(&host, on_close);

    if (mode == 0) {
        litedt_connect(&host, 123456, 1000);
        litedt_set_receive_cb(&host, on_receive);
    } else {
        litedt_set_send_cb(&host, on_send);
        litedt_set_notify_send(&host, 1);
    }

    while (1) {
        cur_time = get_curtime();
        FD_ZERO(&fds);
        FD_SET(sock, &fds);
        tv.tv_sec = 0;
        tv.tv_usec = 1000;
        int num = select(sock + 1, &fds, NULL, NULL, &tv);
        if (num > 0)
            litedt_io_event(&host);
        litedt_time_event(&host, cur_time);

        if (!connected)
            continue;

        if (cur_time - print_time >= 1000) {
            uint32_t send_win, send_win_len, recv_win, recv_win_len;
            uint32_t readable, writable, write_pos;
            litedt_conn_t *conn = (litedt_conn_t *)host.conn_list.next;
            rbuf_window_info(&conn->send_buf, &send_win, &send_win_len);
            rbuf_window_info(&conn->recv_buf, &recv_win, &recv_win_len);
            readable = rbuf_readable_bytes(&conn->recv_buf);
            writable = rbuf_writable_bytes(&conn->send_buf);
            write_pos = rbuf_write_pos(&conn->send_buf);

            printf("swin=%u:%u, rwin=%u:%u, readable=%u, writable=%u, "
                    "write_pos=%u, send_bytes=%u, send_offset=%u.\n", 
                    send_win, send_win_len, 
                    recv_win, recv_win_len, readable, writable, write_pos,
                    host.send_bytes, conn->send_offset);
            litedt_print_stat(&host);

            print_time = cur_time;
        }
    }
    
    litedt_fini(&host);
    return 0;
}
