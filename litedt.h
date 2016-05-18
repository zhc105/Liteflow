#ifndef _LITEDT_H_
#define _LITEDT_H_

#include "litedt_messages.h"
#include "rbuffer.h"
#include "list.h"
#include <arpa/inet.h>

#define SEND_FLOW_CONTROL   -200
#define CLIENT_OFFLINE      -300
#define CONN_HASH_SIZE      233
#define RETRANS_HASH_SIZE   10007
#define MAX_DATA_SIZE       1200
#define ACK_TIME_DELAY      1000
#define CONNECTION_TIMEOUT  600000

typedef struct _litedt_host litedt_host_t;

typedef int 
litedt_connect_fn(litedt_host_t *host, uint64_t flow, uint16_t port);
typedef void 
litedt_close_fn(litedt_host_t *host, uint64_t flow);
typedef void 
litedt_receive_fn(litedt_host_t *host, uint64_t flow, int readable);

enum CONNECT_STATUS {
    CONN_REQUEST = 0,
    CONN_ESTABLISHED,
    CONN_FIN_WAIT,
    CONN_CLOSE_WAIT,
    CONN_CLOSED
};

typedef struct _litedt_stat {
    uint32_t send_bytes_stat;
    uint32_t recv_bytes_stat;
    uint32_t send_bytes_data;
    uint32_t send_bytes_ack;
    uint32_t recv_bytes_data;
    uint32_t recv_bytes_ack;
    uint32_t send_packet_num;
    uint32_t retrans_num;
    uint32_t send_error;
} litedt_stat_t;

struct _litedt_host {
    int sockfd;
    litedt_stat_t stat;
    uint32_t send_bytes;
    uint32_t send_bytes_limit;
    int client_online;
    int notify_recv;
    struct sockaddr_in client_addr;
    uint32_t ping_id;
    uint32_t rtt;
    int64_t clear_send_time;
    int64_t last_ping;
    int64_t last_ping_rsp;
    int conn_num;
    list_head_t conn_hash[CONN_HASH_SIZE];
    list_head_t conn_list;
    list_head_t retrans_hash[RETRANS_HASH_SIZE];
    list_head_t retrans_list;

    litedt_connect_fn *connect_cb;
    litedt_close_fn   *close_cb;
    litedt_receive_fn *receive_cb;
};

typedef struct _litedt_conn {
    list_head_t conn_list;
    list_head_t hash_list;
    int status;
    uint16_t target_port;
    uint64_t flow;
    uint32_t win_start;
    uint32_t win_size;
    int64_t last_responsed;
    int64_t next_ack_time;
    uint32_t send_seq;
    uint32_t send_offset;
    uint32_t *ack_list;
    uint32_t ack_num;
    rbuf_t send_buf;
    rbuf_t recv_buf;
} litedt_conn_t;

typedef struct _litedt_retrans {
    list_head_t retrans_list;
    list_head_t hash_list;
    int turn;
    int64_t retrans_time;
    uint64_t flow;
    uint32_t seq;
    uint32_t offset;
    uint32_t length;
} litedt_retrans_t;

int litedt_init(litedt_host_t *host);

int litedt_connect(litedt_host_t *host, uint64_t flow, uint16_t port);
int litedt_close(litedt_host_t *host, uint64_t flow);
int litedt_send(litedt_host_t *host, uint64_t flow, const char *buf, 
                uint32_t len);
int litedt_recv(litedt_host_t *host, uint64_t flow, char *buf, uint32_t len);
int litedt_writable_bytes(litedt_host_t *host, uint64_t flow);

void litedt_set_connect_cb(litedt_host_t *host, litedt_connect_fn *conn_cb);
void litedt_set_close_cb(litedt_host_t *host, litedt_close_fn *close_cb);
void litedt_set_receive_cb(litedt_host_t *host, litedt_receive_fn *recv_cb);
void litedt_set_notify_recv(litedt_host_t *host, int notify);

void litedt_io_event(litedt_host_t *host);
void litedt_time_event(litedt_host_t *host, int64_t cur_time);
void litedt_print_stat(litedt_host_t *host);

void litedt_fini(litedt_host_t *host);

#endif
