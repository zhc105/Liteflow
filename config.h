#ifndef _CONFIG_H_
#define _CONFIG_H_
#include <stdint.h>

typedef struct _global_config {
    char host_addr[128];
    uint32_t host_port;
    uint32_t buffer_size;
    uint32_t send_bytes_per_sec;
    uint32_t max_rtt;
    uint32_t min_rtt;
    uint32_t ack_size;
} global_config_t;

extern global_config_t g_config;

int global_config_init(const char *filename);

#endif
