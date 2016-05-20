#define _CONFIG_C_
#include <stdint.h>
#include <string.h>
#include "config.h"

global_config_t g_config;

int global_config_init(const char *filename)
{
    memset(g_config.host_addr, 0, sizeof(g_config.host_addr));
    g_config.host_port = 19210;
    g_config.buffer_size = 10 * 1024 * 1024;
    g_config.send_bytes_per_sec = 6 * 1024 * 1024;
    g_config.max_rtt = 1000;
    g_config.min_rtt = 150;
    g_config.ack_size = 100;
    return 0;
}
