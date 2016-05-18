#include <stdint.h>
#include <string.h>

typedef struct _global_config {
    char host_addr[128];
    uint32_t host_port;
    uint32_t buffer_size;
    uint32_t send_bytes_per_sec;
    uint32_t max_rtt;
    uint32_t min_rtt;
    uint32_t ack_size;
} global_config_t;

global_config_t g_config;

int global_config_init(const char *filename)
{
    memset(g_config.host_addr, 0, sizeof(g_config.host_addr));
    g_config.host_port = 19210;
    g_config.buffer_size = 10 * 1024 * 1024;
    g_config.send_bytes_per_sec = 6 * 1024 * 1024;
    g_config.max_rtt = 1000;
    g_config.min_rtt = 100;
    g_config.ack_size = 5;
    return 0;
}
