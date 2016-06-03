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

#ifndef _CONFIG_H_
#define _CONFIG_H_
#include <stdint.h>

#define MAX_PORT_NUM 30
#define ADDRESS_MAX_LEN 50
#define DOMAIN_MAX_LEN  128

typedef struct _allow_access {
    uint16_t map_id;
    char target_addr[ADDRESS_MAX_LEN];
    uint16_t target_port;
} allow_access_t;

typedef struct _listen_port {
    uint16_t local_port;
    uint16_t map_id;
} listen_port_t;

typedef struct _global_config {
    uint32_t debug_log;
    char tcp_bind_addr[ADDRESS_MAX_LEN];
    char udp_local_addr[ADDRESS_MAX_LEN];
    uint32_t udp_local_port;
    char udp_remote_addr[DOMAIN_MAX_LEN];
    uint32_t udp_remote_port;
    uint32_t buffer_size;
    uint32_t send_bytes_per_sec;
    uint32_t max_rtt;
    uint32_t min_rtt;
    float timeout_rtt_ratio;
    uint32_t ack_size;
    allow_access_t allow_list[MAX_PORT_NUM + 1];
    listen_port_t listen_list[MAX_PORT_NUM + 1];
} global_config_t;

void global_config_init();
void load_config_file(const char *filename);

#ifndef _CONFIG_C_
extern global_config_t g_config;
#endif

#endif
