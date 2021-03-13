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

#ifndef _LITEFLOW_H_
#define _LITEFLOW_H_

#include <inttypes.h>
#include <stdint.h>
#include <ev.h>
#include "litedt.h"
#include "config.h"

enum LITEFLOW_ERRCODE {
    LITEFLOW_RECORD_NOT_FOUND       = -1100,
    LITEFLOW_RECORD_EXISTS          = -1101,
    LITEFLOW_CONNECT_FAIL           = -1102,
    LITEFLOW_MEM_ALLOC_ERROR        = -1103,
    LITEFLOW_PARAMETER_ERROR        = -1104,
    LITEFLOW_ACCESS_DENIED          = -1104,
};

enum LITEFLOW_MODE {
    PASSIVE_MODE    = 0,
    ACTIVE_MODE     = 1
};

typedef struct _flow_info flow_info_t;

typedef void 
remote_close_fn(litedt_host_t *host, flow_info_t *flow);
typedef void 
remote_recv_fn(litedt_host_t *host, flow_info_t *flow, int readable);
typedef void 
remote_send_fn(litedt_host_t *host, flow_info_t *flow, int writable);

struct _flow_info {
    uint32_t flow;
    void *ext;

    remote_close_fn *remote_close_cb;
    remote_recv_fn *remote_recv_cb;
    remote_send_fn *remote_send_cb;
};

int  init_liteflow();
void start_liteflow();

uint32_t liteflow_flowid();
flow_info_t* find_flow(uint32_t flow);
int create_flow(uint32_t flow);
void release_flow(uint32_t flow);

#endif
