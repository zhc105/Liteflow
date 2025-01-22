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

#ifndef _LITEDT_INTERNAL_H_
#define _LITEDT_INTERNAL_H_

#include "litedt.h"

enum CONNECT_STATUS {
    CONN_REQUEST = 0,
    CONN_ESTABLISHED,
    CONN_FIN_WAIT,
    CONN_CLOSE_WAIT,
    CONN_CLOSED
};

int socket_send(litedt_host_t *host, const void *buf, size_t len, int force);
void build_litedt_header(litedt_header_t *header, uint8_t cmd, uint32_t flow);
litedt_conn_t* find_connection(litedt_host_t *host, uint32_t flow);
int litedt_ping_req(litedt_host_t *host);
int litedt_ping_rsp(litedt_host_t *host, ping_req_t *req);
int litedt_conn_req(litedt_host_t *host, uint32_t flow, uint16_t tunnel_id);
int litedt_conn_rsp(litedt_host_t *host, uint32_t flow, int32_t status);
int litedt_data_post(litedt_host_t *host, uint32_t flow, uint32_t seq,
                    uint32_t len, uint32_t fec_seq, uint8_t fec_index,
                    int fec_post);
int litedt_data_ack(litedt_host_t *host, uint32_t flow, int ack_list);
int litedt_close_req(litedt_host_t *host, uint32_t flow, uint32_t last_seq);
int litedt_close_rsp(litedt_host_t *host, uint32_t flow);
int litedt_conn_rst(litedt_host_t *host, uint32_t flow);

int litedt_on_ping_req(litedt_host_t *host, ping_req_t *req);
int litedt_on_ping_rsp(litedt_host_t *host, ping_rsp_t *rsp);
int litedt_on_conn_req(litedt_host_t *host, uint32_t flow, conn_req_t *req,
                    int no_rsp);
int litedt_on_conn_rsp(litedt_host_t *host, uint32_t flow, conn_rsp_t *rsp);
int litedt_on_data_recv(litedt_host_t *host, uint32_t flow, data_post_t *data,
                        int fec_recv);
int litedt_on_data_ack(litedt_host_t *host, uint32_t flow, data_ack_t *ack);
int litedt_on_close_req(litedt_host_t *host, uint32_t flow, close_req_t *req);
int litedt_on_close_rsp(litedt_host_t *host, uint32_t flow);
int litedt_on_conn_rst(litedt_host_t *host, uint32_t flow);
int litedt_on_data_fec(litedt_host_t *host, uint32_t flow, data_fec_t *fec);

void litedt_mod_evtime(litedt_host_t *host, litedt_conn_t *conn,
                    litedt_time_t event_time);

#endif
