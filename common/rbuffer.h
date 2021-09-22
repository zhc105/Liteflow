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

#ifndef _RBUFFER_H_
#define _RBUFFER_H_

#include <stddef.h>
#include <stdint.h>
#include "treemap.h"

#define RBUF_BLOCK_BIT  17
#define RBUF_BLOCK_SIZE (1 << RBUF_BLOCK_BIT)   // 128KB Block Size
#define RBUF_BLOCK_MASK (RBUF_BLOCK_SIZE - 1)

#define RBUF_OUT_OF_RANGE -100

typedef struct _rbuf {
    uint32_t    start_pos;          // window start position
    uint32_t    write_pos;          // front writing position indicator
    uint32_t    start_block;        // first readable block id
    uint32_t    blocks_count;       // maximum blocks number
    treemap_t   range_map;          // readable buffer range map
    char        **blocks;           // data block
} rbuf_t;

// rbuffer constructor & destructor
int rbuf_init(rbuf_t *rbuf, int blocks_count);
void rbuf_fini(rbuf_t *rbuf);

// write data to any position of [win_start, win_start + win_size)
int rbuf_write(rbuf_t *rbuf, uint32_t pos, const char *data, uint32_t len);

// read data from any position that data already written
int rbuf_read(rbuf_t *rbuf, uint32_t pos, char *data, uint32_t len);

// append data to the front of buffer and increase write position indicator 
// by data_size
int rbuf_write_front(rbuf_t *rbuf, const char *data, uint32_t data_size);

// read specified bytes data from the head of buffer
int rbuf_read_front(rbuf_t *rbuf, char *data, uint32_t data_size);

// get buffer window start position and window size
void rbuf_window_info(rbuf_t *rbuf, uint32_t *win_start, uint32_t *win_size);

// get buffer remaining readable/writable bytes number
uint32_t rbuf_readable_bytes(rbuf_t *rbuf);
uint32_t rbuf_writable_bytes(rbuf_t *rbuf);

// get buffer write position indicator
uint32_t rbuf_write_pos(rbuf_t *rbuf);

// get readable range map
treemap_t* rbuf_range_map(rbuf_t *rbuf);

// release specified bytes buffer from the front of buffer
void rbuf_release(rbuf_t *rbuf, uint32_t r_size);

#endif
