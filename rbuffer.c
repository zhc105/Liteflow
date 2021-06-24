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

#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "rbuffer.h"
#include "util.h"

// allocate and construct new buffer block structure
static char* block_create();
// release buffer block
static void block_release(char *block);

static inline uint32_t get_block_id(rbuf_t *rbuf, uint32_t pos)
{
    uint32_t block_dist = (pos & ~RBUF_BLOCK_MASK) - 
                          (rbuf->start_pos & ~RBUF_BLOCK_MASK);
    uint32_t id = rbuf->start_block + (block_dist >> RBUF_BLOCK_BIT);
    return id >= rbuf->blocks_count ? id - rbuf->blocks_count : id;
}

int rbuf_init(rbuf_t *rbuf, int blk_cnt)
{
    rbuf->start_pos = rbuf->write_pos = 0;
    rbuf->start_block = 0;
    rbuf->blocks_count = blk_cnt;
    treemap_init(
        &rbuf->range_map, sizeof(uint32_t), sizeof(uint32_t), seq_cmp);
    rbuf->blocks = (char **)malloc(sizeof(char *) * blk_cnt);
    if (NULL == rbuf->blocks)
        return -1;
    memset(rbuf->blocks, 0, sizeof(char *) * blk_cnt);
    return 0;
}

int rbuf_write(rbuf_t *rbuf, uint32_t pos, const char *data, uint32_t data_len)
{
    int ret = 0;
    tree_node_t *it;
    uint32_t end = pos + data_len;
    uint32_t next_block;
    uint32_t max_size = RBUF_BLOCK_SIZE * rbuf->blocks_count
        - (rbuf->start_pos & RBUF_BLOCK_MASK);
    if (data_len > max_size)
        return RBUF_OUT_OF_RANGE;
    if (pos - rbuf->start_pos > max_size || 
        end - rbuf->start_pos > max_size)
        return RBUF_OUT_OF_RANGE;
    
    it = treemap_upper_bound(&rbuf->range_map, &pos);
    it = (it == NULL ? treemap_last(&rbuf->range_map) : treemap_prev(it));
    if (it != NULL) {
        uint32_t rstart = *(uint32_t *)treemap_key(&rbuf->range_map, it);
        uint32_t rend = *(uint32_t *)treemap_value(&rbuf->range_map, it);
        if (LESS_EQUAL(end, rend))
            return 1; // data duplicated
        if (LESS_EQUAL(rstart, pos) && LESS_EQUAL(pos, rend))
            *(uint32_t *)treemap_value(&rbuf->range_map, it) = end;
        else
            ret = treemap_insert2(&rbuf->range_map, &pos, &end, &it);
    } else {
        ret = treemap_insert2(&rbuf->range_map, &pos, &end, &it);
    }
    if (-1 == ret)
        return -1;
    /* merge successor range overlapped */
    uint32_t *pend = (uint32_t *)treemap_value(&rbuf->range_map, it);
    for (tree_node_t *next = treemap_next(it); next != NULL;
        next = treemap_next(it)) {
        uint32_t nstart = *(uint32_t *)treemap_key(&rbuf->range_map, next);
        uint32_t nend = *(uint32_t *)treemap_value(&rbuf->range_map, next);
        if (LESS_EQUAL(nstart, *pend)) {
            if (LESS_EQUAL(*pend, nend))
                *pend = nend;
            treemap_delete(&rbuf->range_map, &nstart);
        } else {
            break;
        }
    }
    /* copy data to block */
    while (data_len > 0) {
        char *block;
        uint32_t copy_size = data_len;
        uint32_t offset = pos & RBUF_BLOCK_MASK;
        uint32_t block_id = get_block_id(rbuf, pos);
        if (copy_size >= RBUF_BLOCK_SIZE - offset)
            copy_size = RBUF_BLOCK_SIZE - offset;
        if (block_id >= rbuf->blocks_count)
            block_id -= rbuf->blocks_count;

        if (NULL == rbuf->blocks[block_id]) {
            block = block_create();
            if (NULL == block)
                return -1;
            rbuf->blocks[block_id] = block;
        } else {
            block = rbuf->blocks[block_id];
        }

        memcpy(rbuf->blocks[block_id] + offset, data, copy_size);
        data += copy_size;
        data_len -= copy_size;
        pos += copy_size;
    }

    return ret;
}

int rbuf_read(rbuf_t *rbuf, uint32_t pos, char *data, uint32_t data_len)
{    
    int data_read = 0;
    while (data_len > 0) {
        uint32_t copy_size = data_len;
        uint32_t offset = pos & RBUF_BLOCK_MASK;
        uint32_t block_id = get_block_id(rbuf, pos);
        if (copy_size >= RBUF_BLOCK_SIZE - offset)
            copy_size = RBUF_BLOCK_SIZE - offset;
        if (block_id >= rbuf->blocks_count)
            block_id -= rbuf->blocks_count;

        memcpy(data, rbuf->blocks[block_id] + offset, copy_size);
        data += copy_size;
        data_len -= copy_size;
        pos += copy_size;
        data_read += copy_size;
    }

    return data_read;
}

int rbuf_write_front(rbuf_t *rbuf, const char *data, uint32_t data_size)
{
    int ret = 0;
    if (rbuf_writable_bytes(rbuf) < data_size)
        return -1;

    ret = rbuf_write(rbuf, rbuf->write_pos, data, data_size);
    if (ret >= 0)
        rbuf->write_pos += data_size;

    return ret;
}

int rbuf_read_front(rbuf_t *rbuf, char *data, uint32_t data_size)
{
    uint32_t readable = rbuf_readable_bytes(rbuf);
    int read_len = (data_size > readable) ? readable : data_size;
    read_len = rbuf_read(rbuf, rbuf->start_pos, data, read_len);
    return read_len;
}

void rbuf_window_info(rbuf_t *rbuf, uint32_t *win_start, uint32_t *win_size)
{
    *win_size = RBUF_BLOCK_SIZE * rbuf->blocks_count
                - (rbuf->start_pos & RBUF_BLOCK_MASK);
    *win_start = rbuf->start_pos;
}

uint32_t rbuf_readable_bytes(rbuf_t *rbuf)
{
    tree_node_t *first = treemap_first(&rbuf->range_map);
    if (NULL == first)
        return 0;
    uint32_t fstart = *(uint32_t *)treemap_key(&rbuf->range_map, first);
    if (rbuf->start_pos != fstart)
        return 0;

    return *(uint32_t *)treemap_value(&rbuf->range_map, first) - fstart;
}

uint32_t rbuf_writable_bytes(rbuf_t *rbuf)
{
    uint32_t win_size = RBUF_BLOCK_SIZE * rbuf->blocks_count
                        - (rbuf->start_pos & RBUF_BLOCK_MASK);
    return win_size - (rbuf->write_pos - rbuf->start_pos);
}

uint32_t rbuf_write_pos(rbuf_t *rbuf)
{
    return rbuf->write_pos;
}

treemap_t* rbuf_range_map(rbuf_t *rbuf)
{
    return &rbuf->range_map;
}

void rbuf_release(rbuf_t *rbuf, uint32_t r_size)
{
    uint32_t readable = rbuf_readable_bytes(rbuf);
    uint32_t next_block;

    assert (r_size <= readable);
    if (r_size == readable) {
        treemap_delete(&rbuf->range_map, &rbuf->start_pos);
    } else { 
        tree_node_t *first = treemap_first(&rbuf->range_map);
        uint32_t new_start = rbuf->start_pos + r_size;
        uint32_t end = *(uint32_t *)treemap_value(&rbuf->range_map, first);
        treemap_delete(&rbuf->range_map, &rbuf->start_pos);
        int ret = treemap_insert(&rbuf->range_map, &new_start, &end);
        assert(ret == 0);
    }

    while (r_size > 0) {
        char *block = rbuf->blocks[rbuf->start_block];
        uint32_t offset = rbuf->start_pos & RBUF_BLOCK_MASK;

        if (RBUF_BLOCK_SIZE - offset <= r_size) {
            block_release(block);
            rbuf->blocks[rbuf->start_block] = NULL;
            rbuf->start_block = (rbuf->start_block + 1 < rbuf->blocks_count) 
                                ? rbuf->start_block + 1 : 0;
            rbuf->start_pos += RBUF_BLOCK_SIZE - offset;
            r_size -= RBUF_BLOCK_SIZE - offset;
        } else {
            rbuf->start_pos += r_size;
            r_size = 0;
        }
    }
}

void rbuf_fini(rbuf_t *rbuf)
{
    unsigned int i;
    for (i = 0; i < rbuf->blocks_count; i++) {
        if (NULL != rbuf->blocks[i]) {
            block_release(rbuf->blocks[i]);
            rbuf->blocks[i] = NULL;
        }
    }
    free(rbuf->blocks);
    treemap_fini(&rbuf->range_map);
}

char* block_create()
{
    char *blk = (char *)malloc(RBUF_BLOCK_SIZE);
    return blk;
}

void block_release(char *blk)
{
    free(blk);
}
