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

#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "rbuffer.h"

typedef struct _frame_record {
    list_head_t lst;
    uint32_t offset;    // frame offset in current block
    uint32_t len;       // frame length
} frame_record_t;

struct _rbuf_block {
    frame_record_t first_rec;       // first record (start from offset 0)
    char data[RBUF_BLOCK_SIZE];     // data buffer
};

// allocate and construct new buffer block structure
static rbuf_block_t* block_create();
// release buffer block
static void block_release(rbuf_block_t *block);
// check if buffer block is full of data
static int is_block_full(rbuf_block_t *block);

inline uint32_t get_block_id(rbuf_t *rbuf, uint32_t pos)
{
    uint32_t block_dist = (pos & ~RBUF_BLOCK_MASK) - 
                          (rbuf->start_pos & ~RBUF_BLOCK_MASK);
    uint32_t id = rbuf->start_block + (block_dist >> RBUF_BLOCK_BIT);
    return id >= rbuf->blocks_count ? id - rbuf->blocks_count : id;
}


int rbuf_init(rbuf_t *rbuf, int blk_cnt)
{
    rbuf->start_pos = rbuf->write_pos = 0;
    rbuf->start_block = rbuf->end_block = 0;
    rbuf->readable = 0;
    rbuf->blocks_count = blk_cnt;
    rbuf->blocks = (rbuf_block_t **)malloc(sizeof(rbuf_block_t *) * blk_cnt);
    if (NULL == rbuf->blocks)
        return -1;
    memset(rbuf->blocks, 0, sizeof(rbuf_block_t *) * blk_cnt);
    return 0;
}

int rbuf_write(rbuf_t *rbuf, uint32_t pos, const char *data, uint32_t data_len)
{
    int ret = 0;
    frame_record_t *record;
    list_head_t *it;
    uint32_t next_block;
    uint32_t max_size = RBUF_BLOCK_SIZE * rbuf->blocks_count
                        - (rbuf->start_pos & RBUF_BLOCK_MASK);
    if (data_len > max_size)
        return RBUF_OUT_OF_RANGE;
    if (pos - rbuf->start_pos > max_size || 
        pos + data_len - rbuf->start_pos > max_size)
        return RBUF_OUT_OF_RANGE;
    
    while (data_len > 0) {
        rbuf_block_t *block;
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

        if (rbuf->end_block == block_id) {
            // recalculate readable bytes
            rbuf->readable -= block->first_rec.len;
        }

        /* find last frame record that start before current position */
        record = (frame_record_t *)block->first_rec.lst.prev; 
        // check last record
        if (offset >= record->offset) { 
            it = block->first_rec.lst.prev;
        } else {
            for (it = &block->first_rec.lst; it->next != &block->first_rec.lst;
                 it = it->next) {
                record = (frame_record_t *)it->next;
                if (offset < record->offset) 
                    break;
            }
        }
        /* insert record node */
        record = (frame_record_t *)it;
        if (offset >= record->offset && offset <= record->offset + record->len) {
            // merge precursor record
            if (offset < record->offset + record->len)
                ret = 1; // data overlapped
            if (offset + copy_size > record->offset + record->len)
                record->len = offset + copy_size - record->offset;
        } else {
            // create new record
            frame_record_t *rn = (frame_record_t *)malloc(sizeof(frame_record_t));
            if (NULL == rn)
                return -1;
            list_add(&rn->lst, it);
            rn->offset = offset;
            rn->len = copy_size;
            record = rn;
        }
        // merge successor record
        while (record->lst.next != &block->first_rec.lst) {
            frame_record_t *succ = (frame_record_t *)record->lst.next;
            if (succ->offset <= record->offset + record->len) {
                if (succ->offset < record->offset + record->len)
                    ret = 1; // data overlapped
                if (succ->offset + succ->len > record->offset + record->len)
                    record->len = succ->offset + succ->len - record->offset;
                list_del(&succ->lst);
                free(succ);
            } else {
                break;
            }
        }

        /* copy data to buffer */
        memcpy(rbuf->blocks[block_id]->data + offset, data, copy_size);
        data += copy_size;
        data_len -= copy_size;
        pos += copy_size;

        if (rbuf->end_block == block_id) {
            // recalculate readable bytes
            rbuf->readable += block->first_rec.len;
            while (is_block_full(rbuf->blocks[rbuf->end_block])) {
                next_block = (rbuf->end_block + 1 < rbuf->blocks_count)
                             ? rbuf->end_block + 1 : 0;
                if (next_block == rbuf->start_block)
                    break;
                if (rbuf->blocks[next_block] != NULL)
                    rbuf->readable += rbuf->blocks[next_block]->first_rec.len;
                rbuf->end_block = next_block;
            }
        }
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
        assert(NULL != rbuf->blocks[block_id]);

        memcpy(data, rbuf->blocks[block_id]->data + offset, copy_size);
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
    int read_len = (data_size > rbuf->readable) ? rbuf->readable: data_size;
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
    return rbuf->readable;
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

void rbuf_release(rbuf_t *rbuf, uint32_t r_size)
{
    uint32_t next_block;
    while (r_size > 0) {
        rbuf_block_t *block = rbuf->blocks[rbuf->start_block];
        assert(NULL != block && r_size <= rbuf->readable);

        if (block->first_rec.len < r_size) {
            assert(is_block_full(block));
            rbuf->readable  -= block->first_rec.len;
            rbuf->start_pos += block->first_rec.len;
            r_size -= block->first_rec.len;
            block->first_rec.offset += block->first_rec.len;
            block->first_rec.len    = 0;
        } else {
            rbuf->readable  -= r_size;
            rbuf->start_pos += r_size;
            block->first_rec.offset += r_size;
            block->first_rec.len    -= r_size;
            r_size = 0;
        }

        if (block->first_rec.len == 0 && is_block_full(block)) {
            // current block was exhausted, release current block
            block_release(rbuf->blocks[rbuf->start_block]);
            rbuf->blocks[rbuf->start_block] = NULL;

            next_block = (rbuf->end_block + 1 < rbuf->blocks_count)
                         ? rbuf->end_block + 1 : 0;
            if (next_block == rbuf->start_block && 
                is_block_full(rbuf->blocks[rbuf->end_block])) {
                rbuf->end_block = next_block;
            }
            rbuf->start_block = (rbuf->start_block + 1 < rbuf->blocks_count) 
                                ? rbuf->start_block + 1 : 0;
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
}

rbuf_block_t* block_create()
{
    rbuf_block_t *blk = (rbuf_block_t *)malloc(sizeof(rbuf_block_t));
    if (NULL != blk) {
        INIT_LIST_HEAD(&blk->first_rec.lst);
        blk->first_rec.offset = 0;
        blk->first_rec.len = 0;
    }
    return blk;
}

void block_release(rbuf_block_t *blk)
{
    // release all frame record in the block (except first block)
    while (!list_empty(&blk->first_rec.lst)) {
        frame_record_t *record = (frame_record_t *)blk->first_rec.lst.next;
        list_del(&record->lst);
        free(record);
    }
    free(blk);
}

int is_block_full(rbuf_block_t *blk)
{
    if (blk && blk->first_rec.offset + blk->first_rec.len == RBUF_BLOCK_SIZE)
        return 1;
    return 0;
}

