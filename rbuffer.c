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

struct _rbuf_blk {
    list_head_t record_list;
    char data[RBUF_BLOCK_SIZE];
};

typedef struct _rbuf_record {
    list_head_t lst;
    uint32_t pos;
    uint32_t len;
} rbuf_record_t;

rbuf_blk_t* rblk_create();
void rblk_release(rbuf_blk_t *blk);

int rbuf_init(rbuf_t *rbuf, int blknum)
{
    rbuf->start_pos = 0;
    rbuf->write_pos = 0;
    rbuf->block_offset = 0;
    rbuf->buf_used = 0;
    rbuf->max_block_num = blknum;
    rbuf->block_num = 0;
    rbuf->blk_tab = (rbuf_blk_t **)malloc(sizeof(rbuf_blk_t *) * blknum);
    if (NULL == rbuf->blk_tab)
        return -1;
    memset(rbuf->blk_tab, 0, sizeof(rbuf_blk_t *) * blknum);
    return 0;
}

int rbuf_write(rbuf_t *rbuf, uint32_t pos, const char *data, uint32_t data_len)
{
    rbuf_record_t *record;
    list_head_t *r_list;
    uint32_t max_size = RBUF_BLOCK_SIZE * rbuf->max_block_num 
        - (rbuf->start_pos % RBUF_BLOCK_SIZE);
    if (data_len > max_size)
        return RBUF_OUT_OF_RANGE;
    if (pos - rbuf->start_pos > max_size 
        || pos + data_len - rbuf->start_pos > max_size)
        return RBUF_OUT_OF_RANGE;
    
    while (data_len > 0) {
        rbuf_blk_t *blk;
        uint32_t csize = data_len;
        uint32_t blk_off = pos % RBUF_BLOCK_SIZE;
        uint32_t fsize = RBUF_BLOCK_SIZE - blk_off;
        uint32_t tab_id = (pos / RBUF_BLOCK_SIZE) % rbuf->max_block_num;
        if (csize > fsize)
            csize = fsize;

        if (NULL == rbuf->blk_tab[tab_id]) {
            blk = rblk_create();
            if (NULL == blk)
                return -1;
            rbuf->blk_tab[tab_id] = blk;
        } else {
            blk = rbuf->blk_tab[tab_id];
        }

        /* insert record node */
        for (   r_list = &blk->record_list; 
                r_list->next != &blk->record_list;
                r_list = r_list->next) {
            record = (rbuf_record_t *)r_list->next;
            if (pos < record->pos) 
                break;
        }
        record = (rbuf_record_t *)r_list;
        if (r_list != &blk->record_list && pos >= record->pos 
            && pos <= record->pos + record->len) {
            // merge precursor record
            if (pos + csize > record->pos + record->len)
                record->len = pos + csize - record->pos;
        } else {
            // create new record
            rbuf_record_t *rn = (rbuf_record_t *)malloc(sizeof(rbuf_record_t));
            list_add(&rn->lst, r_list);
            rn->pos = pos;
            rn->len = csize;
            record = rn;
        }
        // merge successor record
        while (record->lst.next != &blk->record_list) {
            rbuf_record_t *succ = (rbuf_record_t *)record->lst.next;
            if (succ->pos >= record->pos && 
                succ->pos <= record->pos + record->len) {
                if (succ->pos + succ->len > record->pos + record->len)
                    record->len = succ->pos + succ->len - record->pos;
                list_del(&succ->lst);
                free(succ);
            } else {
                break;
            }
        }

        /* copy data */
        memcpy(rbuf->blk_tab[tab_id]->data + blk_off, data, csize);
        data += csize;
        data_len -= csize;
        pos += csize;
    }

    return 0;
}

int rbuf_read(rbuf_t *rbuf, uint32_t pos, char *data, uint32_t data_len)
{    
    int data_read = 0;
    while (data_len > 0) {
        uint32_t csize = data_len;
        uint32_t blk_off = pos % RBUF_BLOCK_SIZE;
        uint32_t fsize = RBUF_BLOCK_SIZE - blk_off;
        uint32_t tab_id = (pos / RBUF_BLOCK_SIZE) % rbuf->max_block_num;
        if (csize > fsize)
            csize = fsize;
        assert(NULL != rbuf->blk_tab[tab_id]);

        memcpy(data, rbuf->blk_tab[tab_id]->data + blk_off, csize);
        data += csize;
        data_len -= csize;
        pos += csize;
        data_read += csize;
    }

    return data_read;
}

int rbuf_write_front(rbuf_t *rbuf, const char *data, uint32_t data_size)
{
    int ret = 0;
    if (rbuf_writable_bytes(rbuf) < data_size)
        return -1;

    ret = rbuf_write(rbuf, rbuf->write_pos, data, data_size);
    if (!ret)
        rbuf->write_pos += data_size;

    return ret;
}

int rbuf_read_front(rbuf_t *rbuf, char *data, uint32_t data_size)
{
    int ret;
    uint32_t read_len = 0, pos = rbuf->start_pos, len;
    uint32_t max_size = RBUF_BLOCK_SIZE * rbuf->max_block_num 
        - (rbuf->start_pos % RBUF_BLOCK_SIZE);
    uint32_t tab_id;
    rbuf_blk_t *blk;
    rbuf_record_t *record;


    while (data_size && pos - rbuf->start_pos < max_size) {
        tab_id = (pos / RBUF_BLOCK_SIZE) % rbuf->max_block_num;
        blk = rbuf->blk_tab[tab_id];
        if (NULL == blk)
            break;

        record = (rbuf_record_t *)blk->record_list.next;
        while ((list_head_t *)record != &blk->record_list 
                && record->pos == pos && data_size) {
            len = record->len;
            if (len > data_size)
                len = data_size;

            ret = rbuf_read(rbuf, pos, data, len);
            assert(ret >= 0);
            data += len;
            read_len += len;
            data_size -= len;
            pos += record->len;

            record = (rbuf_record_t *)record->lst.next;
        }

        if ((pos / RBUF_BLOCK_SIZE) % rbuf->max_block_num == tab_id)
            break;
    }
    
    return read_len;
}

void rbuf_window_info(rbuf_t *rbuf, uint32_t *win_start, uint32_t *win_size)
{
    *win_size = RBUF_BLOCK_SIZE * rbuf->max_block_num 
            - (rbuf->start_pos % RBUF_BLOCK_SIZE);
    *win_start = rbuf->start_pos;
}

uint32_t rbuf_readable_bytes(rbuf_t *rbuf)
{
    uint32_t tab_id;
    uint32_t pos = rbuf->start_pos;
    uint32_t readable = 0;
    uint32_t max_size = RBUF_BLOCK_SIZE * rbuf->max_block_num 
        - (rbuf->start_pos % RBUF_BLOCK_SIZE);
    rbuf_blk_t *blk;
    rbuf_record_t *record;

    while (pos - rbuf->start_pos < max_size) {
        tab_id = (pos / RBUF_BLOCK_SIZE) % rbuf->max_block_num;
        blk = rbuf->blk_tab[tab_id];
        if (NULL == blk)
            break;

        record = (rbuf_record_t *)blk->record_list.next;
        while ((list_head_t *)record != &blk->record_list 
                && record->pos == pos) {
            readable += record->len;
            pos += record->len;

            record = (rbuf_record_t *)record->lst.next;
        }

        if ((pos / RBUF_BLOCK_SIZE) % rbuf->max_block_num == tab_id)
            break;
    }

    return readable;
}

uint32_t rbuf_writable_bytes(rbuf_t *rbuf)
{
    uint32_t window_size = RBUF_BLOCK_SIZE * rbuf->max_block_num 
        - (rbuf->start_pos % RBUF_BLOCK_SIZE);
    return window_size - (rbuf->write_pos - rbuf->start_pos);
}

uint32_t rbuf_write_pos(rbuf_t *rbuf)
{
    return rbuf->write_pos;
}

void rbuf_release(rbuf_t *rbuf, uint32_t r_size)
{
    while (r_size > 0) {
        rbuf_record_t *first_record;
        uint32_t blk_id = rbuf->start_pos / RBUF_BLOCK_SIZE;
        rbuf_blk_t *first_blk = rbuf->blk_tab[blk_id % rbuf->max_block_num];
        assert(NULL != first_blk);
        assert(list_empty(&first_blk->record_list) == 0);

        first_record = (rbuf_record_t *)first_blk->record_list.next;
        assert(first_record->pos == rbuf->start_pos);

        if (r_size > first_record->len) {
            rbuf->start_pos += first_record->len;
            first_record->pos += first_record->len;
            r_size -= first_record->len;
            first_record->len = 0;
        } else {
            rbuf->start_pos += r_size;
            first_record->pos += r_size;
            first_record->len -= r_size;
            r_size = 0;
        }
        if (!first_record->len) {
            list_del(&first_record->lst);
            free(first_record);
        }
        if (blk_id != rbuf->start_pos / RBUF_BLOCK_SIZE) {
            uint32_t tab_id = blk_id % rbuf->max_block_num;
            rblk_release(rbuf->blk_tab[tab_id]);
            rbuf->blk_tab[tab_id] = NULL;
        }
    }
}

void rbuf_fini(rbuf_t *rbuf)
{
    unsigned int i;
    for (i = 0; i < rbuf->max_block_num; i++) {
        if (NULL != rbuf->blk_tab[i]) {
            rblk_release(rbuf->blk_tab[i]);
            rbuf->blk_tab[i] = NULL;
        }
    }
    free(rbuf->blk_tab);
}

rbuf_blk_t* rblk_create()
{
    rbuf_blk_t *blk = (rbuf_blk_t *)malloc(sizeof(rbuf_blk_t));
    if (NULL != blk) {
        INIT_LIST_HEAD(&blk->record_list);
    }
    return blk;
}

void rblk_release(rbuf_blk_t *blk)
{
    while (!list_empty(&blk->record_list)) {
        rbuf_record_t *first_record = (rbuf_record_t *)blk->record_list.next;
        list_del(blk->record_list.next);
        free(first_record);
    }
    free(blk);
}

