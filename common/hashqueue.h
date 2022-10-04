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

#ifndef _HASHQUEUE_H_
#define _HASHQUEUE_H_

#include <stdint.h>
#include "list.h"

typedef uint32_t hq_hash_function(const void *key, size_t len);

typedef struct _queue_node {
    list_head_t hash_list;
    list_head_t queue_list;
} queue_node_t;

typedef struct _node_mem {
    uint32_t        node_size;
    uint32_t        node_total;
    uint32_t        realloc_cnt;
    uint32_t        unalloc_node;
    queue_node_t    **realloc_stack;
    char            *alloc_ptr;
    char            buf[0];
} node_mem_t;

typedef struct _hash_queue {
    uint32_t    bucket_size;
    uint32_t    key_size;
    uint32_t    data_size;
    uint32_t    node_count;
    node_mem_t  *mem;
    hq_hash_function *hash_fn;

    list_head_t  *hash;
    list_head_t  queue;
} hash_queue_t;

int queue_init(hash_queue_t *hq, uint32_t bucket_size, uint32_t key_size,
            uint32_t data_size, hq_hash_function *fn, uint32_t fixed_size);

void queue_fini(hash_queue_t *hq);

void queue_clear(hash_queue_t *hq);
int queue_prepend(hash_queue_t *hq, void *key, void *value);
int queue_append(hash_queue_t *hq, void *key, void *value);
int queue_del(hash_queue_t *hq, void *key);

queue_node_t *queue_first(hash_queue_t *hq);
queue_node_t *queue_last(hash_queue_t *hq);
queue_node_t *queue_next(hash_queue_t *hq, queue_node_t *curr);
queue_node_t *queue_prev(hash_queue_t *hq, queue_node_t *curr);

void* queue_key(hash_queue_t *hq, queue_node_t *node);
void* queue_value(hash_queue_t *hq, queue_node_t *node);
void* queue_get(hash_queue_t *hq, void *key);

void* queue_front(hash_queue_t *hq, void *key);
void* queue_back(hash_queue_t *hq, void *key);

void queue_move_to(queue_node_t *src, queue_node_t *dst);
int queue_move_front(hash_queue_t *hq, void *key);
int queue_move_back(hash_queue_t *hq, void *key);

int queue_empty(hash_queue_t *hq);
uint32_t queue_size(hash_queue_t *hq);

#endif
