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

 #ifndef _HASHQUEUE_H_
 #define _HASHQUEUE_H_

 #include <stdint.h>
 #include "list.h"

 typedef uint32_t hash_function(void *key);

 typedef struct _hash_queue {
    uint32_t bucket_size;
    uint32_t key_size;
    uint32_t data_size;
    hash_function *hash_fn;

    list_head_t *hash;
    list_head_t queue;
 } hash_queue_t;

 typedef struct _hash_node {
    list_head_t hash_list;
    list_head_t queue_list;
 } hash_node_t;

int queue_init(hash_queue_t *hq, uint32_t bucket_size, uint32_t key_size, 
                uint32_t data_size, hash_function *fn);
void queue_fini(hash_queue_t *hq);
int queue_prepend(hash_queue_t *hq, void *key, void *value);
int queue_append(hash_queue_t *hq, void *key, void *value);
int queue_del(hash_queue_t *hq, void *key);
hash_node_t *queue_first(hash_queue_t *hq);
hash_node_t *queue_next(hash_queue_t *hq, hash_node_t *curr);
void* queue_key(hash_queue_t *hq, hash_node_t *node);
void* queue_value(hash_queue_t *hq, hash_node_t *node);
void* queue_get(hash_queue_t *hq, void *key);
void* queue_front(hash_queue_t *hq, void *key);
void* queue_back(hash_queue_t *hq, void *key);
int queue_move_front(hash_queue_t *hq, void *key);
int queue_move_back(hash_queue_t *hq, void *key);
int queue_empty(hash_queue_t *hq);

#endif
