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

#ifndef _TIMER_LIST_H_
#define _TIMER_LIST_H_

#include <stdint.h>
#include "list.h"

typedef uint32_t timer_hash_function(const void *key);

typedef struct _timer_node timer_node_t;
typedef struct _heap_node heap_node_t;

typedef struct _timerlist {
    uint32_t bucket_size;
    uint32_t key_size;
    uint32_t data_size;
    uint32_t node_count;
    uint32_t node_capacity;
    timer_hash_function *hash_fn;

    list_head_t *hash;
    heap_node_t *heap;
} timerlist_t;


int timerlist_init(timerlist_t *tq, uint32_t bucket_size, uint32_t key_size,
                uint32_t data_size, timer_hash_function *fn);

void timerlist_fini(timerlist_t *tq);

void timerlist_clear(timerlist_t *tq);

int  timerlist_push(timerlist_t *tq, int64_t time, void *key, void *value);
void timerlist_pop(timerlist_t *tq);
int  timerlist_moveup(timerlist_t *tq, int64_t time, const void *key);
int  timerlist_resched(timerlist_t *tq, int64_t time, const void *key);
int  timerlist_resched_top(timerlist_t *tq, int64_t time);
int  timerlist_del(timerlist_t *tq, const void *key);

void* timerlist_top(timerlist_t *tq, int64_t *time, void *key);
void* timerlist_get(timerlist_t *tq, int64_t *time, const void *key);

timer_node_t* timerlist_find_first(timerlist_t *tq, const void *key);
timer_node_t* timerlist_find_next(timerlist_t *tq, timer_node_t *n);

int64_t timerlist_time(timerlist_t *tq, timer_node_t *n);
void*   timerlist_key(timerlist_t *tq, timer_node_t *n);
void*   timerlist_value(timerlist_t *tq, timer_node_t *n);

int timerlist_empty(timerlist_t *tq);
uint32_t timerlist_size(timerlist_t *tq);

#endif