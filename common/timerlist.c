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

#include <string.h>
#include <stdlib.h>
#include <stddef.h>
#include "timerlist.h"

#define NODE_CAPACITY_INITIAL 32

#define HEAP_SWAP(a, b) \
    do { \
        uint32_t _heap_id_tmp_ = a.node->heap_id; \
        heap_node_t _heap_tmp_ = a; \
        a.node->heap_id = b.node->heap_id; \
        b.node->heap_id = _heap_id_tmp_; \
        a = b; \
        b = _heap_tmp_; \
    } while(0) \

struct _timer_node {
    list_head_t hash_list;
    uint32_t heap_id;
};

typedef struct _heap_node {
    int64_t time;
    timer_node_t *node;
} heap_node_t;

static void adjust_down(timerlist_t *tq, uint32_t s);
static void adjust_up(timerlist_t *tq, uint32_t s);

int timerlist_init(
    timerlist_t *tq,
    uint32_t bucket_size,
    uint32_t key_size, 
    uint32_t data_size,
    timer_hash_function *fn)
{
    uint32_t i;
    uint32_t heap_size = sizeof(heap_node_t) * NODE_CAPACITY_INITIAL;
    tq->hash = (list_head_t *)malloc(sizeof(list_head_t) * bucket_size);
    if (NULL == tq->hash) {
        return -1;
    }
    tq->heap = (heap_node_t *)malloc(heap_size);
    if (NULL == tq->heap) {
        free(tq->hash);
        return -1;
    }
    
    tq->bucket_size = bucket_size;
    tq->key_size    = key_size;
    tq->data_size   = data_size;
    tq->node_count  = 0;
    tq->node_capacity = NODE_CAPACITY_INITIAL;
    tq->hash_fn     = fn;

    for (i = 0; i < bucket_size; i++)
        INIT_LIST_HEAD(&tq->hash[i]);

    return 0;
}

void timerlist_fini(timerlist_t *tq)
{
    timerlist_clear(tq);
    free(tq->hash);
    free(tq->heap);
}

void timerlist_clear(timerlist_t *tq)
{
    for (uint32_t i = 0; i < tq->node_count; ++i) {
        timer_node_t *node = tq->heap[i].node;
        list_del(&node->hash_list);
        free(node);
    }

    tq->node_count = 0;
}

int timerlist_push(timerlist_t *tq, int64_t time, void *key, void *value)
{
    if (tq->node_count >= tq->node_capacity) {
        // expand heap memory
        heap_node_t *new_heap;
        uint32_t new_capacity = tq->node_capacity << 1;
        uint32_t new_size = sizeof(heap_node_t) * new_capacity;
        new_heap = (heap_node_t *)realloc(tq->heap, new_size);
        if (new_heap == NULL)
            return -1;

        tq->node_capacity = new_capacity;
        tq->heap = new_heap;
    }
    
    uint32_t node_size = sizeof(timer_node_t) + tq->key_size + tq->data_size;
    char *buf = (char *)malloc(node_size);
    timer_node_t *node = (timer_node_t *)buf;
    if (NULL == node)
        return -1;

    uint32_t hv = tq->hash_fn(key) % tq->bucket_size;
    memcpy(buf + sizeof(timer_node_t), key, tq->key_size);
    memcpy(buf + sizeof(timer_node_t) + tq->key_size, value, tq->data_size);
    list_add_tail(&node->hash_list, &tq->hash[hv]);

    tq->heap[tq->node_count].time = time;
    tq->heap[tq->node_count].node = node;
    node->heap_id = tq->node_count;
    ++tq->node_count;

    adjust_up(tq, node->heap_id);
    
    return 0;
}

void timerlist_pop(timerlist_t *tq)
{
    timer_node_t *node;
    if (!tq->node_count)
        return;
    
    --tq->node_count;
    if (tq->node_count) {
        HEAP_SWAP(tq->heap[0], tq->heap[tq->node_count]);
        adjust_down(tq, 0);
    }

    node = tq->heap[tq->node_count].node;
    list_del(&node->hash_list);
    free(node);
}

int timerlist_moveup(timerlist_t *tq, int64_t time, const void *key)
{
    int resched_num = 0;
    uint32_t hv = tq->hash_fn(key) % tq->bucket_size;
    list_head_t *curr, *head = &tq->hash[hv];
    for (curr = head->next; curr != head;) {
        timer_node_t *node = list_entry(curr, timer_node_t, hash_list);
        curr = curr->next;
        void *nkey = (char *)node + sizeof(timer_node_t);
        if (!memcmp(nkey, key, tq->key_size)) {
            uint32_t id = node->heap_id;
            if (tq->heap[id].time <= time)
                continue;

            tq->heap[id].time = time;
            adjust_up(tq, id);
            
            ++resched_num;
        }
    }

    return resched_num;
}

int timerlist_resched(timerlist_t *tq, int64_t time, const void *key)
{
    int resched_num = 0;
    uint32_t hv = tq->hash_fn(key) % tq->bucket_size;
    list_head_t *curr, *head = &tq->hash[hv];
    for (curr = head->next; curr != head;) {
        timer_node_t *node = list_entry(curr, timer_node_t, hash_list);
        curr = curr->next;
        void *nkey = (char *)node + sizeof(timer_node_t);
        if (!memcmp(nkey, key, tq->key_size)) {
            uint32_t id = node->heap_id;
            uint64_t orig_time = tq->heap[id].time; 
            tq->heap[id].time = time;

            if (orig_time > time)
                adjust_up(tq, id);
            else
                adjust_down(tq, id);
            
            ++resched_num;
        }
    }

    return resched_num;
}

int timerlist_resched_top(timerlist_t *tq, int64_t time)
{
    if (!tq->node_count)
        return 0;

    tq->heap[0].time = time;
    adjust_down(tq, 0);
    return 1;
}

int timerlist_del(timerlist_t *tq, const void *key)
{
    int del_num = 0;
    uint32_t hv = tq->hash_fn(key) % tq->bucket_size;
    list_head_t *curr, *head = &tq->hash[hv];
    for (curr = head->next; curr != head;) {
        timer_node_t *node = list_entry(curr, timer_node_t, hash_list);
        curr = curr->next;
        void *nkey = (char *)node + sizeof(timer_node_t);
        if (!memcmp(nkey, key, tq->key_size)) {
            uint32_t id = node->heap_id;
            --tq->node_count;

            if (id != tq->node_count) {
                HEAP_SWAP(tq->heap[id], tq->heap[tq->node_count]);
                adjust_up(tq, id);
                adjust_down(tq, id);
            }

            list_del(&node->hash_list);
            free(node);
            
            ++del_num;
        }
    }

    return del_num;
}

void* timerlist_top(timerlist_t *tq, int64_t *time, void *key)
{
    if (!tq->node_count)
        return NULL;
    
    timer_node_t *node = tq->heap[0].node;
    if (time)
        *time = tq->heap[0].time;
    if (key)
        memcpy(key, (char *)node + sizeof(timer_node_t), tq->key_size);
    return (char *)node + sizeof(timer_node_t) + tq->key_size;
}

void* timerlist_get(timerlist_t *tq, int64_t *time, const void *key)
{
    uint32_t hv = tq->hash_fn(key) % tq->bucket_size;
    list_head_t *curr, *head = &tq->hash[hv];
    for (curr = head->next; curr != head; curr = curr->next) {
        timer_node_t *node = list_entry(curr, timer_node_t, hash_list);
        void *nkey = (char *)node + sizeof(timer_node_t);
        if (!memcmp(nkey, key, tq->key_size)) {
            if (time)
                *time = tq->heap[node->heap_id].time;
            return (char *)node + sizeof(timer_node_t) + tq->key_size;
        } 
    }
    return NULL;
}

timer_node_t* timerlist_find_first(timerlist_t *tq, const void *key)
{
    uint32_t hv = tq->hash_fn(key) % tq->bucket_size;
    list_head_t *curr, *head = &tq->hash[hv];
    for (curr = head->next; curr != head; curr = curr->next) {
        timer_node_t *node = list_entry(curr, timer_node_t, hash_list);
        void *nkey = (char *)node + sizeof(timer_node_t);
        if (!memcmp(nkey, key, tq->key_size)) {
            return node;
        } 
    }
    return NULL;
}

timer_node_t* timerlist_find_next(timerlist_t *tq, timer_node_t *n)
{
    const void *key = (const void*)((char *)n + sizeof(timer_node_t));
    uint32_t hv = tq->hash_fn(key) % tq->bucket_size;
    list_head_t *curr, *head = &tq->hash[hv];
    for (curr = n->hash_list.next; curr != head; curr = curr->next) {
        timer_node_t *node = list_entry(curr, timer_node_t, hash_list);
        void *nkey = (char *)node + sizeof(timer_node_t);
        if (!memcmp(nkey, key, tq->key_size)) {
            return node;
        } 
    }
    return NULL;
}

int64_t timerlist_time(timerlist_t *tq, timer_node_t *n)
{
    return tq->heap[n->heap_id].time;
}

void* timerlist_key(timerlist_t *tq, timer_node_t *n)
{
    return (char *)n + sizeof(timer_node_t);
}

void* timerlist_value(timerlist_t *tq, timer_node_t *n)
{
    return (char *)n + sizeof(timer_node_t) + tq->key_size;
}

int timerlist_empty(timerlist_t *tq)
{
    return !tq->node_count;
}

uint32_t timerlist_size(timerlist_t *tq)
{
    return tq->node_count;
}

static void adjust_down(timerlist_t *tq, uint32_t s)
{
    if (tq->node_count < 2)
        return;

    while (s <= (tq->node_count - 2) >> 1) {
        uint32_t t = (s << 1) + 1;
        if (t + 1 < tq->node_count && tq->heap[t + 1].time < tq->heap[t].time)
            ++t;
        if (tq->heap[t].time < tq->heap[s].time) {
            HEAP_SWAP(tq->heap[s], tq->heap[t]);
            s = t;
        } else {
            break;
        }
    }
}

static void adjust_up(timerlist_t *tq, uint32_t s)
{
    while (s > 0) {
        uint32_t t = (s - 1) >> 1;
        if (tq->heap[s].time < tq->heap[t].time) {
            HEAP_SWAP(tq->heap[s], tq->heap[t]);
            s = t;
        } else {
            break;
        }
    }
}
