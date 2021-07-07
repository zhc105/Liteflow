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
#include "hashqueue.h"

void* node_alloc(hash_queue_t *hq, uint32_t node_size)
{
    void *ptr;
    if (NULL != hq->mem) {
        if (hq->mem->realloc_cnt > 0) {
            ptr = hq->mem->realloc_stack[--hq->mem->realloc_cnt];
        } else if (hq->mem->unalloc_node > 0) {
            ptr = hq->mem->alloc_ptr;
            hq->mem->alloc_ptr += hq->mem->node_size;
            --hq->mem->unalloc_node;
        } else {
            ptr = NULL;
        }
    } else {
        ptr = malloc(node_size);
    }
    return ptr;
}

void node_free(hash_queue_t *hq, hash_node_t *node)
{
    if (NULL != hq->mem) {
        uint32_t pos = hq->mem->realloc_cnt++;
        hq->mem->realloc_stack[pos] = node;
    } else {
        free(node);
    }
}

int queue_init(hash_queue_t *hq, uint32_t bucket_size, uint32_t key_size,
               uint32_t data_size, hash_function *fn, uint32_t fixed_size)
{
    uint32_t i;
    hq->hash = (list_head_t *)malloc(sizeof(list_head_t) * bucket_size);
    if (NULL == hq->hash)
        return -1;
    
    hq->bucket_size = bucket_size;
    hq->key_size    = key_size;
    hq->data_size   = data_size;
    hq->node_count  = 0;
    hq->mem         = NULL;
    hq->hash_fn     = fn;

    if (fixed_size > 0) {
        uint32_t node_size  = sizeof(hash_node_t) + key_size + data_size;
        uint32_t list_size  = sizeof(hash_node_t*) * fixed_size;
        uint32_t buf_size   = list_size + node_size * fixed_size;
        hq->mem = (node_mem_t*)malloc(sizeof(node_mem_t) + buf_size);
        if (NULL == hq->mem) {
            free(hq->hash);
            return -1;
        }
        hq->mem->node_size      = node_size;
        hq->mem->node_total     = fixed_size;
        hq->mem->realloc_cnt    = 0;
        hq->mem->unalloc_node   = fixed_size;
        hq->mem->realloc_stack  = (hash_node_t**)hq->mem->buf;
        hq->mem->alloc_ptr      = hq->mem->buf + list_size;
    }

    INIT_LIST_HEAD(&hq->queue);
    for (i = 0; i < bucket_size; i++)
        INIT_LIST_HEAD(&hq->hash[i]);

    return 0;
}

void queue_fini(hash_queue_t *hq)
{
    queue_clear(hq);
    free(hq->hash);
    if (NULL != hq->mem) {
        free(hq->mem);
    }
}

void queue_clear(hash_queue_t *hq)
{
    list_head_t *curr;
    while (!list_empty(&hq->queue)) {
        curr = hq->queue.next;
        hash_node_t *node = list_entry(curr, hash_node_t, queue_list);
        
        list_del(&node->hash_list);
        list_del(&node->queue_list);
        node_free(hq, node);
    }
}

int queue_prepend(hash_queue_t *hq, void *key, void *value)
{
    uint32_t node_size = sizeof(hash_node_t) + hq->key_size + hq->data_size;
    char *buf = (char*)node_alloc(hq, node_size);
    hash_node_t *node = (hash_node_t *)buf;
    if (NULL == node)
        return -1;

    uint32_t hv = hq->hash_fn(key) % hq->bucket_size;
    memcpy(buf + sizeof(hash_node_t), key, hq->key_size);
    memcpy(buf + sizeof(hash_node_t) + hq->key_size, value, hq->data_size);
    list_add(&node->queue_list, &hq->queue);
    list_add(&node->hash_list, &hq->hash[hv]);
    ++hq->node_count;
    
    return 0;
}

int queue_append(hash_queue_t *hq, void *key, void *value)
{
    uint32_t node_size = sizeof(hash_node_t) + hq->key_size + hq->data_size;
    char *buf = (char *)node_alloc(hq, node_size);
    hash_node_t *node = (hash_node_t *)buf;
    if (NULL == node)
        return -1;

    uint32_t hv = hq->hash_fn(key) % hq->bucket_size;
    memcpy(buf + sizeof(hash_node_t), key, hq->key_size);
    memcpy(buf + sizeof(hash_node_t) + hq->key_size, value, hq->data_size);
    list_add_tail(&node->queue_list, &hq->queue);
    list_add_tail(&node->hash_list, &hq->hash[hv]);
    ++hq->node_count;
    
    return 0;
}

int queue_del(hash_queue_t *hq, void *key)
{
    int del_num = 0;
    uint32_t hv = hq->hash_fn(key) % hq->bucket_size;
    list_head_t *curr, *head = &hq->hash[hv];
    for (curr = head->next; curr != head;) {
        hash_node_t *node = list_entry(curr, hash_node_t, hash_list);
        curr = curr->next;
        void *nkey = (char *)node + sizeof(hash_node_t);
        if (!memcmp(nkey, key, hq->key_size)) {
            list_del(&node->hash_list);
            list_del(&node->queue_list);
            --hq->node_count;
            node_free(hq, node);
            ++del_num;
        }
    }
    return del_num;
}

hash_node_t *queue_first(hash_queue_t *hq)
{
    if (hq->queue.next == &hq->queue)
        return NULL;
    return list_entry(hq->queue.next, hash_node_t, queue_list);
}

hash_node_t *queue_last(hash_queue_t *hq)
{
    if (hq->queue.prev == &hq->queue)
        return NULL;
    return list_entry(hq->queue.prev, hash_node_t, queue_list);
}

hash_node_t *queue_next(hash_queue_t *hq, hash_node_t *curr)
{
    if (curr->queue_list.next == &hq->queue)
        return NULL;
    return list_entry(curr->queue_list.next, hash_node_t, queue_list);
}

hash_node_t *queue_prev(hash_queue_t *hq, hash_node_t *curr)
{
    if (curr->queue_list.prev == &hq->queue)
        return NULL;
    return list_entry(curr->queue_list.prev, hash_node_t, queue_list);
}

void* queue_key(hash_queue_t *hq, hash_node_t *node)
{
    return (char *)node + sizeof(hash_node_t);
}

void* queue_value(hash_queue_t *hq, hash_node_t *node)
{
    return (char *)node + sizeof(hash_node_t) + hq->key_size;
}

void* queue_get(hash_queue_t *hq, void *key)
{
    uint32_t hv = hq->hash_fn(key) % hq->bucket_size;
    list_head_t *curr, *head = &hq->hash[hv];
    for (curr = head->next; curr != head; curr = curr->next) {
        hash_node_t *node = list_entry(curr, hash_node_t, hash_list);
        void *nkey = (char *)node + sizeof(hash_node_t);
        if (!memcmp(nkey, key, hq->key_size)) 
            return (char *)node + sizeof(hash_node_t) + hq->key_size;
    }
    return NULL;
}

void* queue_front(hash_queue_t *hq, void *key)
{
    if (list_empty(&hq->queue))
        return NULL;
    hash_node_t *node = list_entry(hq->queue.next, hash_node_t, queue_list);
    if (key != NULL)
        memcpy(key, (char *)node + sizeof(hash_node_t), hq->key_size);
    return (char *)node + sizeof(hash_node_t) + hq->key_size;
}

void* queue_back(hash_queue_t *hq, void *key)
{
    if (list_empty(&hq->queue))
        return NULL;
    hash_node_t *node = list_entry(hq->queue.prev, hash_node_t, queue_list);
    if (key != NULL)
        memcpy(key, (char *)node + sizeof(hash_node_t), hq->key_size);
    return (char *)node + sizeof(hash_node_t) + hq->key_size;
}

int queue_move_front(hash_queue_t *hq, void *key)
{
    uint32_t hv = hq->hash_fn(key) % hq->bucket_size;
    list_head_t *curr, *head = &hq->hash[hv];
    for (curr = head->next; curr != head; curr = curr->next) {
        hash_node_t *node = list_entry(curr, hash_node_t, hash_list);
        void *nkey = (char *)node + sizeof(hash_node_t);
        if (!memcmp(nkey, key, hq->key_size)) {
            list_move(&node->queue_list, &hq->queue);
        }
    }
    return 0;
}

void queue_move_to(hash_node_t *src, hash_node_t *dst)
{
    list_move(&src->queue_list, &dst->queue_list);
}

int queue_move_back(hash_queue_t *hq, void *key)
{
    uint32_t hv = hq->hash_fn(key) % hq->bucket_size;
    list_head_t *curr, *head = &hq->hash[hv];
    for (curr = head->next; curr != head; curr = curr->next) {
        hash_node_t *node = list_entry(curr, hash_node_t, hash_list);
        void *nkey = (char *)node + sizeof(hash_node_t);
        if (!memcmp(nkey, key, hq->key_size)) {
            list_move_tail(&node->queue_list, &hq->queue);
        }
    }
    return 0;
}

int queue_empty(hash_queue_t *hq)
{
    return hq->queue.next == &hq->queue;
}

uint32_t queue_size(hash_queue_t *hq)
{
    return hq->node_count;
}
