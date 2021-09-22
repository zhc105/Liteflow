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
 *
 * A Tree Map implementation with Left-Leaning Red-Black binary search tree
 * (LLRB)
 */

#ifndef _TREEMAP_H_
#define _TREEMAP_H_

#include <stdint.h>

typedef int compare_fn(void *a, void *b);

typedef struct _tree_node {
    struct _tree_node *parent;
    struct _tree_node *left;
    struct _tree_node *right;
    uint32_t color;
} tree_node_t;

typedef struct _treemap {
    uint32_t    key_size;
    uint32_t    data_size;
    compare_fn  *cmp_fn;

    uint32_t    node_cnt;
    tree_node_t *root;
    tree_node_t *first;
} treemap_t;

int  treemap_init(treemap_t *tm, uint32_t key_size, uint32_t data_size,
                compare_fn *cmp);
void treemap_fini(treemap_t *tm);
void treemap_clear(treemap_t *tm);
int  treemap_insert(treemap_t *tm, void *key, void *value);
int  treemap_insert2(treemap_t *tm, void *key, void *value,
                    tree_node_t **inserted);
int  treemap_delete(treemap_t *tm, void *key);

tree_node_t* treemap_first(treemap_t *tm);
tree_node_t* treemap_last(treemap_t *tm);
tree_node_t* treemap_next(tree_node_t *curr);
tree_node_t* treemap_prev(tree_node_t *curr);
tree_node_t* treemap_lower_bound(treemap_t *tm, void *key);
tree_node_t* treemap_upper_bound(treemap_t *tm, void *key);

void* treemap_key(treemap_t *tm, tree_node_t *node);
void* treemap_value(treemap_t *tm, tree_node_t *node);
void* treemap_get(treemap_t *tm, void *key);
uint32_t treemap_size(treemap_t *tm);

#endif