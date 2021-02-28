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

#include <string.h>
#include <stdlib.h>
#include <stddef.h>
#include "treemap.h"

#define NODE_BLACK 0
#define NODE_RED   1
#define NODE_COLOR(n)  ((n)->color & NODE_RED)
#define IS_RED(n)      ((n) == NULL ? 0 : NODE_COLOR(n))

static tree_node_t* create_node(treemap_t *tm, tree_node_t *parent, 
        void *key, void *value);
static void release_node(treemap_t *tm, tree_node_t **node);

static void treemap_clear_internal(tree_node_t *node);

static int treemap_insert_internal(treemap_t *tm, tree_node_t **node, 
        tree_node_t *parent, void *key, void *value);

static int treemap_delete_internal(treemap_t *tm, tree_node_t **node, 
        void *key);

static void rotate_left(tree_node_t **node);
static void rotate_right(tree_node_t **node);
static void flip_color(tree_node_t **node);
static void move_red_left(tree_node_t **node);
static void move_red_right(tree_node_t **node);
static tree_node_t* delete_min(tree_node_t **node);

int treemap_init(treemap_t *tm, uint32_t key_size, uint32_t data_size, 
        compare_fn *cmp)
{
    tm->key_size    = key_size;
    tm->data_size   = data_size;
    tm->cmp_fn      = cmp;
    tm->node_cnt    = 0;
    tm->root        = NULL;
    tm->first       = NULL;
}

void treemap_fini(treemap_t *tm)
{
    treemap_clear(tm);
}

void treemap_clear(treemap_t *tm)
{
    treemap_clear_internal(tm->root);
    tm->root = NULL;
    tm->first = NULL;
    tm->node_cnt = 0;
}

int treemap_insert(treemap_t *tm, void *key, void *value)
{
    int ret = treemap_insert_internal(tm, &tm->root, NULL, key, value);
    tm->root->color = NODE_BLACK;
    return ret;
}

int treemap_delete(treemap_t *tm, void *key)
{
    int ret = treemap_delete_internal(tm, &tm->root, key);
    if (tm->root != NULL) {
        tm->root->color = NODE_BLACK;
    }
    return ret;
}

tree_node_t* treemap_first(treemap_t *tm)
{
    if (tm->first == NULL && tm->root != NULL) {
        tm->first = tm->root;
        while (tm->first->left != NULL)
            tm->first = tm->first->left;
    }
    return tm->first;
}

tree_node_t* treemap_last(treemap_t *tm)
{
    tree_node_t *last = tm->root;
    if (last != NULL) {
        while (last->right != NULL)
            last = last->right;
    }
    return last;
}

tree_node_t* treemap_next(tree_node_t *curr)
{
    if (curr->right != NULL) {
        curr = curr->right;
        while (curr->left != NULL) {
            curr = curr->left;
        }
    } else {
        tree_node_t *parent = curr->parent;
        while (parent != NULL && parent->right == curr) {
            curr = parent;
            parent = curr->parent;;
        }
        curr = parent;
    }
    return curr;
}

tree_node_t* treemap_prev(tree_node_t *curr)
{
    if (curr->left != NULL) {
        curr = curr->left;
        while (curr->right != NULL) {
            curr = curr->right;
        }
    } else {
        tree_node_t *parent = curr->parent;
        while (parent != NULL && parent->left == curr) {
            curr = parent;
            parent = curr->parent;;
        }
        curr = parent;
    }
    return curr;
}

tree_node_t* treemap_lower_bound(treemap_t *tm, void *key)
{
    tree_node_t *result = NULL;
    tree_node_t *node = tm->root;
    while (node != NULL) {
        if (tm->cmp_fn(treemap_key(tm, node), key) < 0) {
            node = node->right;
        } else {
            result = node;
            node = node->left;
        }
    }
    return result;
}

void* treemap_key(treemap_t *tm, tree_node_t *node)
{
    return (char *)node + sizeof(tree_node_t);
}

void* treemap_value(treemap_t *tm, tree_node_t *node)
{
    return (char *)node + sizeof(tree_node_t) + tm->key_size;
}

void* treemap_get(treemap_t *tm, void *key)
{
    tree_node_t *cur = tm->root;
    while (cur != NULL) {
        void *cur_key = treemap_key(tm, cur);
        int ret = tm->cmp_fn(key, cur_key);
        if (ret > 0) {
            cur = cur->right;
        } else if (ret < 0) {
            cur = cur->left;
        } else {
            return treemap_value(tm, cur);
        }
    }

    return NULL;
}

uint32_t treemap_size(treemap_t *tm)
{
    return tm->node_cnt;
}

static tree_node_t*
create_node(treemap_t *tm, tree_node_t *parent, void *key, void *value)
{
    size_t node_size = sizeof(tree_node_t) + tm->key_size + tm->data_size;
    char *buf = (char*)malloc(node_size);
    tree_node_t *node = (tree_node_t *)buf;
    if (NULL == node)
        return NULL;
    
    node->parent = parent;
    node->left = node->right = NULL;
    node->color = NODE_RED;
    memcpy(buf + sizeof(tree_node_t), key, tm->key_size);
    memcpy(buf + sizeof(tree_node_t) + tm->key_size, value, tm->data_size);
    ++tm->node_cnt;

    return node;
}

static void
release_node(treemap_t *tm, tree_node_t **node)
{
    --tm->node_cnt;
    free(*node);
    *node = NULL;
}

static void
treemap_clear_internal(tree_node_t *node)
{
    if (node == NULL)
        return;

    treemap_clear_internal(node->left);
    treemap_clear_internal(node->right);
    free(node);
}

static int
treemap_insert_internal(treemap_t *tm, tree_node_t **node, tree_node_t *parent,
        void *key, void *value)
{
    if (*node == NULL) {
        // allocate new node
        *node = create_node(tm, parent, key, value);
        return NULL == *node ? -1 : 0;
    }

    int ret = tm->cmp_fn(key, treemap_key(tm, *node));
    if (ret > 0) {
        ret = treemap_insert_internal(tm, &(*node)->right, *node, key, value);
    } else if (ret < 0) {
        ret = treemap_insert_internal(tm, &(*node)->left, *node, key, value);
        if (ret == 0 && *node == tm->first) {
            tm->first = (*node)->left;
        }
    } else {
        return 1;
    }

    if (ret != 0)
        return ret;

    // adjust llrb subtree balance
    if (!IS_RED((*node)->left) && IS_RED((*node)->right))
        rotate_left(node);
    if (IS_RED((*node)->left) && IS_RED((*node)->left->left))
        rotate_right(node);
    if (IS_RED((*node)->left) && IS_RED((*node)->right))
        flip_color(node);

    return 0;
}

static int 
treemap_delete_internal(treemap_t *tm, tree_node_t **node, void *key)
{
    if (*node == NULL) {
        return 0;
    }

    int ret = 0;
    if (tm->cmp_fn(key, treemap_key(tm, *node)) < 0) {
        if ((*node)->left == NULL)
            return 0;
        if (!IS_RED((*node)->left) && !IS_RED((*node)->left->left))
            move_red_left(node);
        ret = treemap_delete_internal(tm, &(*node)->left, key);
    } else {
        if (IS_RED((*node)->left))
            rotate_right(node);

        if (!tm->cmp_fn(key, treemap_key(tm, *node)) && 
            (*node)->right == NULL) {
            // key equals cur_key and no right child (or left child)
            if (tm->first == *node)
                tm->first = (*node)->parent;
            release_node(tm, node);
            return 1;
        }
        if ((*node)->right != NULL && !IS_RED((*node)->right) && 
            !IS_RED((*node)->right->left)) {
            move_red_right(node);
        }

        if (!tm->cmp_fn(key, treemap_key(tm, *node))) {
            tree_node_t *min_node = delete_min(&(*node)->right);
            memcpy(min_node, *node, sizeof(tree_node_t));
            if (min_node->left != NULL)
                min_node->left->parent = min_node;
            if (min_node->right != NULL)
                min_node->right->parent = min_node;

            if (tm->first == *node)
                tm->first = min_node;
            release_node(tm, node);
            *node = min_node;
            ret = 1;
        } else {
            ret = treemap_delete_internal(tm, &(*node)->right, key);
        }
    }

    // fix node balance
    if (IS_RED((*node)->right))
        rotate_left(node);
    if (IS_RED((*node)->left) && IS_RED((*node)->left->left))
        rotate_right(node);
    if (IS_RED((*node)->left) && IS_RED((*node)->right))
        flip_color(node);

    return ret;
}

static void 
rotate_left(tree_node_t **node)
{
    tree_node_t *new_node = (*node)->right;

    (*node)->right = new_node->left;
    new_node->left = *node;
    new_node->color = (*node)->color;
    (*node)->color = NODE_RED;

    new_node->parent = (*node)->parent;
    (*node)->parent = new_node;
    if ((*node)->right != NULL) {
        (*node)->right->parent = (*node);
    }

    *node = new_node;
}

static void 
rotate_right(tree_node_t **node)
{
    tree_node_t *new_node = (*node)->left;

    (*node)->left = new_node->right;
    new_node->right = *node;
    new_node->color = (*node)->color;
    (*node)->color = NODE_RED;

    new_node->parent = (*node)->parent;
    (*node)->parent = new_node;
    if ((*node)->left != NULL) {
        (*node)->left->parent = (*node);
    }

    *node = new_node;
}

static void 
flip_color(tree_node_t **node)
{
    (*node)->color = IS_RED(*node) ? NODE_BLACK : NODE_RED;
    (*node)->left->color = IS_RED((*node)->left) ? NODE_BLACK : NODE_RED;
    (*node)->right->color = IS_RED((*node)->right) ? NODE_BLACK : NODE_RED;
}

static void 
move_red_left(tree_node_t **node)
{
    flip_color(node);
    if (IS_RED((*node)->right->left)) {
        rotate_right(&(*node)->right);
        rotate_left(node);
        flip_color(node);
    }
}

static void
move_red_right(tree_node_t **node)
{
    flip_color(node);
    if (IS_RED((*node)->left->left)) {
        rotate_right(node);
        flip_color(node);
    }
}

static tree_node_t*
delete_min(tree_node_t **node)
{
    tree_node_t *n = NULL;
    if (*node == NULL)
        return NULL;

    if ((*node)->left == NULL) {
        n = *node;
        *node = NULL;
        return n;
    }

    if (!IS_RED((*node)->left) && !IS_RED((*node)->left->left)) {
        move_red_left(node);
    }

    n = delete_min(&(*node)->left);

    // fix node balance
    if (IS_RED((*node)->right))
        rotate_left(node);

    if (IS_RED((*node)->left) && IS_RED((*node)->left->left))
        rotate_right(node);

    if (IS_RED((*node)->left) && IS_RED((*node)->right))
        flip_color(node);

    return n;
}