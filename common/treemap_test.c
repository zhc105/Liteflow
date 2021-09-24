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

#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <assert.h>
#include "test_helper.h"
#include "treemap.h"

#define NODE_BLACK 0
#define NODE_RED   1

#define ACTION_ADD          1
#define ACTION_DEL          2
#define ACTION_VALIDATE     3
#define ACTION_LOWERBOUND   4

int32_t g_actions[10000][3] = {};
size_t g_cnt = 0;

int int_cmp(void *a, void* b)
{
    return *(int32_t*)a - *(int32_t*)b;
}

int get_black_height(treemap_t *tm)
{
    tree_node_t *cur = tm->root;
    int height = 1;
    while (cur != NULL) {
        if (cur->color == NODE_BLACK)
            ++height;
        cur = cur->left;
    }
    return height;
}

void validate_llrb(tree_node_t *node, int black, int expect)
{
    if (node == NULL || node->color == NODE_BLACK)
        ++black;

    if (node == NULL) {
        assert(black == expect);
        return;
    }
    if (node->left != NULL) {
        assert(node->left->parent == node);
        if (node->color == NODE_RED)
            assert(node->left->color == NODE_BLACK);
    }
    if (node->right != NULL) {
        assert(node->right->parent == node);
        assert(node->right->color == NODE_BLACK);
        if (node->color == NODE_RED)
            assert(node->right->color == NODE_BLACK);
    }

    validate_llrb(node->left, black, expect);
    validate_llrb(node->right, black, expect);
}

void print_tree(treemap_t* map, tree_node_t *cur)
{
    if (cur == NULL)
        return;

    printf("[%p] %8d %5s Left=%-18p Right=%-18p Parent=%-18p\n", cur,
        *(int32_t*)treemap_key(map, cur),
        cur->color == NODE_BLACK ? "BLACK" : "RED",
        cur->left, cur->right, cur->parent);
    print_tree(map, cur->left);
    print_tree(map, cur->right);
}

void validate(treemap_t* map, uint32_t cnt, int line)
{
    /* verify whether map->root is a valid llrb tree */
    int height = get_black_height(map);
    validate_llrb(map->root, 0, height);
    /* verify map is in order */
    if (map->node_cnt != cnt) {
        printf("[LINE %d] Assert failure, count of tree node was not match"
            ": expect = %u, actual = %u\n", line, cnt, map->node_cnt);
        assert(0);
    }
    int32_t min = -INT32_MAX;
    uint32_t found = 0;
    for (tree_node_t *cur = treemap_first(map); cur != NULL;
        cur = treemap_next(cur)) {
        int32_t *key = (int32_t*)treemap_key(map, cur);
        if (*key <= min) {
            printf("[LINE %d] Assert failure, sequence of elements in map "
                "was wrong\n", line);
            assert(0);
        }
        ++found;
        min = *key;
    }
    if (found != cnt) {
        printf("[LINE %d] Assert failure, not all elements were found in map"
                ": expect = %u, actual = %u\n", line, cnt, found);
        assert(0);
    }
}

void basic_test()
{
    treemap_t map;
    int ret = 0;
    tree_node_t* node = NULL;
    treemap_init(&map, sizeof(int32_t), sizeof(int32_t), int_cmp);
    for (int i = 0; i < g_cnt; ++i) {
        switch (g_actions[i][0])
        {
        case ACTION_ADD:
            ret = treemap_insert(&map, &g_actions[i][1], &g_actions[i][1]);
            if (ret != g_actions[i][2]) {
                printf("[LINE %d] Assert failure on insert: expect = %d, "
                    "actual = %d\n", i, g_actions[i][2], ret);
                assert(0);
            }
            break;
        case ACTION_DEL:
            ret = treemap_delete(&map, &g_actions[i][1]);
            if (ret != g_actions[i][2]) {
                printf("[LINE %d] Assert failure on delete: expect = %d, "
                    "actual = %d\n", i, g_actions[i][2], ret);
                assert(0);
            }
            break;
        case ACTION_VALIDATE:
            validate(&map, (uint32_t)g_actions[i][1], i);
            break;
        case ACTION_LOWERBOUND:
            node = treemap_lower_bound(&map, &g_actions[i][1]);
            if (node == NULL) {
                if (-1 != g_actions[i][2]) {
                    printf("[LINE %d] Assert failure on lower_bound:"
                        " expect %d, actual not found\n", i, g_actions[i][2]);
                    assert(0);
                }
            } else if (*(int32_t*)treemap_key(&map, node) != g_actions[i][2]) {
                printf("[LINE %d] Assert failure on lower_bound: expect = %d"
                    ", actual = %d\n", i, g_actions[i][2], ret);
                assert(0);
            }
            break;
        default:
            break;
        }
        //printf("Line %d done\n", i);
        //print_tree(&map, map.root);
    }

    treemap_fini(&map);
}

void performance_test()
{
    treemap_t map;
    treemap_init(&map, sizeof(int32_t), sizeof(int32_t), int_cmp);
    for (int32_t i = 0; i < 1000000; ++i)
        treemap_insert(&map, &i, &i);
    assert(treemap_size(&map) == 1000000);
    for (int32_t i = 0; i < 1000000; i += 2)
        treemap_delete(&map, &i);
    assert(treemap_size(&map) == 500000);
    for (int32_t i = 1000000; i < 1500000; ++i)
        treemap_insert(&map, &i, &i);
    assert(treemap_size(&map) == 1000000);
    treemap_fini(&map);

    treemap_init(&map, sizeof(int32_t), sizeof(int32_t), int_cmp);
    for (int32_t i = 1000000; i > 0; --i)
        treemap_insert(&map, &i, &i);
    assert(treemap_size(&map) == 1000000);
    for (int32_t i = 1000000; i > 0; i -= 2)
        treemap_delete(&map, &i);
    assert(treemap_size(&map) == 500000);
    for (int32_t i = 1500000; i > 1000000; --i)
        treemap_insert(&map, &i, &i);
    assert(treemap_size(&map) == 1000000);
    treemap_fini(&map);
}

void load_test_data()
{
    char buf[128];
    FILE *testdata = fopen("testdata/treemap_testdata.txt", "r");
    while (fgets(buf, sizeof(buf) - 1, testdata) != NULL) {
        if (!strncmp(buf, "add", 3)) {
            int num = 0, ret = 0;
            sscanf(buf, "%*s %d %d", &num, &ret);
            g_actions[g_cnt][0] = ACTION_ADD;
            g_actions[g_cnt][1] = num;
            g_actions[g_cnt][2] = ret;
            ++g_cnt;
        } else if (!strncmp(buf, "del", 3)) {
            int num = 0, ret = 0;
            sscanf(buf, "%*s %d %d", &num, &ret);
            g_actions[g_cnt][0] = ACTION_DEL;
            g_actions[g_cnt][1] = num;
            g_actions[g_cnt][2] = ret;
            ++g_cnt;
        } else if (!strncmp(buf, "validate", 8)) {
            int cnt = 0;
            sscanf(buf, "%*s %d", &cnt);
            g_actions[g_cnt][0] = ACTION_VALIDATE;
            g_actions[g_cnt][1] = cnt;
            ++g_cnt;
        } else if (!strncmp(buf, "lowerbound", 10)) {
            int num = 0, ret = 0;
            sscanf(buf, "%*s %d %d", &num, &ret);
            g_actions[g_cnt][0] = ACTION_LOWERBOUND;
            g_actions[g_cnt][1] = num;
            g_actions[g_cnt][2] = ret;
            ++g_cnt;
        }
    }
    fclose(testdata);
}

int main()
{
    load_test_data();

    STOPWATCH(basic_test);
    STOPWATCH(performance_test);

    return 0;
}