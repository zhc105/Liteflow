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
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <assert.h>
#include "list.h"
#include "test_helper.h"
#include "timerlist.h"

#define ACTION_ADD      1
#define ACTION_DEL      2
#define ACTION_VALIDATE 3
#define ACTION_GET      4

int32_t g_actions[10000][3] = {};
list_head_t g_list[10000];
size_t g_cnt = 0;

typedef struct _time_item {
    list_head_t list;
    int64_t time;
} time_item_t;


uint32_t hash(const void *key)
{
    return *(uint32_t*)key;
}

void validate(timerlist_t *tq, timerlist_t *alt_tq, uint32_t cnt, int line)
{
    /* verify timer_list is in order and move all elements from tq to alt_tq */
    if (timerlist_size(tq) != cnt) {
        printf("[LINE %d] Assert failure, elements count of timer list was "
            "not match: expect = %u, actual = %u\n", 
            line, cnt, timerlist_size(tq));
        assert(0);
    }

    int ret;
    int64_t min = -INT32_MAX;
    uint32_t found = 0;
    while (!timerlist_empty(tq)) {
        int64_t time = 0;
        int32_t key; 
        
        if (timerlist_top(tq, &time, &key) == NULL) {
            printf("[LINE %d] Assert failure, timer_top returns NULL", line);
            assert(0);
        }

        if (time < min) {
            printf("[LINE %d] Assert failure, order of elements in timer "
                "list was wrong\n", line);
            assert(0);
        }

        min = time;
        timerlist_pop(tq);
        ret = timerlist_push(alt_tq, time, &key, &key);
        if (ret != 0) {
            printf("[LINE %d] Failed to push data to alt timer list\n", line);
        }

        ++found;
    }

    if (found != cnt) {
        printf("[LINE %d] Assert failure, not all elements were found in list"
                ": expect = %u, actual = %u\n", line, cnt, found);
        assert(0);
    }
}

void basic_test()
{
    timerlist_t timer_list[2];
    timer_node_t *node;
    int ret = 0, curr = 0;
    
    timerlist_init(
        &timer_list[0], 1003, sizeof(uint32_t), sizeof(uint32_t), hash);
    timerlist_init(
        &timer_list[1], 1003, sizeof(uint32_t), sizeof(uint32_t), hash);

    for (int i = 0; i < g_cnt; ++i) {
        switch (g_actions[i][0])
        {
        case ACTION_ADD:
            {
                uint32_t kv = (uint32_t)g_actions[i][2];
                ret = timerlist_push(
                    &timer_list[curr], g_actions[i][1], &kv, &kv);
                if (ret != 0) {
                    printf("[LINE %d] Assert failure on push: expect = %d, "
                        "actual = %d\n", i, 0, ret);
                    assert(0);
                }
                break;
            }
        case ACTION_DEL:
            ret = timerlist_delete(&timer_list[curr], &g_actions[i][1]);
            if (ret != g_actions[i][2]) {
                printf("[LINE %d] Assert failure on delete: expect = %d, "
                    "actual = %d\n", i, g_actions[i][2], ret);
                assert(0);
            }
            break;
        case ACTION_VALIDATE:
            validate(
                &timer_list[curr],
                &timer_list[curr ^ 1],
                (uint32_t)g_actions[i][1],
                i);

            curr ^= 1;
            break;
        case ACTION_GET:
            node = timerlist_find_first(&timer_list[curr], &g_actions[i][1]);
            if (g_actions[i][2]) {
                if (node == NULL) {
                    printf("[LINE %d] Assert failure node != NULL\n", i);
                    assert(node != NULL);
                }

                do {
                    int64_t exptime = timerlist_time(&timer_list[curr], node);
                    list_head_t *now = g_list[i].next;
                    int found = 0;
                    for (; now != &g_list[i]; now = now->next) {
                        time_item_t *item = list_entry(now, time_item_t, list);
                        if (item->time == exptime) {
                            found = 1;
                            list_del(now);
                            free(item);
                            break;
                        }
                    }

                    if (!found) {
                        printf("[LINE %d] Assert failure key=%u time=%"PRId64
                            " not found\n", i, g_actions[i][1], exptime);
                        assert(0);
                    }

                    node = timerlist_find_next(&timer_list[curr], node);
                } while (node != NULL);
            } else {
                if (node != NULL) {
                    printf("[LINE %d] Assert failure node == NULL\n", i);
                    assert(node == NULL);
                }
            }

            assert(list_empty(&g_list[i]));
            break;
        default:
            break;
        }
        //printf("Line %d done\n", i);
    }

    timerlist_fini(&timer_list[0]);
    timerlist_fini(&timer_list[1]);
}

void performance_test()
{
    timerlist_t tq;
    int32_t i;
    timerlist_init(&tq, 1000003, sizeof(uint32_t), sizeof(uint32_t), hash);
    for (i = 0; i < 1000000; ++i)
        timerlist_push(&tq, i, &i, &i);
    assert(timerlist_size(&tq) == 1000000);
    for (i = 0; i < 1000000; i += 2)
        timerlist_delete(&tq, &i);
    assert(timerlist_size(&tq) == 500000);
    for (i = 1000000; i < 1500000; ++i)
        timerlist_push(&tq, i, &i, &i);
    assert(timerlist_size(&tq) == 1000000);
    timerlist_fini(&tq);

    timerlist_init(&tq, 1000003, sizeof(uint32_t), sizeof(uint32_t), hash);
    for (i = 1000000; i > 0; --i)
        timerlist_push(&tq, i, &i, &i);
    assert(timerlist_size(&tq) == 1000000);
    for (i = 1000000; i > 0; i -= 2)
        timerlist_delete(&tq, &i);
    assert(timerlist_size(&tq) == 500000);
    for (i = 1500000; i > 1000000; --i)
        timerlist_push(&tq, i, &i, &i);
    assert(timerlist_size(&tq) == 1000000);
    timerlist_fini(&tq);
}

void load_test_data()
{
    char buf[1024];
    FILE *testdata = fopen("testdata/timerlist_testdata.txt", "r");
    while (fgets(buf, sizeof(buf) - 1, testdata) != NULL) {
        if (!strncmp(buf, "add", 3)) {
            int num = 0, time = 0;
            sscanf(buf, "%*s %d %d", &time, &num);
            g_actions[g_cnt][0] = ACTION_ADD;
            g_actions[g_cnt][1] = time;
            g_actions[g_cnt][2] = num;
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
        } else if (!strncmp(buf, "get", 3)) {
            int num = 0, cnt = 0, i;
            char str[1024] = {};
            char *token, *pstr = str;
            sscanf(buf, "%*s %d %d %s", &num, &cnt, str);
            g_actions[g_cnt][0] = ACTION_GET;
            g_actions[g_cnt][1] = num;
            g_actions[g_cnt][2] = cnt;
            INIT_LIST_HEAD(&g_list[g_cnt]);
            while (cnt > 0 && (token = strsep(&pstr, ",")) != NULL) {
                time_item_t *item = (time_item_t *)malloc(sizeof(time_item_t));
                item->time = atoi(token);
                list_add_tail(&item->list, &g_list[g_cnt]);
                --cnt;
            }
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