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

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <assert.h>
#include "hashqueue.h"

uint32_t hash(void *key)
{
    return *(uint32_t *)key;
}

int main()
{
    char buf[20];
    uint32_t key, i;
    hash_queue_t hq;
    hash_node_t *q_it;
    queue_init(&hq, 1013, sizeof(key), 20, hash);
    key = 1;
    strcpy(buf, "test1");
    queue_append(&hq, &key, buf);
    key = 5;
    strcpy(buf, "test2");
    queue_append(&hq, &key, buf);
    key = 1014;
    strcpy(buf, "test3");
    queue_append(&hq, &key, buf);
    key = 3;
    strcpy(buf, "test4");
    queue_append(&hq, &key, buf);
    key = 0;
    strcpy(buf, "test5");
    queue_append(&hq, &key, buf);
    i = 0;
    for (q_it = queue_first(&hq); q_it; q_it = queue_next(&hq, q_it)) { 
        printf("%u: %u - %s\n", ++i, *(uint32_t *)queue_key(&hq, q_it), 
            (char *)queue_value(&hq, q_it));
    }
    printf("===========================\n");
    key = 6;
    strcpy(buf, "test6");
    queue_append(&hq, &key, buf);
    key = 8;
    strcpy(buf, "test7");
    queue_append(&hq, &key, buf);
    key = 3;
    strcpy(buf, "test8");
    queue_append(&hq, &key, buf);
    i = 0;
    for (q_it = queue_first(&hq); q_it; q_it = queue_next(&hq, q_it)) { 
        printf("%u: %u - %s\n", ++i, *(uint32_t *)queue_key(&hq, q_it), 
            (char *)queue_value(&hq, q_it));
    }
    printf("===========================\n");
    key = 8;
    queue_move_front(&hq, &key);
    key = 1;
    queue_move_back(&hq, &key);
    i = 0;
    for (q_it = queue_first(&hq); q_it; q_it = queue_next(&hq, q_it)) { 
        printf("%u: %u - %s\n", ++i, *(uint32_t *)queue_key(&hq, q_it), 
            (char *)queue_value(&hq, q_it));
    }
    printf("===========================\n");
    key = 5;
    queue_del(&hq, &key);
    key = 3;
    queue_del(&hq, &key);
    key = 1;
    queue_del(&hq, &key);
    i = 0;
    for (q_it = queue_first(&hq); q_it; q_it = queue_next(&hq, q_it)) { 
        printf("%u: %u - %s\n", ++i, *(uint32_t *)queue_key(&hq, q_it), 
            (char *)queue_value(&hq, q_it));
    }
    printf("===========================\n");
    key = 1014;
    queue_del(&hq, &key);
    i = 0;
    for (q_it = queue_first(&hq); q_it; q_it = queue_next(&hq, q_it)) { 
        printf("%u: %u - %s\n", ++i, *(uint32_t *)queue_key(&hq, q_it), 
            (char *)queue_value(&hq, q_it));
    }
    printf("===========================\n");
    return 0;
}
