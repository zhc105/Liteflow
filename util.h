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

#ifndef _UTIL_H_
#define _UTIL_H_
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <sys/time.h>
#include <time.h>
#include "config.h"

#define MSEC_PER_SEC    1000
#define USEC_PER_MSEC   1000
#define USEC_PER_SEC    1000000

#define DBG(fmt, ...)                                                   \
    do {                                                                \
        if (!g_config.debug_log)                                        \
            break;                                                      \
        char timestr[20];                                               \
        time_t now = time(NULL);                                        \
        strftime(timestr, 20, "%Y-%m-%d %H:%M:%S", localtime(&now));    \
        fprintf(stdout, "[%s] " fmt, timestr, ## __VA_ARGS__);          \
        fflush(stdout);                                                 \
    } while (0)                                                         

#define LOG(fmt, ...)                                                   \
    do {                                                                \
        char timestr[20];                                               \
        time_t now = time(NULL);                                        \
        strftime(timestr, 20, "%Y-%m-%d %H:%M:%S", localtime(&now));    \
        fprintf(stdout, "[%s] " fmt, timestr, ## __VA_ARGS__);          \
        fflush(stdout);                                                 \
    } while (0)                                                         

#define LESS_EQUAL(a, b) ((uint32_t)(b) - (uint32_t)(a) < 0x80000000u)
#define BEFORE(a, b) (LESS_EQUAL(a, b) && (a) != (b))
#define AFTER(a, b) (!LESS_EQUAL(a, b))
#define MAX(a, b) ((a) > (b) ? (a) : (b))
#define MIN(a, b) ((a) < (b) ? (a) : (b))

#define likely(x)      __builtin_expect(!!(x), 1)
#define unlikely(x)    __builtin_expect(!!(x), 0)

static inline int64_t get_curtime()
{
    int64_t cur_time;
    struct timespec tp;
    clock_gettime(CLOCK_MONOTONIC, &tp);
    cur_time = (int64_t)tp.tv_sec * USEC_PER_SEC + tp.tv_nsec / 1000;

    return cur_time;
}

static int seq_cmp(void *a, void *b)
{
    if (LESS_EQUAL(*(uint32_t *)a, *(uint32_t *)b)) {
        if (*(uint32_t *)a == *(uint32_t *)b)
            return 0;
        return -1;
    }
    return 1;
}

#endif
