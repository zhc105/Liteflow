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

#ifndef _WINDOWED_FILTER_H_
#define _WINDOWED_FILTER_H_

#include <stdint.h>
#include <string.h>

typedef struct _filter_sample {
    uint32_t t;
    uint32_t v;
} filter_sample_t;

typedef struct _windowed_filter {
    filter_sample_t s[3];
    uint32_t win;
} windowed_filter_t;

static inline void filter_init(windowed_filter_t *f, uint32_t win)
{
    memset(f, 0, sizeof(windowed_filter_t));
    f->win = win;
}

static inline uint32_t filter_get(const windowed_filter_t *f)
{
    return f->s[0].v;
}

static inline int filter_expired(const windowed_filter_t *f, uint32_t t)
{
    if (t - f->s[0].t > f->win)
        return 1;
    return 0;
}

static inline uint32_t filter_reset(
    windowed_filter_t *f, uint32_t t, uint32_t meas)
{
    filter_sample_t val = { .t = t, .v = meas };
    f->s[2] = f->s[1] = f->s[0] = val;
    return f->s[0].v;
}

uint32_t filter_update_max(windowed_filter_t *f, uint32_t t, uint32_t meas);
uint32_t filter_update_min(windowed_filter_t *f, uint32_t t, uint32_t meas);

#endif