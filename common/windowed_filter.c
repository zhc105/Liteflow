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

#include "windowed_filter.h"

#define likely(x)      __builtin_expect(!!(x), 1)
#define unlikely(x)    __builtin_expect(!!(x), 0)

static uint32_t filter_update(windowed_filter_t *f, const filter_sample_t *val)
{
    uint32_t dt = val->t - f->s[0].t;

	if (unlikely(dt > f->win)) {
		f->s[0] = f->s[1];
		f->s[1] = f->s[2];
		f->s[2] = *val;
		if (unlikely(val->t - f->s[0].t > f->win)) {
			f->s[0] = f->s[1];
			f->s[1] = f->s[2];
			f->s[2] = *val;
		}
	} else if (unlikely(f->s[1].t == f->s[0].t) && dt > f->win >> 2) {
		f->s[2] = f->s[1] = *val;
	} else if (unlikely(f->s[2].t == f->s[1].t) && dt > f->win >> 1) {
		f->s[2] = *val;
	}

	return f->s[0].v;
}

uint32_t filter_update_max(windowed_filter_t *f, uint32_t t, uint32_t meas)
{
    filter_sample_t val = { .t = t, .v = meas };

	if (unlikely(val.v >= f->s[0].v) ||	unlikely(val.t - f->s[2].t > f->win))
		return filter_reset(f, t, meas);

	if (unlikely(val.v >= f->s[1].v))
		f->s[2] = f->s[1] = val;
	else if (unlikely(val.v >= f->s[2].v))
		f->s[2] = val;

	return filter_update(f, &val);
}

uint32_t filter_update_min(windowed_filter_t *f, uint32_t t, uint32_t meas)
{
	filter_sample_t val = { .t = t, .v = meas };

	if (unlikely(val.v <= f->s[0].v) || unlikely(val.t - f->s[2].t > f->win))
		return filter_reset(f, t, meas);

	if (unlikely(val.v <= f->s[1].v))
		f->s[2] = f->s[1] = val;
	else if (unlikely(val.v <= f->s[2].v))
		f->s[2] = val;

	return filter_update(f, &val);
}