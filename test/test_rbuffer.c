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
#include "rbuffer.h"

int main() 
{
    char buf[10000], buf2[10000], test_buf[2][10000];
    int len, i, j, ret;
    uint64_t test_bytes;
    rbuf_t rbuf;
    rbuf_init(&rbuf, 100);

    rbuf_write(&rbuf, 10, "hello world", 11);
    rbuf_write(&rbuf, 524388, "test~test~", 10);
    rbuf_write(&rbuf, 200, "test word1", 10);
    rbuf_write(&rbuf, 0, "test word2", 10);

    len = rbuf_read(&rbuf, 0, buf, 256);
    printf("%d %.*s\n", len, len, buf);
    len = rbuf_read(&rbuf, 10, buf, 256);
    printf("%d %.*s\n", len, len, buf);
    len = rbuf_read(&rbuf, 200, buf, 256);
    printf("%d %.*s\n", len, len, buf);
    len = rbuf_read(&rbuf, 524388, buf, 256);
    printf("%d %.*s\n", len, len, buf);

    for (i = 0; i < 21; i++) {
        len = rbuf_read_front(&rbuf, buf, 256);
        printf("%d %.*s\n", len, len, buf);
        rbuf_release(&rbuf, 1);
    }

    len = rbuf_read_front(&rbuf, buf, 256);
    printf("%d %.*s\n", len, len, buf);
    rbuf_write(&rbuf, 21, "append new", 10);
    ret = rbuf_write(&rbuf, 10, "wrong", 5);
    printf("wrong write: %d\n", ret);
    ret = rbuf_write(&rbuf, 21, "repeat", 6);
    printf("repeat write: %d\n", ret);
    ret = rbuf_write(&rbuf, 22, "repeat", 6);
    printf("repeat write: %d\n", ret);

    for (i = 0; i < 10; i++) {
        len = rbuf_read_front(&rbuf, buf, 256);
        printf("%d %.*s\n", len, len, buf);
        rbuf_release(&rbuf, 1);
    }
    len = rbuf_read_front(&rbuf, buf, 256);
    printf("%d %.*s\n", len, len, buf);

    printf("\n5GB Read/Write test...\n");
    rbuf_fini(&rbuf);
    // test 5GB continuous read/write
    rbuf_init(&rbuf, 100);
    test_bytes = 0;
    srand(time(NULL));
    for (i = 0; i < 10000; i++) {
        test_buf[0][i] = rand() & 0xFF;
        test_buf[1][i] = rand() & 0xFF;
    }

    i = 0;
    while (test_bytes < 5368709120ll) {
        uint32_t len;
        rbuf_write_front(&rbuf, test_buf[i], 10000);
        assert(rbuf_readable_bytes(&rbuf) == 10000);
        len = rbuf_read_front(&rbuf, buf2, 10000);
        assert(len == 10000);
        rbuf_release(&rbuf, 10000);
        assert(rbuf_readable_bytes(&rbuf) == 0);
        assert(memcmp(test_buf[i], buf2, 10000) == 0);
        test_bytes += 10000;
        i ^= 1;
        if (test_bytes % 104857600 < 10000)
            printf("test read/write %"PRIu64" bytes ok...\n", test_bytes);
    }

    rbuf_fini(&rbuf);

    // test 5GB continuous read twice/write twice
    printf("\n5GB Read/Write test 2nd...\n");
    rbuf_init(&rbuf, 100);
    test_bytes = 0;
    srand(time(NULL));
    for (i = 0; i < 10000; i++) {
        test_buf[0][i] = rand() & 0xFF;
        test_buf[1][i] = rand() & 0xFF;
    }

    i = j = 0;
    while (test_bytes < 5368709120ll) {
        uint32_t len;
        while (rbuf_readable_bytes(&rbuf) < 10485760) {
            rbuf_write_front(&rbuf, test_buf[i], 10000);
            i ^= 1;
            test_bytes += 10000;
        }
        
        len = rbuf_read_front(&rbuf, buf2, 10000);
        assert(len == 10000);
        rbuf_release(&rbuf, 10000);
        assert(memcmp(test_buf[j], buf2, 10000) == 0);
        j ^= 1;

        if (test_bytes % 104857600 < 10000)
            printf("test read/write %"PRIu64" bytes ok...\n", test_bytes);
    }

    rbuf_fini(&rbuf);
    return 0;
}
