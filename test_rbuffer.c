#include "rbuffer.h"
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <assert.h>

int main() 
{
    char buf[10000], buf2[10000], test_buf[2][10000];
    int len, i, ret;
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

    for (i = 0; i < 10; i++) {
        len = rbuf_read_front(&rbuf, buf, 256);
        printf("%d %.*s\n", len, len, buf);
        rbuf_release(&rbuf, 1);
    }
    len = rbuf_read_front(&rbuf, buf, 256);
    printf("%d %.*s\n", len, len, buf);

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
    return 0;
}
