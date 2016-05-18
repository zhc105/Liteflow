#include <stdlib.h>
#include <inttypes.h>
#include <sys/time.h>

static inline int64_t get_curtime()
{
    struct timeval tv;
    int64_t cur_time;

    gettimeofday(&tv, NULL);
    cur_time = (int64_t)tv.tv_sec * 1000 + tv.tv_usec / 1000;

    return cur_time;
}
