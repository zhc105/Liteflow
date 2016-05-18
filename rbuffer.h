#ifndef _RBUFFER_H_
#define _RBUFFER_H_

#include <stddef.h>
#include <stdint.h>
#include "list.h"

#define RBUF_BLOCK_SIZE 102400 

#define RBUF_OUT_OF_RANGE -100

typedef struct _rbuf_blk rbuf_blk_t;

typedef struct _rbuf {
    uint32_t start_pos;
    uint32_t write_pos;
    uint32_t block_offset;
    uint32_t buf_used;
    uint32_t max_block_num;
    int block_num;
    rbuf_blk_t **blk_tab;
} rbuf_t;

int rbuf_init(rbuf_t *rbuf, int max_blk_num);
int rbuf_write(rbuf_t *rbuf, uint32_t pos, const char *data, uint32_t data_len);
int rbuf_read(rbuf_t *rbuf, uint32_t pos, char *data, uint32_t data_len);
int rbuf_write_front(rbuf_t *rbuf, const char *data, uint32_t data_size);
int rbuf_read_front(rbuf_t *rbuf, char *data, uint32_t data_size);
void rbuf_window_info(rbuf_t *rbuf, uint32_t *win_start, uint32_t *win_size);
uint32_t rbuf_readable_bytes(rbuf_t *rbuf);
uint32_t rbuf_writable_bytes(rbuf_t *rbuf);
uint32_t rbuf_write_pos(rbuf_t *rbuf);
void rbuf_release(rbuf_t *rbuf, uint32_t r_size);
void rbuf_fini(rbuf_t *rbuf);

#endif
