#pragma once

#include <stddef.h>
#include <stdint.h>

#include <wldb-types.h>

#if !defined(WLDB_MAGIC)
#define WLDB_MAGIC 0xc01dface
#endif

#define WLDB_DELETED 0xff

#if !defined(WLDB_KEY_SIZE_MAX)
#define WLDB_KEY_SIZE_MAX 32
#endif

#if WLDB_KEY_SIZE_MAX > 62
#error WLDB_KEY_SIZE_MAX is too big
#endif

#if !defined(WLDB_WRITE_SIZE_MIN)
#define WLDB_WRITE_SIZE_MIN 1
#endif

#if !defined(WLDB_WRITE_SIZE_MAX) && WLDB_WRITE_SIZE_MIN > 1
#define WLDB_WRITE_SIZE_MAX WLDB_WRITE_SIZE_MIN
#endif

#if WLDB_WRITE_SIZE_MIN > 1 || WLDB_WRITE_SIZE_MAX > 1
#define WLDB_USE_WRITE_BUFFER
#endif

enum
{
    WLDB_ERR_INVALID_PAGE_SIZE = -2,
    WLDB_ERR_INVALID_BLOCK_SIZE = -3,
    WLDB_ERR_DATA_CORRUPTION = -4,
    WLDB_ERR_INVALID_KEY_SIZE = -5,
    WLDB_ERR_NO_FREESPACE = -6,
};

#if defined(__cplusplus)
extern "C"
{
#endif

    typedef struct wldb_s
    {
        wldb_addr_t start;
        wldb_addr_t end;
        size_t page_size;
        size_t block_size;

        wldb_addr_t block;
        wldb_addr_t block_free_start;
#if defined(WLDB_USE_WRITE_BUFFER)
        wldb_addr_t write_buffer_addr;
        uint8_t write_buffer[WLDB_WRITE_SIZE_MAX];
        uint8_t write_buffer_idx;
#endif
#if defined(WLDB_USE_CONTEXT)
        void *context;
#endif
    } wldb_t;

    int wldb_init(wldb_t *db,
                  wldb_addr_t start, wldb_addr_t end,
                  size_t page_size, size_t block_size);

    int wldb_get(wldb_t *db,
                 const void *key, size_t key_size,
                 void *blob, size_t *size);

    int wldb_set(wldb_t *db,
                 const void *key, size_t key_size,
                 const void *blob, size_t size);

    size_t wldb_get_free(wldb_t *db);

    int wldb_commit(wldb_t *db);

    int wldb_format(wldb_t *db);

#if defined(__cplusplus)
}
#endif