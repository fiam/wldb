#pragma once

#if defined(__cplusplus)
#define EXTERN_C extern "C"
#else
#define EXTERN_C
#endif

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <wldb-types.h>

typedef struct wldb_s wldb_t;

EXTERN_C int wldb_fs_erase_page(wldb_t *db, wldb_addr_t start, size_t size);

#if defined(WLDB_FS_DIRECT_READ)
static int wldb_fs_read8(wldb_t *db, wldb_addr_t addr, uint8_t *val)
{
    (void)db;

    uint8_t *p = (uint8_t *)addr;
    *val = *p;
    return 0;
}

#else
EXTERN_C int wldb_fs_read8(wldb_t *db, wldb_addr_t addr, uint8_t *val);
#endif

#if defined(WLDB_FS_DIRECT_WRITE)
static int wldb_fs_write_begin(wldb_t *db)
{
    (void)db;

    return 0;
}

static int wldb_fs_write_end(wldb_t *db)
{
    (void)db;

    return 0;
}

static int wldb_fs_write_data(wldb_t *db, wldb_addr_t addr, const void *src, size_t size)
{
    (void)db;

    void *dst = (void *)addr;
    memcpy(dst, src, size);
    return size;
}
#else
EXTERN_C int wldb_fs_write_begin(wldb_t *db);
EXTERN_C int wldb_fs_write_end(wldb_t *db);
EXTERN_C int wldb_fs_write_data(wldb_t *db, wldb_addr_t addr, const void *src, size_t size);
#endif
