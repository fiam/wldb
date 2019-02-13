#include <cstdint>
#include <cstring>

#include <wldb-types.h>
#include <wldb.h>

#include "gtest/gtest.h"

bool write_began = false;

#if !defined(PAGE_SIZE)
#define PAGE_SIZE 1024
#endif
#if !defined(BLOCK_SIZE)
#define BLOCK_SIZE 2048
#endif
#if !defined(BLOCK_COUNT)
#define BLOCK_COUNT 8
#endif

unsigned page_size = PAGE_SIZE;
unsigned block_size = BLOCK_SIZE;
unsigned block_count = BLOCK_COUNT;

uint8_t memory[BLOCK_SIZE * BLOCK_COUNT] __attribute__ ((aligned (PAGE_SIZE)));

unsigned memory_size = sizeof(memory);

#if defined(TEST_USE_ABSOLUTE_ADDR)
wldb_addr_t start = (wldb_addr_t)memory;
#else
wldb_addr_t start = 1;
#endif
wldb_addr_t end = start + sizeof(memory);


wldb_addr_t adjust_addr(wldb_addr_t addr)
{
#if !defined(TEST_USE_ABSOLUTE_ADDR)
    addr += (wldb_addr_t)memory - 1;
#endif
    return addr;
}

wldb_addr_t block_addr(unsigned n)
{
    return (wldb_addr_t)(start + block_size * n);
}

extern "C" int wldb_fs_read8(wldb_t *db, wldb_addr_t addr, uint8_t *val)
{
    uint8_t *p = (uint8_t *)adjust_addr(addr);
    *val = *p;
    return 0;
}

extern "C" int wldb_fs_erase_page(wldb_t *db, wldb_addr_t start, size_t size)
{
    if (!write_began) {
        return -128;
    }
    memset((void *)adjust_addr(start), 0xFF, size);
    return 0;
}

extern "C" int wldb_fs_write_data(wldb_t *db, wldb_addr_t addr, const void *src, size_t size)
{
    assert(size >= WLDB_WRITE_SIZE_MIN);
    assert(size % WLDB_WRITE_SIZE_MIN == 0);
#if defined(WLDB_WRITE_SIZE_MAX)
    assert(size <= WLDB_WRITE_SIZE_MAX);
#endif
    if (!write_began) {
        return -129;
    }
    void *dst = (void *)adjust_addr(addr);
    memcpy(dst, src, size);
    return size;
}

extern "C" int wldb_fs_write_begin(wldb_t *db)
{
    if (write_began) {
        return -130;
    }
    write_began = true;
    return 0;
}

extern "C" int wldb_fs_write_end(wldb_t *db)
{
    if (!write_began) {
        return -131;
    }
    write_began = false;
    return 0;
}

int main(int argc, char **argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    int ret = RUN_ALL_TESTS();
    assert(!write_began);
    return ret;
}
