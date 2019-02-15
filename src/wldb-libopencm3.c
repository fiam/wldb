#include <stddef.h>
#include <stdint.h>

#include <libopencm3/stm32/flash.h>

#include <wldb-types.h>

// Use WLDB_WRITE_SIZE_MIN = 2

int wldb_fs_erase_page(wldb_t *db, wldb_addr_t start, size_t size)
{
    (void)db;
    (void)size;

    flash_unlock();
    flash_erase_page((uint32_t)start);
    flash_lock();
    return 0;
}

int wldb_fs_write_begin(wldb_t *db, wldb_addr_t addr)
{
    (void)db;
    (void)addr;

    flash_unlock();
    return 0;
}

int wldb_fs_write_end(wldb_t *db, wldb_addr_t addr)
{
    (void)db;
    (void)addr;

    flash_lock();
    return 0;
}

int wldb_fs_write_data(wldb_t *db, wldb_addr_t addr, const void *src, size_t size)
{
    (void)db;

    const uint16_t *p = (const uint16_t *)src;
    for (size_t ii = 0; ii < size; ii += 2, p++)
    {
        flash_program_half_word((uint32_t)addr, *p);
    }
    return 0;
}
