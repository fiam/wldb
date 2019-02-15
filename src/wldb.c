#include <assert.h>
#include <stdbool.h>
#include <stdint.h>

#include <wldb.h>

#include "wldb-fs.h"
#include "wldb-log.h"

#define WLDB_HAS_BLOB_FLAG (1 << 7)
#define WLDB_RECORD_ENDS_WITH_DELETE_FLAG (1 << 6)
#define WLDB_PADDING_BYTE 63 // 63 is not a valid key length

#define BLOCK_N(s, b) ((unsigned)((b - s->start) / s->block_size))

#if defined(WLDB_USE_WRITE_BUFFER)
_Static_assert(WLDB_WRITE_SIZE_MIN <= WLDB_WRITE_SIZE_MAX, "WLDB_WRITE_SIZE_MIN > WLDB_WRITE_SIZE_MAX");
_Static_assert(WLDB_WRITE_SIZE_MAX % WLDB_WRITE_SIZE_MIN == 0, "WLDB_WRITE_SIZE_MAX % WLDB_WRITE_SIZE_MIN != 0");
#endif

static int wldb_read8(wldb_t *db, wldb_addr_t addr, uint8_t *val)
{
#if defined(WLDB_USE_WRITE_BUFFER)
    if (db->write_buffer_idx > 0 &&
        addr >= db->write_buffer_addr &&
        addr < db->write_buffer_addr + db->write_buffer_idx)
    {
        *val = db->write_buffer[addr - db->write_buffer_addr];
        return 0;
    }
#endif
    return wldb_fs_read8(db, addr, val);
}

static int wldb_read32(wldb_t *db, wldb_addr_t pos, uint32_t *val)
{
    int ret;
    uint8_t *ptr = (uint8_t *)val;
    for (size_t ii = 0; ii < sizeof(*val); ii++, pos++, ptr++)
    {
        if ((ret = wldb_read8(db, pos, ptr)) < 0)
        {
            return ret;
        }
    }
    return 0;
}

static int wldb_write_begin(wldb_t *db)
{
    return wldb_fs_write_begin(db);
}

static int wldb_write_end(wldb_t *db)
{
    return wldb_fs_write_end(db);
}

static int wldb_write_data(wldb_t *db, wldb_addr_t addr, const void *src, size_t size)
{
    return wldb_fs_write_data(db, addr, src, size);
}

#if defined(WLDB_USE_WRITE_BUFFER)
static int wldb_flush_write_buffer(wldb_t *db)
{
    int ret;

    if (db->write_buffer_idx > 0)
    {
        if ((ret = wldb_write_begin(db)) < 0)
        {
            return ret;
        }
        uint8_t *p = db->write_buffer;
        size_t written = 0;
        wldb_addr_t pos = db->write_buffer_addr;
        while (written < db->write_buffer_idx)
        {
            int req = db->write_buffer_idx - written;
#if defined(WLDB_WRITE_SIZE_MAX)
            if (req > WLDB_WRITE_SIZE_MAX)
            {
                req = WLDB_WRITE_SIZE_MAX;
            }
#endif
#if defined(WLDB_WRITE_SIZE_MIN)
            // We might need to add some padding. Since WLDB_WRITE_SIZE_MAX
            // has to be a multiple of WLDB_WRITE_SIZE_MIN, we always have
            // space at the end
            size_t min_write = (req + WLDB_WRITE_SIZE_MIN - 1) / WLDB_WRITE_SIZE_MIN * WLDB_WRITE_SIZE_MIN;
            while (req < min_write)
            {
                p[req] = WLDB_PADDING_BYTE;
                req += 1;
            }
#endif
            int n = wldb_write_data(db, pos, p, req);
            if (n < 0)
            {
                return n;
            }
            written += n;
            pos += n;
            p += n;
        }
        if ((ret = wldb_write_end(db)) < 0)
        {
            return ret;
        }
        db->block_free_start += written - db->write_buffer_idx;
        db->write_buffer_idx = 0;
    }
    return 0;
}
#endif

static int wldb_write(wldb_t *db, wldb_addr_t *pos, const void *src, size_t size)
{
    int ret;
    size_t rem = size;
    const uint8_t *p = (const uint8_t *)src;
#if defined(WLDB_USE_WRITE_BUFFER)
    if (db->write_buffer_idx > 0 && db->write_buffer_addr + db->write_buffer_idx != *pos)
    {
        if ((ret = wldb_flush_write_buffer(db)) < 0)
        {
            return ret;
        }
    }
    while (rem > 0)
    {
        if (db->write_buffer_idx == 0)
        {
            db->write_buffer_addr = *pos;
        }

        size_t n = rem;
        size_t bufrem = sizeof(db->write_buffer) - db->write_buffer_idx;
        if (bufrem < n)
        {
            n = bufrem;
        }
        memcpy(&db->write_buffer[db->write_buffer_idx], p, n);
        db->write_buffer_idx += n;

        if (db->write_buffer_idx == sizeof(db->write_buffer))
        {
            if ((ret = wldb_flush_write_buffer(db)) < 0)
            {
                return ret;
            }
        }

        rem -= n;
        (*pos) += n;
        p += n;
    }
#else
    if ((ret = wldb_write_begin(db)) < 0)
    {
        return ret;
    }
    while (rem > 0)
    {
#if defined(WLDB_WRITE_SIZE_MAX)
        size_t req = rem <= WLDB_WRITE_SIZE_MAX ? rem : WLDB_WRITE_SIZE_MAX;
#else
        size_t req = rem;
#endif
        int n = wldb_write_data(db, *pos, p, req);
        if (n < 0)
        {
            return n;
        }
        rem -= n;
        (*pos) += n;
        p += n;
    }
    if ((ret = wldb_write_end(db)) < 0)
    {
        return ret;
    }
#endif
    return 0;
}

static int wldb_write32(wldb_t *db, wldb_addr_t pos, uint32_t val)
{
    return wldb_write(db, &pos, &val, sizeof(val));
}

static int wldb_write8(wldb_t *db, wldb_addr_t pos, uint8_t val)
{
    return wldb_write(db, &pos, &val, sizeof(val));
}

static int wldb_decode_length(wldb_t *db, wldb_addr_t *pos, size_t *size)
{
    uint8_t c;
    int ret;

    if ((ret = wldb_read8(db, *pos, &c)) < 0)
    {
        return ret;
    }
    (*pos)++;

    if (c < 0x80)
    {
        *size = c;
    }
    else
    {
        *size = ((uint32_t)c) << 8;
        if ((ret = wldb_read8(db, *pos, &c)) < 0)
        {
            return ret;
        }
        (*pos)++;
        if (c >= 0x80)
        {
            // Bad data
            return WLDB_ERR_DATA_CORRUPTION;
        }
        *size |= c;
    }
    return 0;
}

static size_t wldb_encode_length(uint8_t *out, size_t size)
{
    if (size < 0x80)
    {
        *out = size;
        return 1;
    }
    assert(size < (1 << 15));
    *out = size & 0xFF;
    *(out + 1) = size >> 8;
    return 2;
}

static int wldb_record_is_well_formed(wldb_t *db, wldb_addr_t pos,
                                      size_t key_size, size_t blob_size, bool ends_with_delete)
{
    int ret;
    uint8_t c;

    if (blob_size > 0)
    {
        wldb_addr_t blob_end = pos + key_size + blob_size - 1;
        if ((ret = wldb_read8(db, blob_end, &c)) < 0)
        {
            return ret;
        }
        if ((ends_with_delete && c != WLDB_DELETED) ||
            (!ends_with_delete && c == WLDB_DELETED))
        {

            return 0;
        }
    }
    return 1;
}

typedef int (*wldb_block_iterator_t)(wldb_t *db, wldb_addr_t key_pos,
                                     size_t key_size, size_t blob_size,
                                     wldb_addr_t record_pos, size_t record_size,
                                     void *user_data);

// Returns:
// <0: error
//  0: end of iteration
// >0: reached free space
static int wldb_block_iterate(wldb_t *db,
                              wldb_addr_t *start, wldb_addr_t end,
                              wldb_block_iterator_t iter, void *user_data)
{
    int ret;
    uint8_t c;
    size_t key_size;
    size_t blob_size;
    // Skip magic marker
    wldb_addr_t pos = *start;
    while (pos < end)
    {
        if ((ret = wldb_read8(db, pos, &c)) < 0)
        {
            return ret;
        }

        if (c == WLDB_PADDING_BYTE)
        {
            // WLDB_PADDING_BYTE is not a valid key size
            pos++;
            continue;
        }

        // 0xff is not a valid key size, so if we find that
        // sequence we're at the free space
        if (c == WLDB_DELETED)
        {
            *start = pos;
            return 1;
        }
        size_t record_pos = pos;
        pos += 1;

        bool ends_with_delete = c & WLDB_RECORD_ENDS_WITH_DELETE_FLAG;
        c &= ~WLDB_RECORD_ENDS_WITH_DELETE_FLAG;

        if (c & WLDB_HAS_BLOB_FLAG)
        {
            key_size = c & ~WLDB_HAS_BLOB_FLAG;
            if ((ret = wldb_decode_length(db, &pos, &blob_size)) < 0)
            {
                return ret;
            }
        }
        else
        {
            key_size = c;
            blob_size = 0;
        }

        if (iter)
        {
            // Only call the iterator if the record is well formed
            if ((ret = wldb_record_is_well_formed(db, pos, key_size, blob_size, ends_with_delete)) < 0)
            {
                return ret;
            }
            if (ret > 0)
            {
                size_t key_pos = pos;
                size_t record_size = (pos - record_pos) + key_size + blob_size;
                if ((ret = iter(db, key_pos, key_size, blob_size, record_pos, record_size, user_data)) < 0)
                {
                    return ret;
                }
            }
        }
        pos += key_size + blob_size;
    }
    return 0;
}

static int wldb_find_freespace(wldb_t *db, wldb_addr_t *start)
{
    int ret;
    // Skip magic marker
    wldb_addr_t pos = *start + sizeof(uint32_t);
    wldb_addr_t end = *start + db->block_size;
    if ((ret = wldb_block_iterate(db, &pos, end, NULL, NULL)) <= 0)
    {
        if (ret == 0)
        {
            // No free space found
            return WLDB_ERR_NO_FREESPACE;
        }
        return ret;
    }
    *start = pos;
    return 0;
}

static int wldb_erase_block(wldb_t *db, wldb_addr_t start)
{
    int ret;

    wldb_addr_t end = start + db->block_size;
    for (wldb_addr_t cur = start; cur < end; cur += db->page_size)
    {
        WLDB_LOG("Erasing page at 0x%04x", (unsigned)cur);
        if ((ret = wldb_fs_erase_page(db, cur, db->page_size)) < 0)
        {
            return ret;
        }
    }
    return 0;
}

static int wldb_write_begin_and_erase_block(wldb_t *db, wldb_addr_t start)
{
    int ret;

    if ((ret = wldb_fs_write_begin(db)) < 0)
    {
        return ret;
    }

    if ((ret = wldb_erase_block(db, start)) < 0)
    {
        return ret;
    }

    if ((ret = wldb_fs_write_end(db)) < 0)
    {
        return ret;
    }

    return 0;
}

static int wldb_read(wldb_t *db, wldb_addr_t *pos, void *data, size_t size)
{
    int ret;

    uint8_t *out = (uint8_t *)data;
    for (size_t ii = 0; ii < size; ii++, (*pos)++, out++)
    {
        if ((ret = wldb_read8(db, *pos, out)) < 0)
        {
            return ret;
        }
    }
    return 0;
}

// Returns:
//  1 => empty
//  0 => not empty
//  <0 => error
static int wldb_block_is_empty(wldb_t *db, wldb_addr_t start)
{
    const wldb_addr_t end = start + db->block_size;
    const uint32_t deleted = ((uint32_t)WLDB_DELETED) << 24 | ((uint32_t)WLDB_DELETED) << 16 | ((uint32_t)WLDB_DELETED) << 8 | WLDB_DELETED;
    uint32_t val;
    int ret;

    for (wldb_addr_t p = start; p < end; p += sizeof(val))
    {
        if ((ret = wldb_read32(db, p, &val)) < 0)
        {
            WLDB_LOG("Error reading 4 bytes from 0x%04x: %d", (unsigned)p, ret);
            return ret;
        }
        if (val != deleted)
        {
            return 0;
        }
    }
    return 1;
}

static size_t wldb_record_size(const void *key, size_t key_size, const void *blob, size_t size)
{
    (void)key;

    size_t s = key_size + size;
    s += 1; // key length size
    if (blob && size > 0)
    {
        s += size < 0x80 ? 1 : 2; // blob length size
    }
    return s;
}

static int wldb_key_matches(wldb_t *db, wldb_addr_t pos, const void *k, size_t key_size)
{
    int ret;

    const uint8_t *key = (const uint8_t *)k;
    uint8_t c;
    for (size_t ii = 0; ii < key_size; ii++, pos++, key++)
    {
        if ((ret = wldb_read8(db, pos, &c)) < 0)
        {
            return ret;
        }
        if (c != *key)
        {
            // Key doesn't match
            return 0;
        }
    }
    return 1;
}

typedef struct wldb_read_iterator_data_s
{
    const void *key;
    size_t key_size;
    wldb_addr_t blob_pos;
    size_t blob_size;
    wldb_addr_t record_pos;
    size_t record_size;
} wldb_read_iterator_data_t;

int wldb_read_iterator(wldb_t *db, wldb_addr_t key_pos,
                       size_t key_size, size_t blob_size,
                       wldb_addr_t record_pos, size_t record_size,
                       void *user_data)
{
    int ret;
    wldb_read_iterator_data_t *data = (wldb_read_iterator_data_t *)user_data;

    if (data->key_size == key_size)
    {
        // < 0 is error, == 0 is no match
        if ((ret = wldb_key_matches(db, key_pos, data->key, key_size)) <= 0)
        {
            return ret;
        }
        data->blob_pos = key_pos + key_size;
        data->blob_size = blob_size;
        data->record_pos = record_pos;
        data->record_size = record_size;
    }
    return 0;
}

static int wldb_get_record(wldb_t *db,
                           wldb_addr_t start, wldb_addr_t end,
                           const void *key, size_t key_size,
                           wldb_addr_t *blob_pos, size_t *blob_size,
                           wldb_addr_t *record_pos, size_t *record_size)
{
    int ret;
    wldb_read_iterator_data_t data = {
        .key = key,
        .key_size = key_size,
    };

    if ((ret = wldb_block_iterate(db, &start, end,
                                  wldb_read_iterator, &data)) < 0)
    {

        return ret;
    }

    if (data.record_pos > 0)
    {
        if (blob_pos)
        {
            *blob_pos = data.blob_pos;
        }
        if (blob_size)
        {
            *blob_size = data.blob_size;
        }
        if (record_pos)
        {
            *record_pos = data.record_pos;
        }
        if (record_size)
        {
            *record_size = data.record_size;
        }
        return 1;
    }
    return 0;
}

static int wldb_set_record(wldb_t *db, wldb_addr_t *pos,
                           const void *key, size_t key_size,
                           const void *blob, size_t size)
{
    if (key_size == 0 || key_size > WLDB_KEY_SIZE_MAX)
    {
        return WLDB_ERR_INVALID_KEY_SIZE;
    }

    int ret;
    uint8_t length[2];
    const uint8_t *blobp = (const uint8_t *)blob;
    uint8_t key_length = (uint8_t)key_size;

    // Write header
    if (blob && size > 0)
    {
        key_length |= WLDB_HAS_BLOB_FLAG;
        if (blobp[size - 1] == WLDB_DELETED)
        {
            key_length |= WLDB_RECORD_ENDS_WITH_DELETE_FLAG;
        }
    }

    if ((ret = wldb_write(db, pos, &key_length, 1)) < 0)
    {
        return ret;
    }

    if (size > 0)
    {
        size_t enc_size = wldb_encode_length(length, size);
        if ((ret = wldb_write(db, pos, length, enc_size)) < 0)
        {
            return ret;
        }
    }

    // Write key and data
    if ((ret = wldb_write(db, pos, key, key_size)) < 0)
    {
        return ret;
    }
    if ((ret = wldb_write(db, pos, blob, size)) < 0)
    {
        return ret;
    }

    return 0;
}

typedef struct wldb_migration_iterator_data_s
{
    wldb_addr_t src_block_end;
    wldb_addr_t dst_block_start;
    wldb_addr_t dst_block_end;
    wldb_addr_t dst_block_pos;
} wldb_migration_iterator_data_t;

static int wldb_migration_iterator(wldb_t *db, wldb_addr_t key_pos,
                                   size_t key_size, size_t blob_size,
                                   wldb_addr_t record_pos, size_t record_size,
                                   void *user_data)
{
    int ret;
    wldb_migration_iterator_data_t *data = (wldb_migration_iterator_data_t *)user_data;
    uint8_t key[WLDB_KEY_SIZE_MAX];

    // Read the key
    if ((ret = wldb_read(db, &key_pos, key, key_size)) < 0)
    {
        return ret;
    }

    // Check if the destination block already has this key
    if ((ret = wldb_get_record(db, data->dst_block_start,
                               data->dst_block_end, key, key_size, NULL, NULL, NULL, NULL)) < 0)
    {

        return ret;
    }

    if (ret > 0)
    {
        // Destination block already has this key
        return 0;
    }

    // We need to migrate this key. Make sure we get the latest version of the data.
    wldb_addr_t blob_pos = key_pos + key_size;
    // Start searching after this record
    wldb_addr_t search_start = blob_pos + blob_size;
    if ((ret = wldb_get_record(db, search_start,
                               data->src_block_end, key, key_size, &blob_pos, &blob_size,
                               &record_pos, &record_size)) < 0)
    {

        return ret;
    }
    // record_pos and record_size now point to the record in the old block
    uint8_t c;
    for (size_t ii = 0; ii < record_size; ii++, record_pos++, data->dst_block_pos++)
    {
        if ((ret = wldb_read8(db, record_pos, &c)) < 0)
        {
            return ret;
        }
        if ((ret = wldb_write8(db, data->dst_block_pos, c)) < 0)
        {
            return ret;
        }
    }
    return 0;
}

static int wldb_migrate_block(wldb_t *db)
{
    int ret;

    // We always pick the next block, going back to the first
    // after we use the last one
    wldb_addr_t block = db->block;
    wldb_addr_t block_end = block + db->block_size;
    wldb_addr_t next_block = block_end;
    if (next_block >= db->end)
    {
        next_block = db->start;
    }
    // Erase the new block
    if (!wldb_block_is_empty(db, next_block))
    {
        wldb_erase_block(db, next_block);
    }
    // Reserve space for the magic number, we'll write it at the end
    wldb_addr_t pos = next_block + sizeof(uint32_t);
    wldb_migration_iterator_data_t data = {
        .src_block_end = block_end,
        .dst_block_start = pos,
        .dst_block_end = (wldb_addr_t)(next_block + db->block_size),
        .dst_block_pos = pos,
    };
    wldb_addr_t start = block + sizeof(uint32_t);
    if ((ret = wldb_block_iterate(db, &start, block_end,
                                  wldb_migration_iterator, (void *)&data)) < 0)
    {

        return ret;
    }
    if ((ret = wldb_write32(db, next_block, WLDB_MAGIC)) < 0)
    {
        return ret;
    }
    // Delete the old block and switch to the new one
    wldb_erase_block(db, db->block);
    db->block = next_block;
    db->block_free_start = data.dst_block_pos;
    return 0;
}

int wldb_init(wldb_t *db,
              wldb_addr_t start, wldb_addr_t end,
              size_t page_size, size_t block_size)
{

    wldb_addr_t db_size = end - start;
    WLDB_LOG("DB total size %u", (unsigned)db_size);

    if (db_size % page_size != 0)
    {
        WLDB_LOG("%s", "DB size is not a multiple of page size");
        return WLDB_ERR_INVALID_PAGE_SIZE;
    }
    if (db_size % block_size != 0)
    {
        WLDB_LOG("%s", "DB size is not a multiple of block size");
        return WLDB_ERR_INVALID_BLOCK_SIZE;
    }

    db->start = start;
    db->end = end;

    db->page_size = page_size;
    db->block_size = block_size;

    db->block = NULL;

#if defined(WLDB_USE_WRITE_BUFFER)
    db->write_buffer_addr = 0;
    db->write_buffer_idx = 0;
#endif

    unsigned blocks = db_size / db->block_size;
    wldb_addr_t ptr = start;
    uint32_t marker;
    int ret;

    for (unsigned ii = 0; ii < blocks; ii++, ptr += db->block_size)
    {
        if ((ret = wldb_read32(db, ptr, &marker)) < 0)
        {
            return ret;
        }
        WLDB_LOG("Block %u@0x%04x magic 0x%04x", ii, (unsigned)ptr, (unsigned)marker);
        if (marker == WLDB_MAGIC)
        {
            if (db->block)
            {
                // If we already have a valid block, one of them
                // must be a leftover. Since we pick the next block when
                // one is full, the previous one is the invalid one unless
                // it's the first one and we're checking the last
                if (db->block == start && ii == blocks - 1)
                {
                    WLDB_LOG("Erasing stale block %u@0x%04x",
                             BLOCK_N(db, ptr), (unsigned)ptr);
                    if ((ret = wldb_write_begin_and_erase_block(db, ptr)) < 0)
                    {
                        return ret;
                    }
                }
                else
                {
                    WLDB_LOG("Erasing stale block %u@0x%04x",
                             BLOCK_N(db, db->block), (unsigned)db->block);
                    if ((ret = wldb_write_begin_and_erase_block(db, db->block)) < 0)
                    {
                        return ret;
                    }
                    db->block = ptr;
                }
            }
            else
            {
                // No block found yet. Pick this one.
                db->block = ptr;
            }
        }
    }
    if (!db->block)
    {
        // No blocks initialized, pick one
        db->block = db->start;
#if defined(WLDB_HAS_RAND)
        unsigned chosen = wldb_rand() % blocks;
#else
        unsigned chosen = 0;
#endif
        db->block = start + (db->block_size * chosen);
        if ((ret = wldb_write32(db, db->block, WLDB_MAGIC)) < 0)
        {
            return ret;
        }
        if ((ret = wldb_commit(db)) < 0)
        {
            return ret;
        }
        WLDB_LOG("No valid blocks found, chose %u", chosen);
    }

    WLDB_LOG("Using block %u@0x%04x",
             BLOCK_N(db, db->block), (unsigned)db->block);

    db->block_free_start = db->block;

    if ((ret = wldb_find_freespace(db, &db->block_free_start)) < 0)
    {
        return ret;
    }

    WLDB_LOG("Free space starts at 0x%04x (%u bytes used)",
             (unsigned)db->block_free_start,
             (unsigned)(db->block_free_start - db->block));

    return 0;
}

int wldb_get(wldb_t *db,
             const void *key, size_t key_size,
             void *blob, size_t *size)
{
    int ret;
    wldb_addr_t blob_pos;
    size_t blob_size;
    wldb_addr_t start = db->block + sizeof(uint32_t);
    wldb_addr_t end = db->block_free_start;

    if ((ret = wldb_get_record(db, start, end, key, key_size,
                               &blob_pos, &blob_size, NULL, NULL)) < 0)
    {

        return ret;
    }
    if (ret > 0)
    {
        size_t cpy_size = blob ? (blob_size < *size ? blob_size : *size) : 0;
        if ((ret = wldb_read(db, &blob_pos, blob, cpy_size)) < 0)
        {
            return ret;
        }
        if (size)
        {
            *size = cpy_size;
        }
        return 1;
    }
    return 0;
}

int wldb_set(wldb_t *db,
             const void *key, size_t key_size,
             const void *blob, size_t size)
{
    int ret;

    size_t record_size = wldb_record_size(key, key_size, blob, size);
    if (wldb_get_free(db) < record_size)
    {
        // Move to another block
        if ((ret = wldb_migrate_block(db)) < 0)
        {
            return ret;
        }
        if (wldb_get_free(db) < record_size)
        {
            // We have no free space after doing a block migration
            return WLDB_ERR_NO_FREESPACE;
        }
    }
    return wldb_set_record(db, &db->block_free_start,
                           key, key_size, blob, size);
}

size_t wldb_get_free(wldb_t *db)
{
    return db->block_size - (db->block_free_start - db->block);
}

int wldb_commit(wldb_t *db)
{
#if defined(WLDB_USE_WRITE_BUFFER)
    return wldb_flush_write_buffer(db);
#else
    (void)db;

    return 0;
#endif
}

int wldb_format(wldb_t *db)
{
    int ret;
    wldb_addr_t db_size = db->end - db->start;
    unsigned blocks = db_size / db->block_size;
    wldb_addr_t ptr = db->start;

    for (unsigned ii = 0; ii < blocks; ii++, ptr += db->block_size)
    {
        if (!wldb_block_is_empty(db, ptr))
        {
            if ((ret = wldb_write_begin_and_erase_block(db, ptr)) < 0)
            {
                return ret;
            }
        }
    }

    return 0;
}
