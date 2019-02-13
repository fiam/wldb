#include <stdint.h>
#include <string.h>

#include <wldb.h>

#include <gtest/gtest.h>

extern unsigned page_size;
extern unsigned block_size;
extern unsigned block_count;

extern uint8_t memory[];
extern unsigned memory_size;
extern wldb_addr_t start;
extern wldb_addr_t end;

extern wldb_addr_t adjust_addr(wldb_addr_t addr);
extern wldb_addr_t block_addr(unsigned n);

TEST(T, TestBlockSelection) {
    wldb_t db;
    memset(memory, WLDB_DELETED, memory_size);

    EXPECT_EQ(wldb_init(&db, start, end, page_size, block_size), 0);
    EXPECT_EQ(db.block, start);

    EXPECT_EQ(wldb_init(&db, start, end, page_size, block_size), 0);
    EXPECT_EQ(db.block, start);

    wldb_addr_t last = block_addr(block_count - 1);
    *((uint32_t *)adjust_addr(last)) = WLDB_MAGIC;

    EXPECT_EQ(wldb_init(&db, start, end, page_size, block_size), 0);
    EXPECT_EQ(db.block, start);

    wldb_addr_t second = block_addr(1);
    *((uint32_t *)adjust_addr(second)) = WLDB_MAGIC;

    EXPECT_EQ(wldb_init(&db, start, end, page_size, block_size), 0);
    EXPECT_EQ(db.block, second);
}

TEST(T, TestWrite) {
    wldb_t db;
    memset(memory, WLDB_DELETED, memory_size);

    EXPECT_EQ(wldb_init(&db, start, end, page_size, block_size), 0);

    const char *key = "foobar";
    const char *data1 = "baz";
    size_t key_size = strlen(key);
    size_t data1_size = strlen(data1);

    size_t free_space = wldb_get_free(&db);

    EXPECT_EQ(wldb_set(&db, key, key_size, data1, data1_size), 0);
    EXPECT_EQ(wldb_get_free(&db), free_space - key_size - data1_size - 2);

    // Write a record that ends with WLDB_DELETED
    uint8_t data2[] = {WLDB_DELETED};
    size_t data2_size = sizeof(data2);
    free_space = wldb_get_free(&db);
    EXPECT_EQ(wldb_set(&db, key, key_size, data2, data2_size), 0);
    EXPECT_EQ(wldb_get_free(&db), free_space - key_size - data2_size - 2);

    // Write a record without data
    free_space = wldb_get_free(&db);
    EXPECT_EQ(wldb_set(&db, key, key_size, NULL, 0), 0);
    EXPECT_EQ(wldb_get_free(&db), free_space - key_size - 1);

    // Force re-advancing to the free space
    free_space = wldb_get_free(&db);
    EXPECT_EQ(wldb_init(&db, start, end, page_size, block_size), 0);
    EXPECT_EQ(wldb_get_free(&db), free_space);
}

TEST(T, TestWritePadding) {
    wldb_t db;
    memset(memory, WLDB_DELETED, memory_size);

    EXPECT_EQ(wldb_init(&db, start, end, page_size, block_size), 0);

    size_t free_space = wldb_get_free(&db);
    EXPECT_EQ(free_space, block_size - sizeof(uint32_t));

    uint8_t key[] = {0x11, 0x22};
    size_t key_size = sizeof(key);
    EXPECT_EQ(wldb_set(&db, key, key_size, NULL, 0), 0);

    size_t free_space2 = wldb_get_free(&db);
    EXPECT_EQ(free_space2, free_space - 3);

    EXPECT_EQ(wldb_commit(&db), 0);
    size_t free_space3 = wldb_get_free(&db);
#if WLDB_WRITE_SIZE_MIN == 1
    size_t expect_delta = 0;
#elif WLDB_WRITE_SIZE_MIN == 2
    size_t expect_delta = 1;
#else
    size_t expect_delta = WLDB_WRITE_SIZE_MIN - 3;
#endif
    EXPECT_EQ(free_space3, free_space2 - expect_delta);
}

TEST(T, TestWriteRead) {
    wldb_t db;
    memset(memory, WLDB_DELETED, memory_size);

    EXPECT_EQ(wldb_init(&db, start, end, page_size, block_size), 0);
    uint8_t buf[20];
    size_t bufsize;

    uint8_t key1[] = {0};
    size_t key1_size = sizeof(key1);
    uint8_t data1[] = {0x55, 0x55, 0x55};
    size_t data1_size = sizeof(data1);
    EXPECT_EQ(wldb_set(&db, key1, key1_size, data1, data1_size), 0);
    bufsize = sizeof(buf);
    EXPECT_GT(wldb_get(&db, key1, key1_size, buf, &bufsize), 0);
    EXPECT_EQ(bufsize, sizeof(data1));
    for (size_t ii = 0; ii < sizeof(data1); ii++) {
        EXPECT_EQ(buf[ii], data1[ii]);
    }

    uint8_t data2[] = {1, 2, 3, 4, 5};
    size_t data2_size = sizeof(data2);
    EXPECT_EQ(wldb_set(&db, key1, key1_size, data2, data2_size), 0);
    bufsize = sizeof(buf);
    EXPECT_GT(wldb_get(&db, key1, key1_size, buf, &bufsize), 0);
    EXPECT_EQ(bufsize, sizeof(data2));
    for (size_t ii = 0; ii < sizeof(data2); ii++) {
        EXPECT_EQ(buf[ii], data2[ii]);
    }

    EXPECT_EQ(wldb_set(&db, key1, key1_size, NULL, 0), 0);
    bufsize = sizeof(buf);
    EXPECT_GT(wldb_get(&db, key1, key1_size, buf, &bufsize), 0);
    EXPECT_EQ(bufsize, 0);

    // Read a non existing key without and with output
    uint8_t key2[] = {1};
    size_t key2_size = sizeof(key2);
    EXPECT_EQ(wldb_get(&db, key2, key2_size, NULL, NULL), 0);
    bufsize = sizeof(buf);
    EXPECT_EQ(wldb_get(&db, key2, key2_size, buf, &bufsize), 0);
}

TEST(T, TestBlockSwitch) {
    wldb_t db;
    memset(memory, WLDB_DELETED, memory_size);

    EXPECT_EQ(wldb_init(&db, start, end, page_size, block_size), 0);

    uint8_t key1[] = {0};
    size_t key1_size = sizeof(key1);

    uint8_t key2[] = {0};
    size_t key2_size = sizeof(key2);

    // Each record takes 4 bytes. Fill the block without triggering a rewrite
    size_t records_size = 8;
    size_t magic_size = 4; // Size of the marker
    wldb_addr_t block = db.block;
    uint8_t c = 0;
    for (int ii = 0; ii < (block_size - magic_size) / records_size; ii++) {
        EXPECT_EQ(wldb_set(&db, key1, key1_size, &c, 1), 0);
        c = c < 255 ? c + 1 : 0;
        EXPECT_EQ(wldb_set(&db, key2, key2_size, &c, 1), 0);
        c = c < 255 ? c + 1 : 0;
    }
    // Fill the remaining 4 bytes
    EXPECT_EQ(wldb_set(&db, key1, key1_size, &c, 1), 0);
    c = c < 255 ? c + 1 : 0;

    EXPECT_EQ(db.block, block);

    // This write triggers a block switch
    EXPECT_EQ(wldb_set(&db, key1, key1_size, &c, 1), 0);
    EXPECT_EQ(db.block, block + block_size);
    EXPECT_EQ(wldb_get_free(&db), block_size - magic_size - records_size);
}
