#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "cache.h"

struct PageCache {
    uint8_t page_buffers[NUM_CACHED_PAGES][FSCRYPT_PAGE_SIZE] __attribute__((aligned(16)));
    uint64_t cached_page_offsets[NUM_CACHED_PAGES];
    uint32_t page_lru[NUM_CACHED_PAGES];
    uint64_t lru_counter;
    int last_slot;
};

static int page_cache_find_slot(struct PageCache* pc, uint64_t page_offset) {
    int slot = -1;

    if (pc->cached_page_offsets[pc->last_slot] == page_offset) {
        slot = pc->last_slot;
    } else {
        for (int i = 0; i < NUM_CACHED_PAGES; i++) {
            if (pc->cached_page_offsets[i] == page_offset) {
                slot = i;
                break;
            }
        }
    }

    return slot;
}

struct PageCache* page_cache_create() {
    struct PageCache* pc = calloc(1, sizeof(struct PageCache));

    if (pc == nullptr)
        return nullptr;

    for (int i = 0; i < NUM_CACHED_PAGES; i++) {
        pc->cached_page_offsets[i] = (uint64_t)-1;
        pc->page_lru[i] = 0;
    }

    return pc;
}

int page_cache_get(struct PageCache* pc, uint64_t page_offset, uint8_t buf[FSCRYPT_PAGE_SIZE]) {
    int slot = page_cache_find_slot(pc, page_offset);

    if (slot >= 0) {
        pc->page_lru[slot] = ++pc->lru_counter;
        pc->last_slot = slot;

        memcpy(buf, pc->page_buffers[slot], FSCRYPT_PAGE_SIZE);
    }

    return slot;
}

int page_cache_set(struct PageCache* pc, uint64_t page_offset, const uint8_t buf[FSCRYPT_PAGE_SIZE]) {
    int slot = 0;

    for (int i = 1; i < NUM_CACHED_PAGES; i++) {
        if (pc->page_lru[i] < pc->page_lru[slot]) slot = i;
    }

    memcpy(pc->page_buffers[slot], buf, FSCRYPT_PAGE_SIZE);
    pc->cached_page_offsets[slot] = page_offset;
    pc->page_lru[slot] = ++pc->lru_counter;
    pc->last_slot = slot;

    return slot;
}

int page_cache_evict(struct PageCache* pc, uint64_t page_offset) {
    int slot = page_cache_find_slot(pc, page_offset);

    if (slot >= 0) {
        memset(pc->page_buffers[slot], 0, FSCRYPT_PAGE_SIZE);
        pc->cached_page_offsets[slot] = (uint64_t)-1;
        pc->page_lru[slot] = 0;
    }

    return slot;
}
