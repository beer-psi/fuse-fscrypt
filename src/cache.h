#pragma once

#include <stdint.h>

#define NUM_CACHED_PAGES 256
#define FSCRYPT_PAGE_SIZE 4096U

struct PageCache;

/** Creates a page cache. */
struct PageCache* page_cache_create();

/**
 * Gets a page from the page cache from the given @page_offset.
 * If the page is in cache, copies the cached content to buf and returns a non-negative value.
 * If the page is not in cache, returns a negative value.
 */
int page_cache_get(struct PageCache* pc, uint64_t page_offset, uint8_t buf[FSCRYPT_PAGE_SIZE]);

/**
 * Replaces the least recently used page with the provided page.
 */
int page_cache_set(struct PageCache* pc, uint64_t page_offset, const uint8_t buf[FSCRYPT_PAGE_SIZE]);

/**
 * Evicts the page at @page_offset from the page cache. Returns a non-negative value if the page
 * was in the page cache.
 */
int page_cache_evict(struct PageCache* pc, uint64_t page_offset);
