#include "../../virtualizer.h"
#include <cstdio>
#include <cstring>

static int failures = 0;

static VIRT_CacheEntry g_cache[128];
static uint32_t g_cache_count = 0;

static void reset_cache() {
    g_cache_count = 0;
    memset(g_cache, 0, sizeof(g_cache));
}

static void test_insert_and_lookup() {
    reset_cache();

    int rc = virt_cache_insert(g_cache, &g_cache_count, 128,
                               "/proc/self/maps", 15, true, VIRT_ACTION_BLOCK_ENOENT);
    if (rc < 0) {
        printf("FAIL: cache insert rc=%d\n", rc);
        failures++;
        return;
    }
    if (g_cache_count != 1) {
        printf("FAIL: cache count should be 1, got %u\n", g_cache_count);
        failures++;
        return;
    }

    int cached = virt_cache_lookup(g_cache, g_cache_count, "/proc/self/maps", 15);
    if (cached != VIRT_ACTION_BLOCK_ENOENT) {
        printf("FAIL: cache lookup expected BLOCK_ENOENT, got %d\n", cached);
        failures++;
    } else {
        printf("PASS: cache insert and lookup\n");
    }
}

static void test_cache_miss() {
    reset_cache();

    virt_cache_insert(g_cache, &g_cache_count, 128,
                      "/proc/self/maps", 15, true, VIRT_ACTION_BLOCK_ENOENT);

    int cached = virt_cache_lookup(g_cache, g_cache_count, "/proc/self/status", 17);
    if (cached >= 0) {
        printf("FAIL: cache miss should return negative, got %d\n", cached);
        failures++;
    } else {
        printf("PASS: cache miss\n");
    }
}

static void test_non_sensitive_entry() {
    reset_cache();

    virt_cache_insert(g_cache, &g_cache_count, 128,
                      "/proc/self/maps", 15, false, VIRT_ACTION_BLOCK_ENOENT);

    int cached = virt_cache_lookup(g_cache, g_cache_count, "/proc/self/maps", 15);
    if (cached != VIRT_ACTION_PASS_THROUGH) {
        printf("FAIL: non-sensitive cache should return PASS_THROUGH, got %d\n", cached);
        failures++;
    } else {
        printf("PASS: non-sensitive cache entry\n");
    }
}

static void test_cache_eviction() {
    reset_cache();

    for (uint32_t i = 0; i < 10; i++) {
        char path[32];
        snprintf(path, sizeof(path), "/test/path/%u", i);
        virt_cache_insert(g_cache, &g_cache_count, 5,
                          path, (uint32_t)strlen(path), true, VIRT_ACTION_BLOCK_ENOENT);
    }

    if (g_cache_count != 5) {
        printf("FAIL: cache eviction should keep 5, got %u\n", g_cache_count);
        failures++;
        return;
    }

    int cached = virt_cache_lookup(g_cache, g_cache_count, "/test/path/0", 12);
    if (cached >= 0) {
        printf("FAIL: evicted entry should not be found\n");
        failures++;
    } else {
        printf("PASS: cache eviction\n");
    }
}

static void test_invalidate() {
    reset_cache();

    virt_cache_insert(g_cache, &g_cache_count, 128,
                      "/proc/self/maps", 15, true, VIRT_ACTION_BLOCK_ENOENT);

    int rc = virt_cache_invalidate(g_cache, &g_cache_count, "/proc/self/maps");
    if (rc < 0) {
        printf("FAIL: cache invalidate rc=%d\n", rc);
        failures++;
        return;
    }

    int cached = virt_cache_lookup(g_cache, g_cache_count, "/proc/self/maps", 15);
    if (cached >= 0) {
        printf("FAIL: invalidated cache entry should not be found\n");
        failures++;
    } else {
        printf("PASS: cache invalidate\n");
    }
}

static void test_flush() {
    reset_cache();

    virt_cache_insert(g_cache, &g_cache_count, 128,
                      "/proc/self/maps", 15, true, VIRT_ACTION_BLOCK_ENOENT);
    virt_cache_insert(g_cache, &g_cache_count, 128,
                      "/proc/self/status", 17, true, VIRT_ACTION_FAKE_CONTENT);

    int rc = virt_cache_flush(g_cache, &g_cache_count);
    if (rc < 0 || g_cache_count != 0) {
        printf("FAIL: cache flush (rc=%d, count=%u)\n", rc, g_cache_count);
        failures++;
    } else {
        printf("PASS: cache flush\n");
    }
}

static void test_invalid_args() {
    reset_cache();

    int rc = virt_cache_insert(NULL, &g_cache_count, 128, "/test", 5, true, VIRT_ACTION_BLOCK_ENOENT);
    if (rc >= 0) {
        printf("FAIL: cache insert NULL cache should fail\n");
        failures++;
    } else {
        printf("PASS: cache insert NULL cache fails\n");
    }

    rc = virt_cache_insert(g_cache, NULL, 128, "/test", 5, true, VIRT_ACTION_BLOCK_ENOENT);
    if (rc >= 0) {
        printf("FAIL: cache insert NULL count should fail\n");
        failures++;
    } else {
        printf("PASS: cache insert NULL count fails\n");
    }

    int cached = virt_cache_lookup(NULL, g_cache_count, "/test", 5);
    if (cached >= 0) {
        printf("FAIL: cache lookup NULL cache should fail\n");
        failures++;
    } else {
        printf("PASS: cache lookup NULL cache fails\n");
    }

    cached = virt_cache_lookup(g_cache, g_cache_count, NULL, 5);
    if (cached >= 0) {
        printf("FAIL: cache lookup NULL path should fail\n");
        failures++;
    } else {
        printf("PASS: cache lookup NULL path fails\n");
    }

    rc = virt_cache_flush(NULL, &g_cache_count);
    if (rc >= 0) {
        printf("FAIL: cache flush NULL cache should fail\n");
        failures++;
    } else {
        printf("PASS: cache flush NULL cache fails\n");
    }
}

static void test_cache_insert_null_path() {
    reset_cache();

    int rc = virt_cache_insert(g_cache, &g_cache_count, 128,
                               NULL, 5, true, VIRT_ACTION_BLOCK_ENOENT);
    if (rc >= 0) {
        printf("FAIL: cache insert NULL path should fail\n");
        failures++;
    } else {
        printf("PASS: cache insert NULL path fails\n");
    }
}

static void test_cache_insert_zero_len() {
    reset_cache();

    int rc = virt_cache_insert(g_cache, &g_cache_count, 128,
                               "", 0, true, VIRT_ACTION_BLOCK_ENOENT);
    if (rc >= 0) {
        printf("FAIL: cache insert zero-length path should fail\n");
        failures++;
    } else {
        printf("PASS: cache insert zero-length path fails\n");
    }
}

static void test_cache_lookup_zero_len() {
    reset_cache();

    int cached = virt_cache_lookup(g_cache, g_cache_count, "", 0);
    if (cached >= 0) {
        printf("FAIL: cache lookup zero-length path should fail\n");
        failures++;
    } else {
        printf("PASS: cache lookup zero-length path fails\n");
    }
}

static void test_cache_multiple_inserts_same_path() {
    reset_cache();

    virt_cache_insert(g_cache, &g_cache_count, 128,
                      "/proc/self/maps", 15, true, VIRT_ACTION_BLOCK_ENOENT);
    virt_cache_insert(g_cache, &g_cache_count, 128,
                      "/proc/self/maps", 15, true, VIRT_ACTION_FAKE_CONTENT);

    // Cache does not deduplicate — both entries exist; lookup finds first (BLOCK_ENOENT)
    int cached = virt_cache_lookup(g_cache, g_cache_count, "/proc/self/maps", 15);
    if (cached < 0) {
        printf("FAIL: duplicate insert should still be findable (got %d)\n", cached);
        failures++;
    }
    if (g_cache_count != 2) {
        printf("FAIL: duplicate insert should increase count (%u)\n", g_cache_count);
        failures++;
    }

    printf("PASS: cache multiple inserts same path (%u entries)\n", g_cache_count);
}

static void test_cache_exact_max() {
    reset_cache();

    for (uint32_t i = 0; i < 5; i++) {
        char path[32];
        snprintf(path, sizeof(path), "/test/path/%u", i);
        virt_cache_insert(g_cache, &g_cache_count, 5,
                          path, (uint32_t)strlen(path), true, VIRT_ACTION_BLOCK_ENOENT);
    }

    if (g_cache_count != 5) {
        printf("FAIL: expected 5 entries after filling, got %u\n", g_cache_count);
        failures++;
        return;
    }

    // Look up the most recently added entry (should not be evicted)
    int cached = virt_cache_lookup(g_cache, g_cache_count, "/test/path/4", 12);
    if (cached < 0) {
        printf("FAIL: recently added entry should be found\n");
        failures++;
    }

    printf("PASS: cache exact max\n");
}

static void test_cache_zero_max() {
    reset_cache();

    int rc = virt_cache_insert(g_cache, &g_cache_count, 0,
                               "/test", 5, true, VIRT_ACTION_BLOCK_ENOENT);
    if (rc >= 0) {
        printf("FAIL: insert with max=0 should fail\n");
        failures++;
    } else {
        printf("PASS: cache insert with max=0 fails\n");
    }
}

int main() {
    printf("=== Cache Unit Tests ===\n\n");

    test_insert_and_lookup();
    test_cache_miss();
    test_non_sensitive_entry();
    test_cache_eviction();
    test_invalidate();
    test_flush();
    test_invalid_args();
    test_cache_insert_null_path();
    test_cache_insert_zero_len();
    test_cache_lookup_zero_len();
    test_cache_multiple_inserts_same_path();
    test_cache_exact_max();
    test_cache_zero_max();

    printf("\n%d tests failed\n", failures);
    return failures;
}
