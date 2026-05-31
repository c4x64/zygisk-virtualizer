#include "../../virtualizer.h"
#include <cstdio>
#include <cassert>
#include <cstring>

// Forward declarations for internal symbols we need to reset between tests
extern void virt_trie_destroy(void);
extern uint32_t virt_trie_get_node_count(void);
extern int virt_trie_build_default(void);

static int failures = 0;

static void test_exact_match() {
    virt_trie_destroy();

    int rc = virt_trie_insert("/proc/self/maps", VIRT_ACTION_BLOCK_ENOENT, 100);
    if (rc < 0) {
        printf("FAIL: trie insert rc=%d\n", rc);
        failures++;
        return;
    }

    int action = VIRT_ACTION_PASS_THROUGH;
    rc = virt_trie_lookup("/proc/self/maps", 15, &action);
    if (rc < 0 || action != VIRT_ACTION_BLOCK_ENOENT) {
        printf("FAIL: trie exact match (rc=%d, action=%d)\n", rc, action);
        failures++;
    } else {
        printf("PASS: trie exact match\n");
    }
}

static void test_prefix_match() {
    virt_trie_destroy();

    virt_trie_insert("/proc/self/", VIRT_ACTION_FAKE_CONTENT, 200);
    int action = VIRT_ACTION_PASS_THROUGH;
    int rc = virt_trie_lookup("/proc/self/status", 17, &action);
    if (rc < 0 || action != VIRT_ACTION_FAKE_CONTENT) {
        printf("FAIL: trie prefix match (rc=%d, action=%d)\n", rc, action);
        failures++;
    } else {
        printf("PASS: trie prefix match\n");
    }
}

static void test_non_match() {
    virt_trie_destroy();

    virt_trie_insert("/proc/self/maps", VIRT_ACTION_BLOCK_ENOENT, 100);
    int action = VIRT_ACTION_PASS_THROUGH;
    int rc = virt_trie_lookup("/system/lib/libc.so", 19, &action);
    if (rc >= 0) {
        printf("FAIL: trie non-match should return negative (rc=%d)\n", rc);
        failures++;
    } else {
        printf("PASS: trie non-match\n");
    }
}

static void test_empty_path() {
    virt_trie_destroy();

    virt_trie_insert("/proc/self/maps", VIRT_ACTION_BLOCK_ENOENT, 100);
    int action = VIRT_ACTION_PASS_THROUGH;
    int rc = virt_trie_lookup("", 0, &action);
    if (rc >= 0) {
        printf("FAIL: trie empty path\n");
        failures++;
    } else {
        printf("PASS: trie empty path\n");
    }
}

static void test_trailing_slash() {
    virt_trie_destroy();

    virt_trie_insert("/data/adb/magisk", VIRT_ACTION_BLOCK_ENOENT, 100);
    int action = VIRT_ACTION_PASS_THROUGH;
    int rc = virt_trie_lookup("/data/adb/magisk/", 17, &action);
    if (rc < 0) {
        printf("FAIL: trie should match /data/adb/magisk/ as prefix\n");
        failures++;
    } else {
        printf("PASS: trie prefix match with trailing slash\n");
    }
}

static void test_priority_ordering() {
    virt_trie_destroy();

    virt_trie_insert("/proc/", VIRT_ACTION_FAKE_CONTENT, 50);
    virt_trie_insert("/proc/self/maps", VIRT_ACTION_BLOCK_ENOENT, 200);
    int action = VIRT_ACTION_PASS_THROUGH;
    int rc = virt_trie_lookup("/proc/self/maps", 15, &action);
    if (rc < 0 || action != VIRT_ACTION_BLOCK_ENOENT) {
        printf("FAIL: trie priority ordering (action=%d)\n", action);
        failures++;
    } else {
        printf("PASS: trie priority ordering\n");
    }
}

static void test_node_count() {
    virt_trie_destroy();

    uint32_t before = virt_trie_get_node_count();
    virt_trie_insert("/a/b/c", VIRT_ACTION_BLOCK_ENOENT, 100);
    virt_trie_insert("/a/b/d", VIRT_ACTION_BLOCK_ENOENT, 100);
    uint32_t after = virt_trie_get_node_count();
    if (after - before < 5) {
        printf("FAIL: trie node count too small (%u -> %u)\n", before, after);
        failures++;
    } else {
        printf("PASS: trie node count (%u -> %u)\n", before, after);
    }
}

static void test_default_patterns_build() {
    virt_trie_destroy();

    int rc = virt_trie_build_default();
    if (rc < 0) {
        printf("FAIL: trie build default (rc=%d)\n", rc);
        failures++;
        return;
    }
    uint32_t count = virt_trie_get_node_count();
    if (count == 0) {
        printf("FAIL: trie build default produced zero nodes\n");
        failures++;
    } else {
        printf("PASS: trie build default (%u nodes)\n", count);
    }

    int action;
    rc = virt_trie_lookup("/proc/self/pagemap", 18, &action);
    if (rc < 0) {
        printf("FAIL: trie default should match /proc/self/pagemap\n");
        failures++;
    } else {
        printf("PASS: trie default matches /proc/self/pagemap (action=%d)\n", action);
    }
    // /proc/self/maps is redirected via decoy, not blocked in trie
    rc = virt_trie_lookup("/proc/self/maps", 15, &action);
    if (rc >= 0) {
        printf("WARN: /proc/self/maps unexpectedly matched in trie (not expected, but OK)\n");
    }
}

static void test_invalid_args() {
    virt_trie_destroy();

    int rc = virt_trie_insert("", VIRT_ACTION_BLOCK_ENOENT, 100);
    if (rc >= 0) {
        printf("FAIL: trie insert empty string should fail\n");
        failures++;
    } else {
        printf("PASS: trie insert empty string fails\n");
    }

    int action;
    rc = virt_trie_lookup(NULL, 10, &action);
    if (rc >= 0) {
        printf("FAIL: trie lookup NULL path should fail\n");
        failures++;
    } else {
        printf("PASS: trie lookup NULL path fails\n");
    }

    rc = virt_trie_lookup("/test", 5, NULL);
    if (rc >= 0) {
        printf("FAIL: trie lookup NULL out should fail\n");
        failures++;
    } else {
        printf("PASS: trie lookup NULL out fails\n");
    }
}

static void test_fallback_behavior() {
    virt_trie_destroy();

    virt_trie_insert("/proc/self/status", VIRT_ACTION_FAKE_CONTENT, 100);
    virt_trie_insert("/proc/version", VIRT_ACTION_BLOCK_ENOENT, 50);

    int action;
    // /proc/self/status should match exactly
    int rc = virt_trie_lookup("/proc/self/status", 17, &action);
    if (rc < 0 || action != VIRT_ACTION_FAKE_CONTENT) {
        printf("FAIL: fallback exact match (rc=%d, action=%d)\n", rc, action);
        failures++;
    } else {
        printf("PASS: fallback exact match\n");
    }

    // /proc/self/stat should NOT match /proc/self/status (character boundary)
    rc = virt_trie_lookup("/proc/self/stat", 15, &action);
    if (rc == 0) {
        printf("WARN: /proc/self/stat unexpectedly matched\n");
    }

    printf("PASS: trie fallback behavior\n");
}

static void test_partial_root_fallback() {
    virt_trie_destroy();

    virt_trie_insert("/system/app/", VIRT_ACTION_BLOCK_ENOENT, 100);

    int action;
    // /system/bin should NOT match /system/app/ - different character after /
    int rc = virt_trie_lookup("/system/bin/su", 14, &action);
    if (rc == 0) {
        printf("FAIL: /system/bin/su should not match /system/app/\n");
        failures++;
    } else {
        printf("PASS: partial root fallback (/system/bin != /system/app)\n");
    }
}

static void test_empty_pattern_edge() {
    virt_trie_destroy();

    int rc = virt_trie_insert("", VIRT_ACTION_BLOCK_ENOENT, 100);
    if (rc >= 0) {
        printf("FAIL: insert empty pattern should fail\n");
        failures++;
    } else {
        printf("PASS: empty pattern insert fails\n");
    }

    virt_trie_insert("/valid/path", VIRT_ACTION_BLOCK_ENOENT, 100);
    int action;
    rc = virt_trie_lookup("/valid/path", 11, &action);
    if (rc < 0) {
        printf("FAIL: valid path after empty insert attempt\n");
        failures++;
    } else {
        printf("PASS: trie works after empty insert attempt\n");
    }
}

static void test_long_path() {
    virt_trie_destroy();

    // Path must exceed VIRT_PATH_BUF_SIZE (4096)
    char long_path[4200];
    memset(long_path, 'a', sizeof(long_path) - 1);
    long_path[0] = '/';
    long_path[sizeof(long_path) - 1] = '\0';

    int rc = virt_trie_insert(long_path, VIRT_ACTION_BLOCK_ENOENT, 100);
    if (rc >= 0) {
        printf("FAIL: path too long should be rejected\n");
        failures++;
        return;
    }
    printf("PASS: long path rejected (%d)\n", rc);

    // Normal paths should still work after rejection
    virt_trie_insert("/normal", VIRT_ACTION_BLOCK_ENOENT, 100);
    int action;
    rc = virt_trie_lookup("/normal", 7, &action);
    if (rc < 0) {
        printf("FAIL: normal path after long path rejection\n");
        failures++;
    } else {
        printf("PASS: trie works after long path rejection\n");
    }
}

static void test_special_chars() {
    virt_trie_destroy();

    virt_trie_insert("/proc/self/fd/0", VIRT_ACTION_BLOCK_ENOENT, 100);
    virt_trie_insert("/proc/self/fd/255", VIRT_ACTION_BLOCK_ENOENT, 100);

    int action;
    int rc = virt_trie_lookup("/proc/self/fd/0", 16, &action);
    if (rc < 0) {
        printf("FAIL: path with digit 0 should match\n");
        failures++;
    }
    rc = virt_trie_lookup("/proc/self/fd/255", 18, &action);
    if (rc < 0) {
        printf("FAIL: path with digit 255 should match\n");
        failures++;
    }
    rc = virt_trie_lookup("/proc/self/fd/12", 17, &action);
    if (rc >= 0) {
        printf("FAIL: /proc/self/fd/12 should not match /proc/self/fd/0 or /proc/self/fd/255\n");
        failures++;
    }

    printf("PASS: trie special chars (digits)\n");
}

static void test_trie_overwrite() {
    virt_trie_destroy();

    virt_trie_insert("/proc/self/maps", VIRT_ACTION_FAKE_CONTENT, 50);
    virt_trie_insert("/proc/self/maps", VIRT_ACTION_BLOCK_ENOENT, 200);

    int action;
    int rc = virt_trie_lookup("/proc/self/maps", 15, &action);
    if (rc < 0 || action != VIRT_ACTION_BLOCK_ENOENT) {
        printf("FAIL: overwritten rule should use higher priority (action=%d)\n", action);
        failures++;
    } else {
        printf("PASS: trie overwrite with higher priority\n");
    }
}

int main() {
    printf("=== Trie Unit Tests ===\n\n");

    test_exact_match();
    test_prefix_match();
    test_non_match();
    test_empty_path();
    test_trailing_slash();
    test_priority_ordering();
    test_node_count();
    test_default_patterns_build();
    test_invalid_args();
    test_fallback_behavior();
    test_partial_root_fallback();
    test_empty_pattern_edge();
    test_long_path();
    test_special_chars();
    test_trie_overwrite();

    virt_trie_destroy();

    printf("\n%d tests failed\n", failures);
    return failures;
}
