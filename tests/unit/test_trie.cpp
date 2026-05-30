#include "../../virtualizer.h"
#include <cstdio>
#include <cassert>
#include <cstring>

// Forward declarations for internal symbols we need to reset between tests
extern "C" void virt_trie_destroy(void);
extern "C" uint32_t virt_trie_get_node_count(void);
extern "C" int virt_trie_build_default(void);

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
    rc = virt_trie_lookup("/proc/self/maps", 14, &action);
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
    int rc = virt_trie_lookup("/proc/self/maps", 14, &action);
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
    rc = virt_trie_lookup("/proc/self/maps", 14, &action);
    if (rc < 0) {
        printf("FAIL: trie default should match /proc/self/maps\n");
        failures++;
    } else {
        printf("PASS: trie default matches /proc/self/maps\n");
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

    virt_trie_destroy();

    printf("\n%d tests failed\n", failures);
    return failures;
}
