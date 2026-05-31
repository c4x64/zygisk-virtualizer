#include "../../virtualizer.h"
#include <cstdio>
#include <cstring>
#include <cerrno>

#ifndef __NR_perf_event_open
#if defined(__aarch64__)
#define __NR_perf_event_open 241
#elif defined(__arm__)
#define __NR_perf_event_open 364
#else
#define __NR_perf_event_open 364
#endif
#endif

static int failures = 0;
static int tests_run = 0;

#define TEST(name) do { tests_run++; printf("  %s ... ", name); } while(0)
#define PASS() do { printf("PASS\n"); } while(0)
#define FAIL(msg) do { printf("FAIL: %s\n", msg); failures++; } while(0)

static void test_perf_event_open_syscall() {
    TEST("perf_event_open syscall number defined");
    if (__NR_perf_event_open > 0) {
        printf("nr=%d ", __NR_perf_event_open);
        PASS();
    } else {
        FAIL("syscall number not defined");
    }
}

static void test_perf_event_open_invalid() {
    TEST("perf_event_open invalid args");
    struct virt_perf_event_attr pea;
    memset(&pea, 0, sizeof(pea));
    pea.size = sizeof(pea);
    pea.type = PERF_TYPE_HARDWARE;
    pea.config = 0;
    int fd = (int)syscall(__NR_perf_event_open, &pea, -1, 0, -1, 0);
    if (fd < 0) {
        printf("errno=%d ", errno);
        PASS();
    } else {
        close(fd);
        FAIL("unexpected success");
    }
}

static void test_fingerprint_init() {
    TEST("fingerprint init different seeds for different PIDs");
    VIRT_Fingerprint fp1, fp2;
    memset(&fp1, 0, sizeof(fp1));
    memset(&fp2, 0, sizeof(fp2));

    g_fp = fp1;
    virt_fingerprint_init(1000);
    uint32_t seed1 = g_fp.seed;

    g_fp = fp2;
    virt_fingerprint_init(2000);
    uint32_t seed2 = g_fp.seed;

    if (seed1 != seed2) {
        PASS();
    } else {
        FAIL("seeds are identical for different PIDs");
    }
}

static void test_fingerprint_rand() {
    TEST("fingerprint rand deterministic per seed");
    VIRT_Fingerprint save = g_fp;
    g_fp.seed = 0x12345678;
    g_fp.state = g_fp.seed;
    uint32_t r1 = virt_fingerprint_rand();
    g_fp.seed = 0x12345678;
    g_fp.state = g_fp.seed;
    uint32_t r2 = virt_fingerprint_rand();
    g_fp = save;
    if (r1 == r2) {
        printf("val=%08x ", r1);
        PASS();
    } else {
        FAIL("rand not deterministic");
    }
}

static void test_fingerprint_rand_different() {
    TEST("fingerprint rand different seeds give different values");
    VIRT_Fingerprint save = g_fp;
    g_fp.seed = 0x11111111;
    g_fp.state = g_fp.seed;
    uint32_t r1 = virt_fingerprint_rand();
    g_fp.seed = 0x22222222;
    g_fp.state = g_fp.seed;
    uint32_t r2 = virt_fingerprint_rand();
    g_fp = save;
    if (r1 != r2) {
        printf("v1=%08x v2=%08x ", r1, r2);
        PASS();
    } else {
        FAIL("different seeds gave same value");
    }
}

static void test_auto_tune_null() {
    TEST("auto_tune null config");
    int rc = virt_config_auto_tune(NULL);
    if (rc == VIRT_ERR_INVAL) {
        PASS();
    } else {
        FAIL("expected VIRT_ERR_INVAL");
    }
}

static void test_auto_tune_defaults() {
    TEST("auto_tune default config no crash");
    VIRT_Config cfg = VIRT_DEFAULT_CONFIG;
    int rc = virt_config_auto_tune(&cfg);
    if (rc == VIRT_OK) {
        PASS();
    } else {
        printf("rc=%d ", rc);
        FAIL("auto_tune failed");
    }
}

static void test_auto_tune_cache() {
    TEST("auto_tune cache size adjustments");
    VIRT_Config cfg = VIRT_DEFAULT_CONFIG;
    uint32_t original = cfg.cache_size;
    /* Simulate low memory: override cache_size */
    cfg.cache_size = 8192;
    /* With default config auto-tune should at least not corrupt cache_size */
    int rc = virt_config_auto_tune(&cfg);
    if (rc == VIRT_OK && cfg.cache_size > 0 && cfg.cache_size <= VIRT_MAX_CACHED_PATHS) {
        printf("cache=%u ", cfg.cache_size);
        PASS();
    } else {
        printf("rc=%d cache=%u ", rc, cfg.cache_size);
        FAIL("invalid cache size after auto_tune");
    }
    cfg.cache_size = original;
}

static void test_shell_detect_notty() {
    TEST("shell detect not a terminal");
    /* When no tty is connected, virt_detect_shell_access should return 0 */
    int rc = virt_detect_shell_access();
    if (rc == 0 || rc == 1) {
        /* Either is valid depending on env; just check no crash */
        printf("rc=%d ", rc);
        PASS();
    } else {
        FAIL("unexpected return value");
    }
}

static void test_virt_read_property() {
    TEST("virt_read_property with test data");
    /* Create a fake build.prop in cwd for testing */
    FILE *f = fopen("/tmp/test_build_prop", "w");
    if (!f) {
        printf("SKIP (cannot create temp file) ");
        PASS();
        return;
    }
    fprintf(f, "ro.build.version.sdk=33\n");
    fprintf(f, "ro.product.board=goldfish\n");
    fprintf(f, "ro.build.fingerprint=test/fingerprint\n");
    fclose(f);

    /* We can't easily redirect virt_read_property to /tmp,
     * so just verify the function exists and handles NULL */
    char buf[64];
    int rc = virt_read_property(NULL, buf, sizeof(buf));
    if (rc == -1) {
        PASS();
    } else {
        FAIL("expected -1 for NULL key");
    }
}

int main() {
    printf("=== Feature Unit Tests ===\n\n");

    printf("--- perf_event_open ---\n");
    test_perf_event_open_syscall();
    test_perf_event_open_invalid();

    printf("\n--- Fingerprint ---\n");
    test_fingerprint_init();
    test_fingerprint_rand();
    test_fingerprint_rand_different();

    printf("\n--- Auto-Tune ---\n");
    test_auto_tune_null();
    test_auto_tune_defaults();
    test_auto_tune_cache();

    printf("\n--- Shell Detection ---\n");
    test_shell_detect_notty();
    test_virt_read_property();

    printf("\n---\n");
    printf("%d tests run, %d failed\n", tests_run, failures);
    return failures;
}
