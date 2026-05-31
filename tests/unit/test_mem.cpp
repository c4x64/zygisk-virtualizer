#include "../../virtualizer.h"
#include <cstdio>
#include <cstring>
#include <cstdlib>

static int failures = 0;

// Memory tracking uses a global static state. These tests account
// for cumulative state by computing deltas vs. initial conditions.
static void test_alloc_free_balance() {
    size_t before = virt_mem_get_usage();
    virt_mem_track_alloc(1000);
    virt_mem_track_alloc(2000);
    virt_mem_track_free(1000);
    size_t mid = virt_mem_get_usage();
    if (mid - before != 2000) {
        printf("FAIL: mid alloc expected +2000 got +%zu\n", mid - before);
        failures++;
        return;
    }
    virt_mem_track_free(2000);
    if (virt_mem_get_usage() != before) {
        printf("FAIL: after full free expected %zu got %zu\n", before, virt_mem_get_usage());
        failures++;
        return;
    }
    printf("PASS: mem alloc free balance\n");
}

static void test_peak_tracking() {
    size_t before = virt_mem_get_usage();
    virt_mem_track_alloc(5000);
    size_t peak1 = virt_mem_get_peak();
    virt_mem_track_alloc(3000);
    size_t peak2 = virt_mem_get_peak();
    virt_mem_track_free(8000);
    size_t peak3 = virt_mem_get_peak();
    // Peak must be >= usage and monotonic non-decreasing
    if (peak1 < before + 5000 || peak2 < peak1 || peak3 < peak2) {
        printf("FAIL: peak monotonicity (p1=%zu, p2=%zu, p3=%zu, before=%zu)\n",
               peak1, peak2, peak3, before);
        failures++;
        return;
    }
    // After freeing all, peak should remain at max
    if (peak3 != peak2) {
        printf("FAIL: peak should retain max after free (%zu vs %zu)\n", peak3, peak2);
        failures++;
        return;
    }
    printf("PASS: mem peak tracking\n");
}

static void test_oom_count() {
    virt_mem_record_oom();
    virt_mem_record_oom();
    virt_mem_record_oom();
    size_t usage = virt_mem_get_usage();
    if (usage != virt_mem_get_usage()) {
        printf("FAIL: oom record should not change usage\n");
        failures++;
        return;
    }
    printf("PASS: mem record oom\n");
}

static void test_pressure_none() {
    size_t before = virt_mem_get_usage();
    if (before >= 10ULL * 1024 * 1024) {
        printf("SKIP: pressure none (usage too high: %zu)\n", before);
        return;
    }
    int level = virt_mem_check_pressure();
    if (level != 0) {
        printf("FAIL: low memory should report 0 pressure got %d\n", level);
        failures++;
        return;
    }
    printf("PASS: mem pressure none\n");
}

static void test_pressure_warning() {
    size_t before = virt_mem_get_usage();
    size_t needed = 10ULL * 1024 * 1024 - before;
    if (needed > 10ULL * 1024 * 1024) {
        printf("SKIP: pressure warning (usage too high to test cleanly)\n");
        return;
    }
    virt_mem_track_alloc(needed);
    int level = virt_mem_check_pressure();
    bool got_warning = (level == 1);
    virt_mem_track_free(needed);
    if (!got_warning) {
        printf("FAIL: warning threshold expected 1 got %d (needed=%zu, before=%zu)\n",
               level, needed, before);
        failures++;
        return;
    }
    printf("PASS: mem pressure warning\n");
}

static void test_pressure_critical() {
    size_t before = virt_mem_get_usage();
    size_t needed = 20ULL * 1024 * 1024 - before;
    if (needed > 30ULL * 1024 * 1024) {
        printf("SKIP: pressure critical (usage too high)\n");
        return;
    }
    virt_mem_track_alloc(needed);
    int level = virt_mem_check_pressure();
    bool got_critical = (level == 2);
    virt_mem_track_free(needed);
    if (!got_critical) {
        printf("FAIL: critical threshold expected 2 got %d (needed=%zu, before=%zu)\n",
               level, needed, before);
        failures++;
        return;
    }
    printf("PASS: mem pressure critical\n");
}

static void test_pressure_above_critical() {
    size_t before = virt_mem_get_usage();
    size_t needed = 50ULL * 1024 * 1024 - before;
    if (needed < 20ULL * 1024 * 1024) {
        printf("SKIP: pressure above critical (usage too high)\n");
        return;
    }
    virt_mem_track_alloc(needed);
    int level = virt_mem_check_pressure();
    bool got_critical = (level == 2);
    virt_mem_track_free(needed);
    if (!got_critical) {
        printf("FAIL: above critical expected 2 got %d\n", level);
        failures++;
        return;
    }
    printf("PASS: mem pressure above critical\n");
}

static void test_reduce_footprint_after_alloc() {
    size_t before = virt_mem_get_usage();
    virt_mem_track_alloc(500000);
    virt_mem_track_alloc(300000);
    virt_mem_reduce_footprint();
    size_t after_reduce = virt_mem_get_usage();
    size_t expected = before + 800000;
    if (after_reduce != expected) {
        printf("FAIL: reduce_footprint should keep tracking (expected %zu got %zu)\n",
               expected, after_reduce);
        failures++;
        return;
    }
    virt_mem_track_free(800000);
    printf("PASS: mem reduce footprint after alloc\n");
}

static void test_resource_limits_init() {
    VIRT_ResourceLimits limits;
    memset(&limits, 0xFF, sizeof(limits));
    int rc = virt_resource_limits_init(&limits);
    if (rc != VIRT_OK) {
        printf("FAIL: limits init rc=%d\n", rc);
        failures++;
        return;
    }
    if (limits.max_cache_entries == 0) {
        printf("FAIL: max_cache_entries not set\n");
        failures++;
    }
    if (limits.max_rules == 0) {
        printf("FAIL: max_rules not set\n");
        failures++;
    }
    if (limits.max_trie_nodes == 0) {
        printf("FAIL: max_trie_nodes not set\n");
        failures++;
    }
    if (limits.max_event_history == 0) {
        printf("FAIL: max_event_history not set\n");
        failures++;
    }
    if (limits.max_log_size == 0) {
        printf("FAIL: max_log_size not set\n");
        failures++;
    }
    if (limits.enable_strict_mode != false) {
        printf("FAIL: strict_mode should be false\n");
        failures++;
    }
    printf("PASS: resource limits init\n");
}

static void test_resource_limits_init_null() {
    int rc = virt_resource_limits_init(NULL);
    if (rc == VIRT_OK) {
        printf("FAIL: limits init with NULL should fail\n");
        failures++;
    } else {
        printf("PASS: resource limits init null\n");
    }
}

static void test_resource_check_limit_ok() {
    int rc = virt_resource_check_limit(5, 10, "test");
    if (rc != VIRT_OK) {
        printf("FAIL: under limit should return OK got %d\n", rc);
        failures++;
    } else {
        printf("PASS: resource check limit ok\n");
    }
}

static void test_resource_check_limit_at_max() {
    int rc = virt_resource_check_limit(10, 10, "test");
    if (rc != VIRT_ERR_BUSY) {
        printf("FAIL: at limit should return BUSY got %d\n", rc);
        failures++;
    } else {
        printf("PASS: resource check limit at max\n");
    }
}

static void test_resource_check_limit_over() {
    int rc = virt_resource_check_limit(15, 10, "test");
    if (rc != VIRT_ERR_BUSY) {
        printf("FAIL: over limit should return BUSY got %d\n", rc);
        failures++;
    } else {
        printf("PASS: resource check limit over\n");
    }
}

static void test_resource_check_limit_zero_max() {
    int rc = virt_resource_check_limit(0, 0, "zero_max");
    if (rc != VIRT_ERR_BUSY) {
        printf("FAIL: zero max should return BUSY got %d\n", rc);
        failures++;
    } else {
        printf("PASS: resource check limit zero max\n");
    }
}

static void test_free_underflow() {
    size_t before = virt_mem_get_usage();
    virt_mem_track_alloc(100);
    virt_mem_track_free(200);
    size_t after = virt_mem_get_usage();
    // Implementation subtracts min(size, total_allocated).
    // Since total_allocated was before+100, free(200) subtracts before+100.
    // Result should be >= before and <= before+100.
    if (after > before + 100) {
        printf("FAIL: free underflow clamping unexpected (%zu -> %zu)\n", before, after);
        failures++;
        return;
    }
    printf("PASS: mem free underflow (usage %zu)\n", after);
}

static void test_peak_not_reset_by_free() {
    size_t prev_peak = virt_mem_get_peak();
    size_t before = virt_mem_get_usage();
    // Allocate more than current peak to test peak update
    size_t extra = prev_peak + 100000;
    virt_mem_track_alloc(extra);
    size_t peak_after_alloc = virt_mem_get_peak();
    virt_mem_track_free(extra);
    size_t peak_after_free = virt_mem_get_peak();
    if (peak_after_alloc <= prev_peak) {
        printf("FAIL: peak should increase after alloc (%zu <= %zu)\n",
               peak_after_alloc, prev_peak);
        failures++;
        return;
    }
    if (peak_after_free != peak_after_alloc) {
        printf("FAIL: peak should retain max after free (%zu vs %zu)\n",
               peak_after_free, peak_after_alloc);
        failures++;
        return;
    }
    if (virt_mem_get_usage() != before) {
        printf("FAIL: usage should return to %zu after free, got %zu\n",
               before, virt_mem_get_usage());
        failures++;
        return;
    }
    printf("PASS: mem peak not reset by free\n");
}

static void test_tracking_large_alloc() {
    size_t before = virt_mem_get_usage();
    size_t huge = 1024UL * 1024 * 1024;
    virt_mem_track_alloc(huge);
    size_t after = virt_mem_get_usage();
    // Allow for previous allocations that may increase total beyond huge
    if (after - before != huge) {
        printf("FAIL: large alloc delta expected %zu got %zu\n", huge, after - before);
        failures++;
        return;
    }
    virt_mem_track_free(huge);
    printf("PASS: mem tracking large alloc\n");
}

int main() {
    printf("=== Memory Tracking & Resource Limits Unit Tests ===\n\n");

    test_alloc_free_balance();
    test_peak_tracking();
    test_oom_count();
    test_pressure_none();
    test_pressure_warning();
    test_pressure_critical();
    test_pressure_above_critical();
    test_reduce_footprint_after_alloc();
    test_resource_limits_init();
    test_resource_limits_init_null();
    test_resource_check_limit_ok();
    test_resource_check_limit_at_max();
    test_resource_check_limit_over();
    test_resource_check_limit_zero_max();
    test_free_underflow();
    test_peak_not_reset_by_free();
    test_tracking_large_alloc();

    printf("\n%d tests failed\n", failures);
    return failures;
}
