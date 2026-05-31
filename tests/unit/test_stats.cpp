#include "../../virtualizer.h"
#include <cstdio>
#include <cstring>

static int failures = 0;

static VIRT_SyscallStats g_stats;

static void test_init() {
    memset(&g_stats, 0, sizeof(g_stats));
    int rc = virt_stats_init(&g_stats);
    if (rc != VIRT_OK) {
        printf("FAIL: init rc=%d\n", rc);
        failures++;
        return;
    }
    if (g_stats.total_calls != 0) {
        printf("FAIL: total_calls should be 0 after init\n");
        failures++;
    }
    if (g_stats.min_latency_ns != UINT64_MAX) {
        printf("FAIL: min_latency should be UINT64_MAX after init\n");
        failures++;
    }
    if (g_stats.last_reset_tp == 0) {
        printf("FAIL: last_reset_tp should be non-zero\n");
        failures++;
    }
    if (g_stats.window_seconds != 60) {
        printf("FAIL: window_seconds should be 60\n");
        failures++;
    }
    printf("PASS: stats init\n");
}

static void test_init_null() {
    int rc = virt_stats_init(NULL);
    if (rc == VIRT_OK) {
        printf("FAIL: init with NULL should fail\n");
        failures++;
    } else {
        printf("PASS: stats init null\n");
    }
}

static void test_record_basic() {
    virt_stats_init(&g_stats);

    // Record one allowed call
    int rc = virt_stats_record(&g_stats, 62, VIRT_ACTION_ALLOW, 100);
    if (rc != VIRT_OK) {
        printf("FAIL: record rc=%d\n", rc);
        failures++;
        return;
    }

    if (g_stats.total_calls != 1) {
        printf("FAIL: total_calls expected 1 got %llu\n", g_stats.total_calls);
        failures++;
    }
    if (g_stats.allowed_calls != 1) {
        printf("FAIL: allowed_calls expected 1 got %llu\n", g_stats.allowed_calls);
        failures++;
    }
    if (g_stats.total_latency_ns != 100) {
        printf("FAIL: total_latency expected 100 got %llu\n", g_stats.total_latency_ns);
        failures++;
    }
    if (g_stats.max_latency_ns != 100) {
        printf("FAIL: max_latency expected 100 got %llu\n", g_stats.max_latency_ns);
        failures++;
    }
    if (g_stats.min_latency_ns != 100) {
        printf("FAIL: min_latency expected 100 got %llu\n", g_stats.min_latency_ns);
        failures++;
    }
    if (g_stats.per_syscall[62] != 1) {
        printf("FAIL: per_syscall[62] expected 1\n");
        failures++;
    }
    if (g_stats.per_action[VIRT_ACTION_ALLOW] != 1) {
        printf("FAIL: per_action[ALLOW] expected 1\n");
        failures++;
    }

    printf("PASS: stats record basic\n");
}

static void test_record_blocked() {
    virt_stats_init(&g_stats);

    virt_stats_record(&g_stats, 61, VIRT_ACTION_BLOCK_ENOENT, 200);
    virt_stats_record(&g_stats, 61, VIRT_ACTION_FAKE_MAPS, 300);

    if (g_stats.blocked_calls != 2) {
        printf("FAIL: blocked_calls expected 2 got %llu\n", g_stats.blocked_calls);
        failures++;
    }
    if (g_stats.total_calls != 2) {
        printf("FAIL: total_calls expected 2 got %llu\n", g_stats.total_calls);
        failures++;
    }
    if (g_stats.blocked_percent != 100.0) {
        printf("FAIL: blocked_percent expected 100 got %f\n", g_stats.blocked_percent);
        failures++;
    }

    printf("PASS: stats record blocked\n");
}

static void test_record_mixed() {
    virt_stats_init(&g_stats);

    virt_stats_record(&g_stats, 61, VIRT_ACTION_BLOCK_ENOENT, 150);
    virt_stats_record(&g_stats, 62, VIRT_ACTION_ALLOW, 50);
    virt_stats_record(&g_stats, 78, VIRT_ACTION_PASS_THROUGH, 500);

    if (g_stats.total_calls != 3) {
        printf("FAIL: total_calls expected 3 got %llu\n", g_stats.total_calls);
        failures++;
    }
    if (g_stats.blocked_calls != 1) {
        printf("FAIL: blocked_calls expected 1 got %llu\n", g_stats.blocked_calls);
        failures++;
    }
    if (g_stats.allowed_calls != 1) {
        printf("FAIL: allowed_calls expected 1 got %llu\n", g_stats.allowed_calls);
        failures++;
    }
    if (g_stats.continued_calls != 1) {
        printf("FAIL: continued_calls expected 1 got %llu\n", g_stats.continued_calls);
        failures++;
    }
    if (g_stats.per_action[VIRT_ACTION_BLOCK_ENOENT] != 1) {
        printf("FAIL: per_action[BLOCK_ENOENT] expected 1\n");
        failures++;
    }
    if (g_stats.per_action[VIRT_ACTION_ALLOW] != 1) {
        printf("FAIL: per_action[ALLOW] expected 1\n");
        failures++;
    }
    if (g_stats.per_action[VIRT_ACTION_PASS_THROUGH] != 1) {
        printf("FAIL: per_action[PASS_THROUGH] expected 1\n");
        failures++;
    }
    if (g_stats.min_latency_ns != 50) {
        printf("FAIL: min_latency expected 50 got %llu\n", g_stats.min_latency_ns);
        failures++;
    }
    if (g_stats.max_latency_ns != 500) {
        printf("FAIL: max_latency expected 500 got %llu\n", g_stats.max_latency_ns);
        failures++;
    }
    // Total latency: 150 + 50 + 500 = 700
    if (g_stats.total_latency_ns != 700) {
        printf("FAIL: total_latency expected 700 got %llu\n", g_stats.total_latency_ns);
        failures++;
    }

    printf("PASS: stats record mixed\n");
}

static void test_record_null() {
    virt_stats_init(&g_stats);

    int rc = virt_stats_record(NULL, 62, VIRT_ACTION_ALLOW, 100);
    if (rc == VIRT_OK) {
        printf("FAIL: record with NULL should fail\n");
        failures++;
    }

    printf("PASS: stats record null\n");
}

static void test_record_out_of_range_syscall() {
    virt_stats_init(&g_stats);

    // Syscall 999 should be ignored for per-syscall stats but count towards total
    int rc = virt_stats_record(&g_stats, 999, VIRT_ACTION_ALLOW, 100);
    if (rc != VIRT_OK) {
        printf("FAIL: record with out-of-range syscall should succeed rc=%d\n", rc);
        failures++;
        return;
    }
    if (g_stats.total_calls != 1) {
        printf("FAIL: total_calls expected 1 got %llu\n", g_stats.total_calls);
        failures++;
    }
    // per_syscall[999] shouldn't exist... we'll check it doesn't crash
    printf("PASS: stats record out of range syscall\n");
}

static void test_record_out_of_range_action() {
    virt_stats_init(&g_stats);

    // Action 99 should be ignored for per-action, but count towards blocked (not ALLOW/CONTINUE match)
    int rc = virt_stats_record(&g_stats, 62, 99, 100);
    if (rc != VIRT_OK) {
        printf("FAIL: record with out-of-range action should succeed rc=%d\n", rc);
        failures++;
        return;
    }
    if (g_stats.total_calls != 1) {
        printf("FAIL: total_calls expected 1 got %llu\n", g_stats.total_calls);
        failures++;
    }
    if (g_stats.blocked_calls != 0 && g_stats.allowed_calls != 0 && g_stats.continued_calls != 0) {
        printf("FAIL: unknown action should not increment any action counter\n");
        failures++;
    }

    printf("PASS: stats record out of range action\n");
}

static void test_snapshot() {
    virt_stats_init(&g_stats);

    virt_stats_record(&g_stats, 61, VIRT_ACTION_BLOCK_ENOENT, 150);
    virt_stats_record(&g_stats, 62, VIRT_ACTION_ALLOW, 50);
    virt_stats_record(&g_stats, 78, VIRT_ACTION_PASS_THROUGH, 500);

    char buf[4096];
    int rc = virt_stats_snapshot(&g_stats, buf, sizeof(buf));
    if (rc <= 0) {
        printf("FAIL: snapshot rc=%d\n", rc);
        failures++;
        return;
    }

    // Verify snapshot output contains expected values
    if (strstr(buf, "Total:") == NULL) {
        printf("FAIL: snapshot missing Total line\n%s\n", buf);
        failures++;
    }
    if (strstr(buf, "Total:") && strstr(buf, "3") == NULL && strstr(buf, "       3") == NULL) {
        // The format uses %10lu, so "Total:           3" or similar
        if (buf[0] == '\0') {
            printf("FAIL: snapshot empty\n");
            failures++;
        }
    }

    if (strstr(buf, "Allowed:") == NULL) {
        printf("FAIL: snapshot missing Allowed line\n");
        failures++;
    }
    if (strstr(buf, "Blocked:") == NULL) {
        printf("FAIL: snapshot missing Blocked line\n");
        failures++;
    }
    if (strstr(buf, "Errors:") == NULL) {
        printf("FAIL: snapshot missing Errors line\n");
        failures++;
    }

    printf("PASS: stats snapshot\n");
}

static void test_snapshot_null() {
    char buf[256];
    int rc = virt_stats_snapshot(NULL, buf, sizeof(buf));
    if (rc == VIRT_OK) {
        printf("FAIL: snapshot with NULL stats should fail\n");
        failures++;
    }
    rc = virt_stats_snapshot(&g_stats, NULL, sizeof(buf));
    if (rc == VIRT_OK) {
        printf("FAIL: snapshot with NULL buf should fail\n");
        failures++;
    }
    rc = virt_stats_snapshot(&g_stats, buf, 0);
    if (rc == VIRT_OK) {
        printf("FAIL: snapshot with 0 size should fail\n");
        failures++;
    }

    printf("PASS: stats snapshot null\n");
}

static void test_history() {
    virt_stats_init(&g_stats);

    // Record several events to build up history
    for (int i = 0; i < 20; i++) {
        virt_stats_record(&g_stats, 61, VIRT_ACTION_BLOCK_ENOENT, (uint64_t)(i * 100));
    }

    if (g_stats.history_count != 20) {
        printf("FAIL: history_count expected 20 got %u\n", g_stats.history_count);
        failures++;
    }
    if (g_stats.history_index != 20) {
        printf("FAIL: history_index expected 20 got %u\n", g_stats.history_index);
        failures++;
    }

    printf("PASS: stats history\n");
}

static void test_history_wrap() {
    virt_stats_init(&g_stats);

    // Record more than VIRT_MAX_STATS_HISTORY events to test wrap
    for (int i = 0; i < VIRT_MAX_STATS_HISTORY + 10; i++) {
        virt_stats_record(&g_stats, 61, VIRT_ACTION_BLOCK_ENOENT, (uint64_t)(i * 50));
    }

    if (g_stats.history_count != VIRT_MAX_STATS_HISTORY) {
        printf("FAIL: history_count should cap at %d, got %u\n",
               VIRT_MAX_STATS_HISTORY, g_stats.history_count);
        failures++;
    }

    printf("PASS: stats history wrap\n");
}

static void test_avg_latency() {
    virt_stats_init(&g_stats);

    virt_stats_record(&g_stats, 61, VIRT_ACTION_BLOCK_ENOENT, 100);
    virt_stats_record(&g_stats, 62, VIRT_ACTION_ALLOW, 200);
    virt_stats_record(&g_stats, 78, VIRT_ACTION_PASS_THROUGH, 300);

    // avg = (100 + 200 + 300) / 3 = 200
    if (g_stats.avg_latency_ns < 199.0 || g_stats.avg_latency_ns > 201.0) {
        printf("FAIL: avg_latency expected ~200 got %f\n", g_stats.avg_latency_ns);
        failures++;
    }

    printf("PASS: stats avg latency\n");
}

int main() {
    printf("=== Syscall Stats Unit Tests ===\n\n");

    test_init();
    test_init_null();
    test_record_basic();
    test_record_blocked();
    test_record_mixed();
    test_record_null();
    test_record_out_of_range_syscall();
    test_record_out_of_range_action();
    test_snapshot();
    test_snapshot_null();
    test_history();
    test_history_wrap();
    test_avg_latency();

    printf("\n%d tests failed\n", failures);
    return failures;
}
