#include "../../virtualizer.h"
#include <cstdio>
#include <cstring>
#include <cstdlib>

static int failures = 0;

static void test_default_config_valid() {
    VIRT_Config cfg = VIRT_DEFAULT_CONFIG;
    int errs = virt_config_validate(&cfg);
    if (errs != 0) {
        printf("FAIL: default config validate returned %d errors\n", errs);
        failures++;
        return;
    }
    if (cfg.cache_size != VIRT_MAX_CACHED_PATHS) {
        printf("FAIL: default cache_size %u != %u\n", cfg.cache_size, VIRT_MAX_CACHED_PATHS);
        failures++;
        return;
    }
    if (cfg.log_level != VIRT_LOG_LEVEL_INFO) {
        printf("FAIL: default log_level %d != %d\n", cfg.log_level, VIRT_LOG_LEVEL_INFO);
        failures++;
        return;
    }
    if (cfg.enable_stats != true) {
        printf("FAIL: default enable_stats not true\n");
        failures++;
        return;
    }
    if (cfg.handler_stack_size != VIRT_HANDLER_STACK_SIZE) {
        printf("FAIL: default handler_stack_size %u != %u\n",
               cfg.handler_stack_size, VIRT_HANDLER_STACK_SIZE);
        failures++;
        return;
    }
    printf("PASS: default config valid\n");
}

static void test_config_validate_clamps() {
    VIRT_Config cfg = VIRT_DEFAULT_CONFIG;

    // Test handler_stack_size clamping (too large)
    cfg.handler_stack_size = 100000000;
    int errs = virt_config_validate(&cfg);
    if (errs < 1) {
        printf("FAIL: should have error for oversized handler_stack\n");
        failures++;
        return;
    }
    if (cfg.handler_stack_size > 8388608) {
        printf("FAIL: handler_stack not clamped (%u)\n", cfg.handler_stack_size);
        failures++;
        return;
    }
    printf("PASS: config handler_stack_size clamp\n");

    // Test handler_stack_size clamping (too small)
    cfg = VIRT_DEFAULT_CONFIG;
    cfg.handler_stack_size = 1000;
    errs = virt_config_validate(&cfg);
    if (errs < 1) {
        printf("FAIL: should have error for undersized handler_stack\n");
        failures++;
        return;
    }
    if (cfg.handler_stack_size < 65536) {
        printf("FAIL: handler_stack not clamped up (%u)\n", cfg.handler_stack_size);
        failures++;
        return;
    }
    printf("PASS: config handler_stack_size clamp low\n");

    // Test cache_size clamping
    cfg = VIRT_DEFAULT_CONFIG;
    cfg.cache_size = 999999;
    errs = virt_config_validate(&cfg);
    if (errs < 1) {
        printf("FAIL: should warn for oversized cache\n");
        failures++;
        return;
    }
    if (cfg.cache_size > VIRT_MAX_CACHED_PATHS) {
        printf("FAIL: cache_size not clamped (%u)\n", cfg.cache_size);
        failures++;
        return;
    }
    printf("PASS: config cache_size clamp\n");

    // Test log_level clamping
    cfg = VIRT_DEFAULT_CONFIG;
    cfg.log_level = 99;
    errs = virt_config_validate(&cfg);
    if (cfg.log_level > 5) {
        printf("FAIL: log_level not clamped (%d)\n", cfg.log_level);
        failures++;
        return;
    }
    printf("PASS: config log_level clamp\n");

    // Test jitter clamping
    cfg = VIRT_DEFAULT_CONFIG;
    cfg.timing_jitter_us = 99999;
    errs = virt_config_validate(&cfg);
    if (cfg.timing_jitter_us > 10000) {
        printf("FAIL: jitter not clamped (%u)\n", cfg.timing_jitter_us);
        failures++;
        return;
    }
    printf("PASS: config jitter clamp\n");
}

static void test_config_load_nonexistent() {
    // Loading a non-existent file should return OK with defaults
    VIRT_Config cfg;
    memset(&cfg, 0, sizeof(cfg));
    int rc = virt_config_load("/nonexistent/config.txt", &cfg);
    if (rc != VIRT_OK) {
        printf("FAIL: load nonexistent file should return OK (got %d)\n", rc);
        failures++;
        return;
    }
    if (strcmp(cfg.log_tag, VIRT_DEFAULT_CONFIG.log_tag) != 0) {
        printf("FAIL: defaults not loaded for log_tag\n");
        failures++;
        return;
    }
    if (cfg.cache_size != VIRT_DEFAULT_CONFIG.cache_size) {
        printf("FAIL: defaults not loaded for cache_size\n");
        failures++;
        return;
    }
    printf("PASS: config load nonexistent returns defaults\n");
}

static void test_config_load_valid_file() {
    // Create a temporary config file
    const char *tmp_path = "/tmp/virt_test_config.txt";
    FILE *f = fopen(tmp_path, "w");
    if (!f) {
        printf("FAIL: cannot create temp file\n");
        failures++;
        return;
    }
    fprintf(f, "log_level=5\n");
    fprintf(f, "filter_mode=1\n");
    fprintf(f, "enable_stats=0\n");
    fprintf(f, "enable_cache=0\n");
    fprintf(f, "cache_size=100\n");
    fprintf(f, "handler_stack_size=131072\n");
    fprintf(f, "enable_watchdog=0\n");
    fprintf(f, "enable_anti_tamper=0\n");
    fprintf(f, "enable_proc_hiding=0\n");
    fprintf(f, "enable_fake_content=0\n");
    fprintf(f, "enable_timing_jitter=1\n");
    fprintf(f, "timing_jitter_us=500\n");
    fprintf(f, "jitter_range_us=100\n");
    fprintf(f, "notif_timeout_ms=3000\n");
    fprintf(f, "max_consecutive_errors=5\n");
    fprintf(f, "log_test=1\n");
    fprintf(f, "enable_thread_sync=0\n");
    fprintf(f, "enable_kernel_compat=0\n");
    fprintf(f, "enable_self_diagnostics=0\n");
    fprintf(f, "enable_event_ring=0\n");
    fprintf(f, "enable_trie_index=0\n");
    fclose(f);

    VIRT_Config cfg;
    memset(&cfg, 0, sizeof(cfg));
    int rc = virt_config_load(tmp_path, &cfg);
    if (rc != VIRT_OK) {
        printf("FAIL: load valid file returned %d\n", rc);
        failures++;
        return;
    }

    // Verify loaded values
    if (cfg.log_level != 5) {
        printf("FAIL: log_level expected 5 got %d\n", cfg.log_level);
        failures++;
    }
    if (cfg.filter_mode != 1) {
        printf("FAIL: filter_mode expected 1 got %d\n", cfg.filter_mode);
        failures++;
    }
    if (cfg.enable_stats != false) {
        printf("FAIL: enable_stats expected 0 got %d\n", cfg.enable_stats);
        failures++;
    }
    if (cfg.enable_cache != false) {
        printf("FAIL: enable_cache expected 0 got %d\n", cfg.enable_cache);
        failures++;
    }
    if (cfg.cache_size != 100) {
        printf("FAIL: cache_size expected 100 got %u\n", cfg.cache_size);
        failures++;
    }
    if (cfg.handler_stack_size != 131072) {
        printf("FAIL: handler_stack_size expected 131072 got %u\n", cfg.handler_stack_size);
        failures++;
    }
    if (cfg.enable_watchdog != false) {
        printf("FAIL: enable_watchdog expected 0\n");
        failures++;
    }
    if (cfg.enable_anti_tamper != false) {
        printf("FAIL: enable_anti_tamper expected 0\n");
        failures++;
    }
    if (cfg.enable_proc_hiding != false) {
        printf("FAIL: enable_proc_hiding expected 0\n");
        failures++;
    }
    if (cfg.enable_fake_content != false) {
        printf("FAIL: enable_fake_content expected 0\n");
        failures++;
    }
    if (cfg.enable_timing_jitter != true) {
        printf("FAIL: enable_timing_jitter expected 1\n");
        failures++;
    }
    if (cfg.timing_jitter_us != 500) {
        printf("FAIL: timing_jitter_us expected 500 got %u\n", cfg.timing_jitter_us);
        failures++;
    }
    if (cfg.notif_timeout_ms != 3000) {
        printf("FAIL: notif_timeout_ms expected 3000 got %u\n", cfg.notif_timeout_ms);
        failures++;
    }
    if (cfg.max_consecutive_errors != 5) {
        printf("FAIL: max_consecutive_errors expected 5 got %u\n", cfg.max_consecutive_errors);
        failures++;
    }

    // Check that all bools set to 0 are correct
    if (cfg.enable_thread_sync != false) {
        printf("FAIL: enable_thread_sync expected 0\n");
        failures++;
    }
    if (cfg.enable_kernel_compat != false) {
        printf("FAIL: enable_kernel_compat expected 0\n");
        failures++;
    }
    if (cfg.enable_self_diagnostics != false) {
        printf("FAIL: enable_self_diagnostics expected 0\n");
        failures++;
    }
    if (cfg.enable_event_ring != false) {
        printf("FAIL: enable_event_ring expected 0\n");
        failures++;
    }
    if (cfg.enable_trie_index != false) {
        printf("FAIL: enable_trie_index expected 0\n");
        failures++;
    }

    printf("PASS: config load valid file\n");

    remove(tmp_path);
}

static void test_config_load_all_keys() {
    const char *tmp_path = "/tmp/virt_test_config_all.txt";
    FILE *f = fopen(tmp_path, "w");
    if (!f) {
        printf("FAIL: cannot create temp file\n");
        failures++;
        return;
    }
    // Test every config key
    fprintf(f, "log_level=1\n");
    fprintf(f, "filter_mode=2\n");
    fprintf(f, "default_action=3\n");
    fprintf(f, "cache_size=500\n");
    fprintf(f, "stats_window_sec=120\n");
    fprintf(f, "watchdog_interval_sec=10\n");
    fprintf(f, "handler_stack_size=262144\n");
    fprintf(f, "notif_timeout_ms=2000\n");
    fprintf(f, "max_rules=512\n");
    fprintf(f, "max_consecutive_errors=3\n");
    fprintf(f, "enable_stats=1\n");
    fprintf(f, "enable_cache=1\n");
    fprintf(f, "enable_watchdog=1\n");
    fprintf(f, "enable_anti_tamper=1\n");
    fprintf(f, "enable_proc_hiding=1\n");
    fprintf(f, "enable_fake_content=1\n");
    fprintf(f, "enable_timing_jitter=1\n");
    fprintf(f, "enable_thread_sync=1\n");
    fprintf(f, "enable_kernel_compat=1\n");
    fprintf(f, "enable_self_diagnostics=1\n");
    fprintf(f, "enable_trie_index=1\n");
    fprintf(f, "enable_event_ring=1\n");
    fprintf(f, "enable_latency_tracking=1\n");
    fprintf(f, "enable_periodic_reporting=1\n");
    fprintf(f, "enable_jitter=1\n");
    fprintf(f, "jitter_base_us=200\n");
    fprintf(f, "jitter_range_us=50\n");
    fprintf(f, "enable_proc_hider=1\n");
    fprintf(f, "enable_file_decoy=1\n");
    fprintf(f, "fake_maps_path=/tmp/fake_maps\n");
    fprintf(f, "fake_status_path=/tmp/fake_status\n");
    fprintf(f, "rules_json_path=/tmp/rules.json\n");
    fprintf(f, "config_path=/tmp/config.txt\n");
    fprintf(f, "rules_path=/tmp/rules\n");
    fprintf(f, "log_tag=TestTag\n");
    fclose(f);

    VIRT_Config cfg;
    memset(&cfg, 0, sizeof(cfg));
    int rc = virt_config_load(tmp_path, &cfg);
    if (rc != VIRT_OK) {
        printf("FAIL: load all keys returned %d\n", rc);
        failures++;
        remove(tmp_path);
        return;
    }

    if (cfg.log_level != 1) { printf("FAIL: log_level\n"); failures++; }
    if (cfg.filter_mode != 2) { printf("FAIL: filter_mode\n"); failures++; }
    if (cfg.default_action != 3) { printf("FAIL: default_action\n"); failures++; }
    if (cfg.cache_size != 500) { printf("FAIL: cache_size\n"); failures++; }
    if (cfg.stats_window_sec != 120) { printf("FAIL: stats_window_sec\n"); failures++; }
    if (cfg.watchdog_interval_sec != 10) { printf("FAIL: watchdog_interval_sec\n"); failures++; }
    if (cfg.handler_stack_size != 262144) { printf("FAIL: handler_stack_size\n"); failures++; }
    if (cfg.notif_timeout_ms != 2000) { printf("FAIL: notif_timeout_ms\n"); failures++; }
    if (cfg.max_rules != 512) { printf("FAIL: max_rules\n"); failures++; }
    if (cfg.max_consecutive_errors != 3) { printf("FAIL: max_consecutive_errors\n"); failures++; }
    if (cfg.enable_stats != true) { printf("FAIL: enable_stats\n"); failures++; }
    if (cfg.enable_cache != true) { printf("FAIL: enable_cache\n"); failures++; }
    if (cfg.enable_watchdog != true) { printf("FAIL: enable_watchdog\n"); failures++; }
    if (cfg.enable_anti_tamper != true) { printf("FAIL: enable_anti_tamper\n"); failures++; }
    if (cfg.enable_proc_hiding != true) { printf("FAIL: enable_proc_hiding\n"); failures++; }
    if (cfg.enable_fake_content != true) { printf("FAIL: enable_fake_content\n"); failures++; }
    if (cfg.enable_timing_jitter != true) { printf("FAIL: enable_timing_jitter\n"); failures++; }
    if (cfg.enable_thread_sync != true) { printf("FAIL: enable_thread_sync\n"); failures++; }
    if (cfg.enable_kernel_compat != true) { printf("FAIL: enable_kernel_compat\n"); failures++; }
    if (cfg.enable_self_diagnostics != true) { printf("FAIL: enable_self_diagnostics\n"); failures++; }
    if (cfg.enable_trie_index != true) { printf("FAIL: enable_trie_index\n"); failures++; }
    if (cfg.enable_event_ring != true) { printf("FAIL: enable_event_ring\n"); failures++; }
    if (cfg.enable_latency_tracking != true) { printf("FAIL: enable_latency_tracking\n"); failures++; }
    if (cfg.enable_periodic_reporting != true) { printf("FAIL: enable_periodic_reporting\n"); failures++; }
    if (strcmp(cfg.fake_maps_path, "/tmp/fake_maps") != 0) { printf("FAIL: fake_maps_path\n"); failures++; }
    if (strcmp(cfg.fake_status_path, "/tmp/fake_status") != 0) { printf("FAIL: fake_status_path\n"); failures++; }
    if (strcmp(cfg.rules_json_path, "/tmp/rules.json") != 0) { printf("FAIL: rules_json_path\n"); failures++; }
    if (strcmp(cfg.config_path, "/tmp/config.txt") != 0) { printf("FAIL: config_path\n"); failures++; }
    if (strcmp(cfg.rules_path, "/tmp/rules") != 0) { printf("FAIL: rules_path\n"); failures++; }
    if (strcmp(cfg.log_tag, "TestTag") != 0) { printf("FAIL: log_tag\n"); failures++; }

    // jitter_base_us should set timing_jitter_us
    if (cfg.timing_jitter_us != 200) { printf("FAIL: jitter_base_us -> timing_jitter_us\n"); failures++; }
    // jitter_range_us
    if (cfg.jitter_range_us != 50) { printf("FAIL: jitter_range_us\n"); failures++; }

    if (failures == 0) {
        printf("PASS: config load all keys\n");
    }

    remove(tmp_path);
}

int main() {
    printf("=== Config Unit Tests ===\n\n");

    test_default_config_valid();
    test_config_validate_clamps();
    test_config_load_nonexistent();
    test_config_load_valid_file();
    test_config_load_all_keys();

    printf("\n%d tests failed\n", failures);
    return failures;
}
