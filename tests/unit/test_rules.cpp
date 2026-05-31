#include "../../virtualizer.h"
#include <cstdio>
#include <cstring>

static int failures = 0;

static VIRT_Rule g_rules[512];
static uint32_t g_rule_count = 0;

static void reset_rules() {
    g_rule_count = 0;
    memset(g_rules, 0, sizeof(g_rules));
}

static void test_add_and_count() {
    reset_rules();

    VIRT_Rule rule;
    memset(&rule, 0, sizeof(rule));
    virt_safe_strncpy(rule.pattern, "/proc/self/maps", sizeof(rule.pattern));
    rule.pattern_len = 15;
    rule.action = VIRT_ACTION_BLOCK_ENOENT;
    rule.priority = 100;
    rule.enabled = true;
    rule.category = VIRT_CAT_PROC;

    int rc = virt_rules_add(g_rules, &g_rule_count, 512, &rule);
    if (rc < 0) {
        printf("FAIL: rules add rc=%d\n", rc);
        failures++;
        return;
    }
    if (g_rule_count != 1) {
        printf("FAIL: rule count should be 1, got %u\n", g_rule_count);
        failures++;
        return;
    }

    int cnt = virt_rules_count_by_action(g_rules, g_rule_count, VIRT_ACTION_BLOCK_ENOENT);
    if (cnt != 1) {
        printf("FAIL: rules count by action expected 1, got %d\n", cnt);
        failures++;
    } else {
        printf("PASS: rules add and count\n");
    }
}

static void test_lookup() {
    reset_rules();

    VIRT_Rule rule;
    memset(&rule, 0, sizeof(rule));
    virt_safe_strncpy(rule.pattern, "/proc/self/maps", sizeof(rule.pattern));
    rule.pattern_len = 15;
    rule.action = VIRT_ACTION_BLOCK_ENOENT;
    rule.match_type = VIRT_MATCH_SUBSTRING;
    rule.priority = 100;
    rule.enabled = true;
    rule.category = VIRT_CAT_PROC;
    virt_rules_add(g_rules, &g_rule_count, 512, &rule);

    memset(&rule, 0, sizeof(rule));
    virt_safe_strncpy(rule.pattern, "frida", sizeof(rule.pattern));
    rule.pattern_len = 5;
    rule.action = VIRT_ACTION_BLOCK_ENOENT;
    rule.match_type = VIRT_MATCH_SUBSTRING;
    rule.priority = 200;
    rule.enabled = true;
    rule.category = VIRT_CAT_DEBUG;
    virt_rules_add(g_rules, &g_rule_count, 512, &rule);

    int action;
    int rc = virt_rules_lookup(g_rules, g_rule_count, "/proc/self/maps", 15, &action);
    if (rc < 0 || action != VIRT_ACTION_BLOCK_ENOENT) {
        printf("FAIL: rules lookup /proc/self/maps (rc=%d, action=%d)\n", rc, action);
        failures++;
    } else {
        printf("PASS: rules lookup /proc/self/maps\n");
    }

    rc = virt_rules_lookup(g_rules, g_rule_count, "/data/frida-agent.so", 20, &action);
    if (rc < 0 || action != VIRT_ACTION_BLOCK_ENOENT) {
        printf("FAIL: rules lookup frida (rc=%d, action=%d)\n", rc, action);
        failures++;
    } else {
        printf("PASS: rules lookup frida\n");
    }

    rc = virt_rules_lookup(g_rules, g_rule_count, "/system/lib/libc.so", 19, &action);
    if (rc >= 0) {
        printf("FAIL: rules lookup non-matching should fail\n");
        failures++;
    } else {
        printf("PASS: rules lookup non-matching\n");
    }
}

static void test_disabled_rule() {
    reset_rules();

    VIRT_Rule rule;
    memset(&rule, 0, sizeof(rule));
    virt_safe_strncpy(rule.pattern, "/proc/self/maps", sizeof(rule.pattern));
    rule.pattern_len = 15;
    rule.action = VIRT_ACTION_BLOCK_ENOENT;
    rule.match_type = VIRT_MATCH_SUBSTRING;
    rule.priority = 100;
    rule.enabled = false;
    rule.category = VIRT_CAT_PROC;
    virt_rules_add(g_rules, &g_rule_count, 512, &rule);

    int action;
    int rc = virt_rules_lookup(g_rules, g_rule_count, "/proc/self/maps", 15, &action);
    if (rc >= 0) {
        printf("FAIL: disabled rule should not match\n");
        failures++;
    } else {
        printf("PASS: disabled rule\n");
    }

    int cnt = virt_rules_count_by_action(g_rules, g_rule_count, VIRT_ACTION_BLOCK_ENOENT);
    if (cnt != 0) {
        printf("FAIL: disabled rule should not count\n");
        failures++;
    } else {
        printf("PASS: disabled rule not counted\n");
    }
}

static void test_priority_ordering() {
    reset_rules();

    VIRT_Rule rule;
    memset(&rule, 0, sizeof(rule));
    virt_safe_strncpy(rule.pattern, "/proc/", sizeof(rule.pattern));
    rule.pattern_len = 6;
    rule.action = VIRT_ACTION_FAKE_CONTENT;
    rule.match_type = VIRT_MATCH_PREFIX;
    rule.priority = 50;
    rule.enabled = true;
    virt_rules_add(g_rules, &g_rule_count, 512, &rule);

    memset(&rule, 0, sizeof(rule));
    virt_safe_strncpy(rule.pattern, "/proc/self/maps", sizeof(rule.pattern));
    rule.pattern_len = 15;
    rule.action = VIRT_ACTION_BLOCK_ENOENT;
    rule.match_type = VIRT_MATCH_PREFIX;
    rule.priority = 200;
    rule.enabled = true;
    virt_rules_add(g_rules, &g_rule_count, 512, &rule);

    virt_rules_sort(g_rules, g_rule_count);

    int action;
    virt_rules_lookup(g_rules, g_rule_count, "/proc/self/maps", 15, &action);
    if (action != VIRT_ACTION_BLOCK_ENOENT) {
        printf("FAIL: higher priority rule should win (action=%d)\n", action);
        failures++;
    } else {
        printf("PASS: rules priority ordering\n");
    }
}

static void test_remove() {
    reset_rules();

    VIRT_Rule rule;
    memset(&rule, 0, sizeof(rule));
    virt_safe_strncpy(rule.pattern, "/proc/self/maps", sizeof(rule.pattern));
    rule.action = VIRT_ACTION_BLOCK_ENOENT;
    rule.match_type = VIRT_MATCH_SUBSTRING;
    rule.priority = 100;
    rule.enabled = true;
    rule.is_system = false;
    rule.category = VIRT_CAT_PROC;
    virt_rules_add(g_rules, &g_rule_count, 512, &rule);

    int rc = virt_rules_remove(g_rules, &g_rule_count, 0);
    if (rc < 0 || g_rule_count != 0) {
        printf("FAIL: rules remove (rc=%d, count=%u)\n", rc, g_rule_count);
        failures++;
    } else {
        printf("PASS: rules remove\n");
    }
}

static void test_system_rule_protection() {
    reset_rules();

    VIRT_Rule rule;
    memset(&rule, 0, sizeof(rule));
    virt_safe_strncpy(rule.pattern, "/proc/self/maps", sizeof(rule.pattern));
    rule.action = VIRT_ACTION_BLOCK_ENOENT;
    rule.match_type = VIRT_MATCH_SUBSTRING;
    rule.priority = 100;
    rule.enabled = true;
    rule.is_system = true;
    rule.category = VIRT_CAT_PROC;
    virt_rules_add(g_rules, &g_rule_count, 512, &rule);

    int rc = virt_rules_remove(g_rules, &g_rule_count, 0);
    if (rc >= 0) {
        printf("FAIL: system rules should not be removable\n");
        failures++;
    } else {
        printf("PASS: system rule protection\n");
    }
}

static void test_count_by_category() {
    reset_rules();

    VIRT_Rule rule;
    memset(&rule, 0, sizeof(rule));
    virt_safe_strncpy(rule.pattern, "/proc/self/maps", sizeof(rule.pattern));
    rule.action = VIRT_ACTION_BLOCK_ENOENT;
    rule.enabled = true;
    rule.category = VIRT_CAT_PROC;
    virt_rules_add(g_rules, &g_rule_count, 512, &rule);

    memset(&rule, 0, sizeof(rule));
    virt_safe_strncpy(rule.pattern, "frida", sizeof(rule.pattern));
    rule.action = VIRT_ACTION_BLOCK_ENOENT;
    rule.enabled = true;
    rule.category = VIRT_CAT_DEBUG;
    virt_rules_add(g_rules, &g_rule_count, 512, &rule);

    memset(&rule, 0, sizeof(rule));
    virt_safe_strncpy(rule.pattern, "xposed", sizeof(rule.pattern));
    rule.action = VIRT_ACTION_BLOCK_ENOENT;
    rule.enabled = true;
    rule.category = VIRT_CAT_DEBUG;
    virt_rules_add(g_rules, &g_rule_count, 512, &rule);

    int proc_cnt = virt_rules_count_by_category(g_rules, g_rule_count, VIRT_CAT_PROC);
    int debug_cnt = virt_rules_count_by_category(g_rules, g_rule_count, VIRT_CAT_DEBUG);
    if (proc_cnt != 1 || debug_cnt != 2) {
        printf("FAIL: count by category (proc=%d, debug=%d)\n", proc_cnt, debug_cnt);
        failures++;
    } else {
        printf("PASS: count by category\n");
    }
}

static void test_load_defaults() {
    reset_rules();

    int rc = virt_rules_load_defaults(g_rules, &g_rule_count, 512);
    if (rc < 0 || g_rule_count == 0) {
        printf("FAIL: rules load defaults (rc=%d, count=%u)\n", rc, g_rule_count);
        failures++;
    } else {
        printf("PASS: rules load defaults (%u rules)\n", g_rule_count);
        if (g_rule_count != 179) {
            printf("FAIL: expected 179 default rules, got %u\n", g_rule_count);
            failures++;
        }
    }
}

static void test_overwrite_with_priority() {
    reset_rules();

    for (uint32_t i = 0; i < 100; i++) {
        VIRT_Rule rule;
        memset(&rule, 0, sizeof(rule));
        snprintf(rule.pattern, sizeof(rule.pattern), "/test/rule/%u", i);
        rule.action = VIRT_ACTION_BLOCK_ENOENT;
        rule.priority = 50;
        rule.enabled = true;
        rule.is_default = true;
        rule.category = VIRT_CAT_PROC;
        virt_rules_add(g_rules, &g_rule_count, 10, &rule);
    }

    if (g_rule_count != 10) {
        printf("FAIL: overwrite should keep max 10, got %u\n", g_rule_count);
        failures++;
    } else {
        printf("PASS: rules overwrite with priority\n");
    }
}

static void test_invalid_args() {
    reset_rules();

    int rc = virt_rules_add(NULL, &g_rule_count, 512, &g_rules[0]);
    if (rc >= 0) {
        printf("FAIL: rules add NULL rules should fail\n");
        failures++;
    } else {
        printf("PASS: rules add NULL rules fails\n");
    }

    int action;
    rc = virt_rules_lookup(NULL, g_rule_count, "/test", 5, &action);
    if (rc >= 0) {
        printf("FAIL: rules lookup NULL rules should fail\n");
        failures++;
    } else {
        printf("PASS: rules lookup NULL rules fails\n");
    }

    rc = virt_rules_sort(NULL, g_rule_count);
    if (rc >= 0) {
        printf("FAIL: rules sort NULL should fail\n");
        failures++;
    } else {
        printf("PASS: rules sort NULL fails\n");
    }

    rc = virt_rules_load_defaults(NULL, &g_rule_count, 512);
    if (rc >= 0) {
        printf("FAIL: rules load defaults NULL rules should fail\n");
        failures++;
    } else {
        printf("PASS: rules load defaults NULL rules fails\n");
    }
}

static void test_exact_match_rule() {
    reset_rules();

    VIRT_Rule rule;
    memset(&rule, 0, sizeof(rule));
    virt_safe_strncpy(rule.pattern, "/proc/self/maps", sizeof(rule.pattern));
    rule.pattern_len = 15;
    rule.action = VIRT_ACTION_BLOCK_ENOENT;
    rule.match_type = VIRT_MATCH_EXACT;
    rule.priority = 100;
    rule.enabled = true;
    rule.category = VIRT_CAT_PROC;
    virt_rules_add(g_rules, &g_rule_count, 512, &rule);

    int action;
    int rc = virt_rules_lookup(g_rules, g_rule_count, "/proc/self/maps", 15, &action);
    if (rc < 0 || action != VIRT_ACTION_BLOCK_ENOENT) {
        printf("FAIL: exact match lookup (rc=%d, action=%d)\n", rc, action);
        failures++;
    }

    // Slightly longer path should not match
    rc = virt_rules_lookup(g_rules, g_rule_count, "/proc/self/maps/extra", 21, &action);
    if (rc >= 0) {
        printf("FAIL: exact match should not match longer path\n");
        failures++;
    }

    printf("PASS: exact match rule\n");
}

static void test_prefix_match_rule() {
    reset_rules();

    VIRT_Rule rule;
    memset(&rule, 0, sizeof(rule));
    virt_safe_strncpy(rule.pattern, "/proc/self/", sizeof(rule.pattern));
    rule.pattern_len = 11;
    rule.action = VIRT_ACTION_FAKE_CONTENT;
    rule.match_type = VIRT_MATCH_PREFIX;
    rule.priority = 100;
    rule.enabled = true;
    virt_rules_add(g_rules, &g_rule_count, 512, &rule);

    int action;
    int rc = virt_rules_lookup(g_rules, g_rule_count, "/proc/self/status", 17, &action);
    if (rc < 0 || action != VIRT_ACTION_FAKE_CONTENT) {
        printf("FAIL: prefix match should match subpath (rc=%d, action=%d)\n", rc, action);
        failures++;
    }

    rc = virt_rules_lookup(g_rules, g_rule_count, "/proc/version", 13, &action);
    if (rc >= 0) {
        printf("FAIL: prefix match should not match different path\n");
        failures++;
    }

    printf("PASS: prefix match rule\n");
}

static void test_suffix_match_rule() {
    reset_rules();

    VIRT_Rule rule;
    memset(&rule, 0, sizeof(rule));
    virt_safe_strncpy(rule.pattern, "magisk", sizeof(rule.pattern));
    rule.pattern_len = 6;
    rule.action = VIRT_ACTION_BLOCK_ENOENT;
    rule.match_type = VIRT_MATCH_SUFFIX;
    rule.priority = 100;
    rule.enabled = true;
    virt_rules_add(g_rules, &g_rule_count, 512, &rule);

    int action;
    int rc = virt_rules_lookup(g_rules, g_rule_count, "/sbin/magisk", 12, &action);
    if (rc < 0 || action != VIRT_ACTION_BLOCK_ENOENT) {
        printf("FAIL: suffix match should match ending (rc=%d)\n", rc);
        failures++;
    }

    rc = virt_rules_lookup(g_rules, g_rule_count, "/sbin/magiskd", 13, &action);
    if (rc >= 0) {
        printf("FAIL: suffix should not match longer tail\n");
        failures++;
    }

    printf("PASS: suffix match rule\n");
}

static void test_disabled_not_counted() {
    reset_rules();

    VIRT_Rule rule;
    memset(&rule, 0, sizeof(rule));
    virt_safe_strncpy(rule.pattern, "/proc", sizeof(rule.pattern));
    rule.action = VIRT_ACTION_BLOCK_ENOENT;
    rule.enabled = true;
    rule.category = VIRT_CAT_PROC;
    virt_rules_add(g_rules, &g_rule_count, 512, &rule);

    memset(&rule, 0, sizeof(rule));
    virt_safe_strncpy(rule.pattern, "frida", sizeof(rule.pattern));
    rule.action = VIRT_ACTION_BLOCK_ENOENT;
    rule.enabled = false; // disabled
    rule.category = VIRT_CAT_DEBUG;
    virt_rules_add(g_rules, &g_rule_count, 512, &rule);

    // Count by action should only count enabled
    int cnt = virt_rules_count_by_action(g_rules, g_rule_count, VIRT_ACTION_BLOCK_ENOENT);
    if (cnt != 1) {
        printf("FAIL: count by action should exclude disabled (got %d)\n", cnt);
        failures++;
    }

    printf("PASS: disabled rules excluded from count\n");
}

int main() {
    printf("=== Rules Unit Tests ===\n\n");

    test_add_and_count();
    test_lookup();
    test_disabled_rule();
    test_priority_ordering();
    test_remove();
    test_system_rule_protection();
    test_count_by_category();
    test_load_defaults();
    test_overwrite_with_priority();
    test_invalid_args();
    test_exact_match_rule();
    test_prefix_match_rule();
    test_suffix_match_rule();
    test_disabled_not_counted();

    printf("\n%d tests failed\n", failures);
    return failures;
}
