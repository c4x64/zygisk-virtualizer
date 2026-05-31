#include "../../virtualizer.h"
#include <cstdio>
#include <cstring>

static int failures = 0;

// Define linux_dirent64 for use in tests (same layout as kernel)
struct my_dirent64 {
    uint64_t  d_ino;
    int64_t   d_off;
    uint16_t  d_reclen;
    uint8_t   d_type;
    char      d_name[];
};

#define MY_DT_REG 8

static VIRT_ProcHiderState g_state;

static void reset_state() {
    memset(&g_state, 0, sizeof(g_state));
    virt_proc_hider_init(&g_state);
}

static void test_init() {
    reset_state();
    if (!g_state.initialized) {
        printf("FAIL: proc hider not initialized\n");
        failures++;
    }
    if (g_state.hidden_fd_count != 0) {
        printf("FAIL: init should have 0 hidden fds\n");
        failures++;
    }
    printf("PASS: proc hider init\n");
}

static void test_add_fd() {
    reset_state();

    int rc = virt_proc_hider_add_fd(&g_state, 5);
    if (rc != VIRT_OK) {
        printf("FAIL: add fd 5 rc=%d\n", rc);
        failures++;
    }
    if (g_state.hidden_fd_count != 1 || g_state.hidden_fds[0] != 5) {
        printf("FAIL: fd count/val wrong (%u, %u)\n",
               g_state.hidden_fd_count, g_state.hidden_fds[0]);
        failures++;
    }

    // Duplicate add should be idempotent
    rc = virt_proc_hider_add_fd(&g_state, 5);
    if (g_state.hidden_fd_count != 1) {
        printf("FAIL: duplicate add should be idempotent (%u)\n", g_state.hidden_fd_count);
        failures++;
    }

    // Add negative fd should fail
    rc = virt_proc_hider_add_fd(&g_state, -1);
    if (rc >= 0) {
        printf("FAIL: add negative fd should fail\n");
        failures++;
    }

    // NULL state should fail
    rc = virt_proc_hider_add_fd(NULL, 5);
    if (rc >= 0) {
        printf("FAIL: NULL state should fail\n");
        failures++;
    }

    printf("PASS: proc hider add fd\n");
}

static void test_remove_fd() {
    reset_state();

    virt_proc_hider_add_fd(&g_state, 5);
    virt_proc_hider_add_fd(&g_state, 10);

    int rc = virt_proc_hider_remove_fd(&g_state, 5);
    if (rc != VIRT_OK || g_state.hidden_fd_count != 1 || g_state.hidden_fds[0] != 10) {
        printf("FAIL: remove fd 5 failed (rc=%d, count=%u, fds[0]=%u)\n",
               rc, g_state.hidden_fd_count, g_state.hidden_fds[0]);
        failures++;
    }

    rc = virt_proc_hider_remove_fd(&g_state, 99);
    if (rc >= 0) {
        printf("FAIL: remove non-existent fd should fail\n");
        failures++;
    }

    rc = virt_proc_hider_remove_fd(NULL, 5);
    if (rc >= 0) {
        printf("FAIL: NULL state remove should fail\n");
        failures++;
    }

    printf("PASS: proc hider remove fd\n");
}

static void test_check_fd_path() {
    reset_state();

    virt_proc_hider_add_fd(&g_state, 7);

    // /proc/self/fd/7 should match
    int rc = virt_proc_hider_check_fd_path(&g_state, "/proc/self/fd/7", 15);
    if (rc != 1) {
        printf("FAIL: should detect fd 7 in /proc/self/fd/7 (rc=%d)\n", rc);
        failures++;
    }

    // /proc/1234/fd/7 should also match
    rc = virt_proc_hider_check_fd_path(&g_state, "/proc/1234/fd/7", 16);
    if (rc != 1) {
        printf("FAIL: should detect fd 7 in /proc/1234/fd/7 (rc=%d)\n", rc);
        failures++;
    }

    // /proc/self/fd/8 should NOT match
    rc = virt_proc_hider_check_fd_path(&g_state, "/proc/self/fd/8", 15);
    if (rc != 0) {
        printf("FAIL: should not detect fd 8 (rc=%d)\n", rc);
        failures++;
    }

    // No /fd/ in path should not match
    rc = virt_proc_hider_check_fd_path(&g_state, "/proc/self/maps", 15);
    if (rc != 0) {
        printf("FAIL: path without /fd/ should not match\n");
        failures++;
    }

    // Empty path should not match
    rc = virt_proc_hider_check_fd_path(&g_state, "", 0);
    if (rc != 0) {
        printf("FAIL: empty path should not match\n");
        failures++;
    }

    // NULL state
    rc = virt_proc_hider_check_fd_path(NULL, "/proc/self/fd/7", 15);
    if (rc != 0) {
        printf("FAIL: NULL state should return 0\n");
        failures++;
    }

    printf("PASS: proc hider check fd path\n");
}

static int build_dirent_buf(char *buf, const char *names[], int count) {
    uint32_t pos = 0;
    for (int i = 0; i < count; i++) {
        size_t name_len = strlen(names[i]) + 1;
        uint16_t reclen = (uint16_t)(sizeof(struct my_dirent64) + name_len);
        if (reclen < sizeof(struct my_dirent64) + name_len) return -1;
        // Align to 8 bytes
        if (reclen % 8) reclen = (uint16_t)((reclen + 7) & ~7);
        struct my_dirent64 *ent = (struct my_dirent64 *)(buf + pos);
        memset(ent, 0, reclen);
        ent->d_ino = 100 + pos;
        ent->d_off = 0;
        ent->d_reclen = reclen;
        ent->d_type = MY_DT_REG;
        memcpy(ent->d_name, names[i], name_len);
        pos += reclen;
    }
    return (int)pos;
}

static int count_dirents(const char *buf, uint32_t len) {
    uint32_t pos = 0;
    int count = 0;
    while (pos < len) {
        const struct my_dirent64 *ent = (const struct my_dirent64 *)(buf + pos);
        if (ent->d_reclen == 0) break;
        count++;
        pos += ent->d_reclen;
    }
    return count;
}

static bool find_dirent(const char *buf, uint32_t len, const char *name) {
    uint32_t pos = 0;
    while (pos < len) {
        const struct my_dirent64 *ent = (const struct my_dirent64 *)(buf + pos);
        if (ent->d_reclen == 0) break;
        if (strcmp(ent->d_name, name) == 0) return true;
        pos += ent->d_reclen;
    }
    return false;
}

static void test_filter_dirents() {
    reset_state();

    virt_proc_hider_add_fd(&g_state, 3);
    virt_proc_hider_add_fd(&g_state, 7);

    char buf[1024];
    const char *names[] = {"1", "3", "5", "7", "9"};
    int dlen = build_dirent_buf(buf, names, 5);
    if (dlen < 0) {
        printf("FAIL: could not build dirent buffer\n");
        failures++;
        return;
    }

    char out[1024];
    uint32_t out_len = 0;
    int rc = virt_proc_hider_filter_dirents(&g_state, buf, (uint32_t)dlen, out, &out_len);
    if (rc != VIRT_OK) {
        printf("FAIL: filter dirents rc=%d\n", rc);
        failures++;
        return;
    }

    if (find_dirent(out, out_len, "3") || find_dirent(out, out_len, "7")) {
        printf("FAIL: hidden fds 3 or 7 still present in output\n");
        failures++;
    }
    if (count_dirents(out, out_len) != 3) {
        printf("FAIL: expected 3 entries after filter, got %d\n", count_dirents(out, out_len));
        failures++;
    }
    if (!find_dirent(out, out_len, "1") || !find_dirent(out, out_len, "5") || !find_dirent(out, out_len, "9")) {
        printf("FAIL: non-hidden entries missing from output\n");
        failures++;
    }

    printf("PASS: proc hider filter dirents\n");
}

static void test_filter_dirents_null_handling() {
    char buf[64], out[64];
    uint32_t out_len;

    int rc = virt_proc_hider_filter_dirents(NULL, buf, 64, out, &out_len);
    if (rc >= 0) {
        printf("FAIL: NULL state should fail\n");
        failures++;
    }
    rc = virt_proc_hider_filter_dirents(&g_state, NULL, 64, out, &out_len);
    if (rc >= 0) {
        printf("FAIL: NULL dirents should fail\n");
        failures++;
    }
    rc = virt_proc_hider_filter_dirents(&g_state, buf, 64, NULL, &out_len);
    if (rc >= 0) {
        printf("FAIL: NULL out should fail\n");
        failures++;
    }
    rc = virt_proc_hider_filter_dirents(&g_state, buf, 64, out, NULL);
    if (rc >= 0) {
        printf("FAIL: NULL out_len should fail\n");
        failures++;
    }

    printf("PASS: proc hider filter dirents null\n");
}

static void test_filter_dirents_empty() {
    reset_state();

    char buf[64];
    uint32_t dlen = 0;
    char out[64];
    uint32_t out_len = 0;

    int rc = virt_proc_hider_filter_dirents(&g_state, buf, dlen, out, &out_len);
    if (rc != VIRT_OK || out_len != 0) {
        printf("FAIL: empty filter should return OK (rc=%d, out_len=%u)\n", rc, out_len);
        failures++;
    }

    printf("PASS: proc hider filter empty\n");
}

static void test_filter_dirents_all_filtered() {
    reset_state();

    virt_proc_hider_add_fd(&g_state, 1);

    char buf[256];
    const char *names[] = {"1"};
    int dlen = build_dirent_buf(buf, names, 1);
    if (dlen < 0) {
        printf("FAIL: could not build dirent buffer\n");
        failures++;
        return;
    }

    char out[256];
    uint32_t out_len = 0;
    int rc = virt_proc_hider_filter_dirents(&g_state, buf, (uint32_t)dlen, out, &out_len);
    if (rc != VIRT_OK) {
        printf("FAIL: all-filtered rc=%d\n", rc);
        failures++;
        return;
    }
    if (out_len != 0) {
        printf("FAIL: all-filtered should produce empty output\n");
        failures++;
    }

    printf("PASS: proc hider filter all filtered\n");
}

static void test_add_pid() {
    reset_state();

    int rc = virt_proc_hider_add_pid(&g_state, 100);
    if (rc != VIRT_OK || g_state.hidden_pid_count != 1 || g_state.hidden_pids[0] != 100) {
        printf("FAIL: add pid failed (rc=%d, count=%u)\n", rc, g_state.hidden_pid_count);
        failures++;
    }

    rc = virt_proc_hider_add_pid(&g_state, 100);
    if (g_state.hidden_pid_count != 1) {
        printf("FAIL: duplicate pid should be idempotent\n");
        failures++;
    }

    rc = virt_proc_hider_add_pid(NULL, 100);
    if (rc >= 0) {
        printf("FAIL: NULL state add pid should fail\n");
        failures++;
    }

    printf("PASS: proc hider add pid\n");
}

static void test_remove_pid() {
    reset_state();

    virt_proc_hider_add_pid(&g_state, 100);

    int rc = virt_proc_hider_remove_pid(&g_state, 100);
    if (rc != VIRT_OK || g_state.hidden_pid_count != 0) {
        printf("FAIL: remove pid failed (rc=%d, count=%u)\n", rc, g_state.hidden_pid_count);
        failures++;
    }

    rc = virt_proc_hider_remove_pid(&g_state, 999);
    if (rc >= 0) {
        printf("FAIL: remove non-existent pid should fail\n");
        failures++;
    }

    printf("PASS: proc hider remove pid\n");
}

static void test_add_tid() {
    reset_state();

    int rc = virt_proc_hider_add_tid(&g_state, 50);
    if (rc != VIRT_OK || g_state.hidden_tid_count != 1 || g_state.hidden_tids[0] != 50) {
        printf("FAIL: add tid failed\n");
        failures++;
    }

    rc = virt_proc_hider_add_tid(NULL, 50);
    if (rc >= 0) {
        printf("FAIL: NULL state add tid should fail\n");
        failures++;
    }

    printf("PASS: proc hider add tid\n");
}

int main() {
    printf("=== Proc Hider Unit Tests ===\n\n");

    test_init();
    test_add_fd();
    test_remove_fd();
    test_check_fd_path();
    test_filter_dirents();
    test_filter_dirents_null_handling();
    test_filter_dirents_empty();
    test_filter_dirents_all_filtered();
    test_add_pid();
    test_remove_pid();
    test_add_tid();

    printf("\n%d tests failed\n", failures);
    return failures;
}
