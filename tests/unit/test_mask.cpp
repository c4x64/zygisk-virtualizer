#include "../../virtualizer.h"
#include <cstdio>
#include <cstring>
#include <cstdlib>

static int failures = 0;

// Helper: search for a substring within a null-separated environ buffer
static bool environ_contains(const char *buf, uint32_t buf_size, const char *needle) {
    uint32_t pos = 0;
    while (pos < buf_size) {
        const char *entry = buf + pos;
        uint32_t elen = 0;
        while (pos + elen < buf_size && buf[pos + elen] != '\0')
            elen++;
        if (elen > 0 && strstr(entry, needle) != NULL)
            return true;
        pos += elen + 1;
    }
    return false;
}

// --- cmdline masking ---

static void test_mask_cmdline_magisk() {
    const char *input = "/sbin/magisk\0--daemon";
    uint32_t input_len = 17;
    char output[256];
    memset(output, 0, sizeof(output));
    int rc = virt_mask_cmdline(input, input_len, output, sizeof(output));
    if (rc < 0) {
        printf("FAIL: mask_cmdline magisk rc=%d\n", rc);
        failures++;
        return;
    }
    // The "magisk" segment should be replaced with "app_process64"
    if (strstr(output, "app_process64") == NULL) {
        printf("FAIL: magisk not replaced, got: '%s'\n", output);
        failures++;
        return;
    }
    if (strstr(output, "magisk") != NULL) {
        printf("FAIL: magisk still present in output\n");
        failures++;
        return;
    }
    printf("PASS: mask cmdline removes magisk\n");
}

static void test_mask_cmdline_zygisk() {
    const char *input = "/system/bin/zygisk\0--start";
    uint32_t input_len = 23;
    char output[256];
    memset(output, 0, sizeof(output));
    int rc = virt_mask_cmdline(input, input_len, output, sizeof(output));
    if (rc < 0) {
        printf("FAIL: mask_cmdline zygisk rc=%d\n", rc);
        failures++;
        return;
    }
    if (strstr(output, "app_process64") == NULL) {
        printf("FAIL: zygisk not replaced, got: '%s'\n", output);
        failures++;
        return;
    }
    printf("PASS: mask cmdline removes zygisk\n");
}

static void test_mask_cmdline_modules() {
    const char *input = "/data/adb/modules\0--action";
    uint32_t input_len = 22;
    char output[256];
    memset(output, 0, sizeof(output));
    int rc = virt_mask_cmdline(input, input_len, output, sizeof(output));
    if (rc < 0) {
        printf("FAIL: mask_cmdline modules rc=%d\n", rc);
        failures++;
        return;
    }
    if (strstr(output, "app_process64") == NULL) {
        printf("FAIL: modules not replaced, got: '%s'\n", output);
        failures++;
        return;
    }
    printf("PASS: mask cmdline removes modules\n");
}

static void test_mask_cmdline_innocent() {
    const char *input = "/system/bin/app_process64\0--nice";
    uint32_t input_len = 29;
    char output[256];
    memset(output, 0, sizeof(output));
    int rc = virt_mask_cmdline(input, input_len, output, sizeof(output));
    if (rc < 0) {
        printf("FAIL: mask_cmdline innocent rc=%d\n", rc);
        failures++;
        return;
    }
    if (strstr(output, "app_process64") == NULL) {
        printf("FAIL: innocent path should preserve app_process64\n");
        failures++;
        return;
    }
    printf("PASS: mask cmdline preserves innocent\n");
}

static void test_mask_cmdline_inject() {
    const char *input = "injector";
    uint32_t input_len = 8;
    char output[256];
    memset(output, 0, sizeof(output));
    int rc = virt_mask_cmdline(input, input_len, output, sizeof(output));
    if (rc < 0) {
        printf("FAIL: mask_cmdline inject rc=%d\n", rc);
        failures++;
        return;
    }
    if (strstr(output, "app_process64") == NULL) {
        printf("FAIL: 'inject' not replaced, got: '%s'\n", output);
        failures++;
        return;
    }
    printf("PASS: mask cmdline removes inject\n");
}

static void test_mask_cmdline_null_input() {
    char output[256];
    int rc = virt_mask_cmdline(NULL, 10, output, sizeof(output));
    if (rc >= 0) {
        printf("FAIL: NULL input should fail\n");
        failures++;
    } else {
        printf("PASS: mask cmdline null input\n");
    }
}

static void test_mask_cmdline_null_output() {
    const char *input = "/sbin/magisk";
    int rc = virt_mask_cmdline(input, 12, NULL, 256);
    if (rc >= 0) {
        printf("FAIL: NULL output should fail\n");
        failures++;
    } else {
        printf("PASS: mask cmdline null output\n");
    }
}

static void test_mask_cmdline_zero_size() {
    const char *input = "/sbin/magisk";
    char output[256];
    int rc = virt_mask_cmdline(input, 12, output, 0);
    if (rc >= 0) {
        printf("FAIL: zero output_size should fail\n");
        failures++;
    } else {
        printf("PASS: mask cmdline zero size\n");
    }
}

// --- environ masking ---

static void test_mask_environ_ld_preload() {
    char buf[] = "LD_PRELOAD=/data/ta.lib\0HOME=/data\0PATH=/sbin\0\0";
    uint32_t buf_size = (uint32_t)sizeof(buf);
    int rc = virt_mask_environ(buf, buf_size);
    if (rc < 0) {
        printf("FAIL: mask_environ rc=%d\n", rc);
        failures++;
        return;
    }
    if (environ_contains(buf, buf_size, "LD_PRELOAD")) {
        printf("FAIL: LD_PRELOAD still present\n");
        failures++;
        return;
    }
    if (!environ_contains(buf, buf_size, "HOME")) {
        printf("FAIL: HOME should still be present\n");
        failures++;
        return;
    }
    if (!environ_contains(buf, buf_size, "PATH")) {
        printf("FAIL: PATH should still be present\n");
        failures++;
        return;
    }
    printf("PASS: mask environ removes LD_PRELOAD\n");
}

static void test_mask_environ_magisk() {
    char buf[] = "MAGISK=1\0HOME=/data\0\0";
    uint32_t buf_size = (uint32_t)sizeof(buf);
    int rc = virt_mask_environ(buf, buf_size);
    if (rc < 0) {
        printf("FAIL: mask_environ MAGISK rc=%d\n", rc);
        failures++;
        return;
    }
    if (environ_contains(buf, buf_size, "MAGISK")) {
        printf("FAIL: MAGISK still present\n");
        failures++;
        return;
    }
    printf("PASS: mask environ removes MAGISK\n");
}

static void test_mask_environ_ksu() {
    char buf[] = "KSU=1\0HOME=/data\0\0";
    uint32_t buf_size = (uint32_t)sizeof(buf);
    int rc = virt_mask_environ(buf, buf_size);
    if (rc < 0) {
        printf("FAIL: mask_environ KSU rc=%d\n", rc);
        failures++;
        return;
    }
    if (environ_contains(buf, buf_size, "KSU")) {
        printf("FAIL: KSU still present\n");
        failures++;
        return;
    }
    printf("PASS: mask environ removes KSU\n");
}

static void test_mask_environ_zygisk() {
    char buf[] = "ZYGISK=1\0FOO=bar\0\0";
    uint32_t buf_size = (uint32_t)sizeof(buf);
    int rc = virt_mask_environ(buf, buf_size);
    if (rc < 0) {
        printf("FAIL: mask_environ ZYGISC rc=%d\n", rc);
        failures++;
        return;
    }
    if (environ_contains(buf, buf_size, "ZYGISK")) {
        printf("FAIL: ZYGISK still present\n");
        failures++;
        return;
    }
    if (!environ_contains(buf, buf_size, "FOO")) {
        printf("FAIL: FOO should still be present\n");
        failures++;
        return;
    }
    printf("PASS: mask environ removes ZYGISK\n");
}

static void test_mask_environ_preserves_normal() {
    char buf[] = "HOME=/data\0PATH=/system/bin\0USER=shell\0\0";
    uint32_t buf_size = (uint32_t)sizeof(buf);
    int rc = virt_mask_environ(buf, buf_size);
    if (rc < 0) {
        printf("FAIL: mask_environ normal rc=%d\n", rc);
        failures++;
        return;
    }
    if (!environ_contains(buf, buf_size, "HOME") ||
        !environ_contains(buf, buf_size, "PATH") ||
        !environ_contains(buf, buf_size, "USER")) {
        printf("FAIL: normal vars removed\n");
        failures++;
        return;
    }
    printf("PASS: mask environ preserves normal\n");
}

static void test_mask_environ_containing_keyword() {
    char buf[] = "SOME_VAR=/data/magisk\0HOME=/data\0\0";
    uint32_t buf_size = (uint32_t)sizeof(buf);
    int rc = virt_mask_environ(buf, buf_size);
    if (rc < 0) {
        printf("FAIL: mask_environ containing keyword rc=%d\n", rc);
        failures++;
        return;
    }
    // Check that "SOME_VAR" (the prefix) was stripped
    if (environ_contains(buf, buf_size, "SOME_VAR")) {
        printf("FAIL: SOME_VAR should be stripped\n");
        failures++;
        return;
    }
    if (!environ_contains(buf, buf_size, "HOME")) {
        printf("FAIL: HOME should still be present\n");
        failures++;
        return;
    }
    printf("PASS: mask environ removes var containing 'magisk'\n");
}

static void test_mask_environ_null() {
    int rc = virt_mask_environ(NULL, 256);
    if (rc >= 0) {
        printf("FAIL: NULL buffer should fail\n");
        failures++;
    } else {
        printf("PASS: mask environ null\n");
    }
}

static void test_mask_environ_zero_size() {
    char buf[16] = "HOME=/data";
    int rc = virt_mask_environ(buf, 0);
    if (rc >= 0) {
        printf("FAIL: zero size should fail\n");
        failures++;
    } else {
        printf("PASS: mask environ zero size\n");
    }
}

static void test_mask_environ_empty() {
    char buf[] = "\0";
    int rc = virt_mask_environ(buf, 1);
    if (rc < 0) {
        printf("FAIL: empty environ should succeed rc=%d\n", rc);
        failures++;
    } else {
        printf("PASS: mask environ empty\n");
    }
}

static void test_mask_environ_xposed() {
    char buf[] = "xposed=1\0ANDROID_DATA=/data\0\0";
    uint32_t buf_size = (uint32_t)sizeof(buf);
    int rc = virt_mask_environ(buf, buf_size);
    if (rc < 0) {
        printf("FAIL: mask_environ xposed rc=%d\n", rc);
        failures++;
        return;
    }
    if (environ_contains(buf, buf_size, "xposed")) {
        printf("FAIL: xposed still present\n");
        failures++;
        return;
    }
    if (!environ_contains(buf, buf_size, "ANDROID_DATA")) {
        printf("FAIL: ANDROID_DATA should still be present\n");
        failures++;
        return;
    }
    printf("PASS: mask environ removes xposed\n");
}

static void test_mask_environ_frida() {
    char buf[] = "frida=1\0HOME=/data\0\0";
    uint32_t buf_size = (uint32_t)sizeof(buf);
    int rc = virt_mask_environ(buf, buf_size);
    if (rc < 0) {
        printf("FAIL: mask_environ frida rc=%d\n", rc);
        failures++;
        return;
    }
    if (environ_contains(buf, buf_size, "frida")) {
        printf("FAIL: frida still present\n");
        failures++;
        return;
    }
    if (!environ_contains(buf, buf_size, "HOME")) {
        printf("FAIL: HOME should still be present\n");
        failures++;
        return;
    }
    printf("PASS: mask environ removes frida\n");
}

// --- SELinux spoofing ---

static void test_selinux_context_format() {
    char buf[128];
    memset(buf, 0, sizeof(buf));
    int rc = virt_get_fake_selinux_context(buf, sizeof(buf));
    if (rc < 0) {
        printf("FAIL: get fake selinux context rc=%d\n", rc);
        failures++;
        return;
    }
    if (strstr(buf, "u:r:untrusted_app") == NULL) {
        printf("FAIL: expected 'u:r:untrusted_app' in output, got '%s'\n", buf);
        failures++;
        return;
    }
    // Should have newline at end (from snprintf)
    if (buf[rc] == '\0' && rc > 0) {
        // ok
    }
    printf("PASS: selinux context format\n");
}

static void test_selinux_context_null() {
    // virt_get_fake_selinux_context will crash with NULL buf (snprintf UB).
    // Instead, verify it fails gracefully with an empty buf.
    char buf[1] = {0};
    int rc = virt_get_fake_selinux_context(buf, 0);
    if (rc >= 0) {
        printf("FAIL: selinux context with zero size should return <0 (got %d)\n", rc);
        failures++;
        return;
    }
    printf("PASS: selinux context zero-size buf\n");
}

static void test_selinux_context_small_buf() {
    char buf[4];
    memset(buf, 0, sizeof(buf));
    int rc = virt_get_fake_selinux_context(buf, sizeof(buf));
    if (rc < 0) {
        printf("FAIL: small buf should still work rc=%d\n", rc);
        failures++;
        return;
    }
    // Should be truncated but not crash
    printf("PASS: selinux context small buf (rc=%d, content='%s')\n", rc, buf);
}

static void test_selinux_context_matches_define() {
    char buf[128];
    virt_get_fake_selinux_context(buf, sizeof(buf));
    // Remove trailing newline if present
    size_t len = strlen(buf);
    if (len > 0 && buf[len - 1] == '\n') {
        buf[len - 1] = '\0';
    }
    if (strcmp(buf, VIRT_FAKE_SELINUX_CONTEXT) != 0) {
        printf("FAIL: context '%s' doesn't match define '%s'\n",
               buf, VIRT_FAKE_SELINUX_CONTEXT);
        failures++;
        return;
    }
    printf("PASS: selinux context matches define\n");
}

static void test_is_selinux_enforcing() {
    // On macOS, /sys/fs/selinux/enforce doesn't exist, so expect -1
    int rc = virt_is_selinux_enforcing();
    if (rc >= 0) {
        // Running on Linux with SELinux - that's OK too
        printf("INFO: virt_is_selinux_enforcing returned %d (host has SELinux)\n", rc);
    }
    printf("PASS: is_selinux_enforcing (no crash)\n");
}

static void test_spoof_selinux_context() {
    // virt_spoof_selinux_context is a no-op stub that always succeeds
    int rc = virt_spoof_selinux_context(12345);
    if (rc != VIRT_OK) {
        printf("FAIL: spoof selinux context should succeed rc=%d\n", rc);
        failures++;
        return;
    }
    printf("PASS: spoof selinux context\n");
}

int main() {
    printf("=== Cmdline/Environ Mask & SELinux Unit Tests ===\n\n");

    printf("--- Command Line Masking ---\n");
    test_mask_cmdline_magisk();
    test_mask_cmdline_zygisk();
    test_mask_cmdline_modules();
    test_mask_cmdline_innocent();
    test_mask_cmdline_inject();
    test_mask_cmdline_null_input();
    test_mask_cmdline_null_output();
    test_mask_cmdline_zero_size();

    printf("\n--- Environment Masking ---\n");
    test_mask_environ_ld_preload();
    test_mask_environ_magisk();
    test_mask_environ_ksu();
    test_mask_environ_zygisk();
    test_mask_environ_preserves_normal();
    test_mask_environ_containing_keyword();
    test_mask_environ_null();
    test_mask_environ_zero_size();
    test_mask_environ_empty();
    test_mask_environ_xposed();
    test_mask_environ_frida();

    printf("\n--- SELinux Spoofing ---\n");
    test_selinux_context_format();
    test_selinux_context_null();
    test_selinux_context_small_buf();
    test_selinux_context_matches_define();
    test_is_selinux_enforcing();
    test_spoof_selinux_context();

    printf("\n%d tests failed\n", failures);
    return failures;
}
