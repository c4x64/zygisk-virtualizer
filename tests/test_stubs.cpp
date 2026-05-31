#include "../virtualizer.h"
#include <cstdio>
#include <cstdlib>

// Stubs for seccomp_engine.cpp functions used by virtualizer_core.cpp
// These are not tested in unit tests - they are tested in integration tests.

int virt_seccomp_get_features(int *out_features) {
    static int cached = -1;
    if (cached < 0) {
        // On host test environment, probe is not possible
        // Return minimum feature set for testing
        cached = (1 | 2 | 4); // USER_NOTIF | NEW_LISTENER | TSYNC
    }
    if (out_features) *out_features = cached;
    return cached;
}

uint64_t virt_seccomp_get_event_count(void) { return 0; }
uint64_t virt_seccomp_get_error_count(void) { return 0; }
uint64_t virt_seccomp_get_continue_fallback_count(void) { return 0; }
bool virt_seccomp_has_continue(void) { return false; }
uint32_t virt_seccomp_get_active_listeners(void) { return 0; }
uint32_t virt_seccomp_get_total_listeners(void) { return 0; }
uint64_t virt_seccomp_get_avg_latency_ns(void) { return 0; }

bool virt_decoy_file_create(const char *path, const char *const *lines) {
    (void)path;
    (void)lines;
    return true;
}
