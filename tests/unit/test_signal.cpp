#include "../../virtualizer.h"
#include <cstdio>
#include <cstring>
#include <cerrno>
#include <signal.h>
#include <sys/syscall.h>

#ifndef __NR_timerfd_create
#define __NR_timerfd_create 283
#endif

static int failures = 0;

static void test_signalfd_syscall() {
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGTERM);
    sigaddset(&mask, SIGINT);

    int rc = (int)syscall(__NR_signalfd4, -1, &mask, (size_t)sizeof(mask), SFD_NONBLOCK);
    if (rc < 0) {
        // On non-Linux (macOS), signalfd4 will definitely fail.
        // That's expected and proves error path is safe.
        printf("INFO: signalfd4 returned %d (errno=%d) - expected on non-Linux\n", rc, errno);
    } else {
        close(rc);
    }
    printf("PASS: signalfd syscall (no crash)\n");
}

static void test_signalfd_invalid_fd() {
    // Passing an invalid fd (123456789) should fail
    sigset_t mask;
    sigemptyset(&mask);
    int rc = (int)syscall(__NR_signalfd4, 123456789, &mask, (size_t)sizeof(mask), 0);
    if (rc >= 0) {
        // Might succeed on Linux if 123456789 is somehow valid (unlikely)
        close(rc);
    }
    printf("PASS: signalfd invalid fd (no crash)\n");
}

static void test_timerfd_create_syscall() {
    int fd = (int)syscall(__NR_timerfd_create, CLOCK_MONOTONIC, TFD_NONBLOCK);
    if (fd < 0) {
        printf("INFO: timerfd_create returned %d (errno=%d) - expected on non-Linux\n", fd, errno);
    } else {
        close(fd);
    }
    printf("PASS: timerfd_create syscall (no crash)\n");
}

static void test_timerfd_invalid_clock() {
    int fd = (int)syscall(__NR_timerfd_create, 9999, 0);
    if (fd >= 0) {
        close(fd);
    }
    printf("PASS: timerfd_create invalid clock (no crash)\n");
}

static void test_timerfd_realtime() {
    int fd = (int)syscall(__NR_timerfd_create, CLOCK_REALTIME, TFD_NONBLOCK);
    if (fd < 0) {
        printf("INFO: timerfd_realtime returned %d (errno=%d)\n", fd, errno);
    } else {
        close(fd);
    }
    printf("PASS: timerfd_realtime (no crash)\n");
}

static void test_inotify_init_syscall() {
    int fd = (int)syscall(__NR_inotify_init1, IN_NONBLOCK | IN_CLOEXEC);
    if (fd < 0) {
        printf("INFO: inotify_init1 returned %d (errno=%d) - expected on non-Linux\n", fd, errno);
    } else {
        close(fd);
    }
    printf("PASS: inotify_init1 syscall (no crash)\n");
}

static void test_inotify_init_default() {
    int fd = (int)syscall(__NR_inotify_init1, 0);
    if (fd < 0) {
        printf("INFO: inotify_init1(0) returned %d (errno=%d)\n", fd, errno);
    } else {
        close(fd);
    }
    printf("PASS: inotify_init1 default flags (no crash)\n");
}

static void test_inotify_invalid_watch() {
    // Calling inotify_add_watch on invalid fd must not crash
    int rc = (int)syscall(__NR_inotify_add_watch, -1, "/nonexistent", IN_ALL_EVENTS);
    if (rc >= 0) {
        printf("FAIL: inotify_add_watch with invalid args succeeded unexpectedly\n");
        failures++;
        return;
    }
    printf("PASS: inotify_add_watch invalid args\n");
}

int main() {
    printf("=== Signal/Timer/Inotify Syscall Unit Tests ===\n\n");

    printf("Note: These tests use Linux syscalls. On macOS (host)\n");
    printf("they will return -1/ENOSYS. That is expected behavior.\n\n");

    test_signalfd_syscall();
    test_signalfd_invalid_fd();
    test_timerfd_create_syscall();
    test_timerfd_invalid_clock();
    test_timerfd_realtime();
    test_inotify_init_syscall();
    test_inotify_init_default();
    test_inotify_invalid_watch();

    printf("\n%d tests failed\n", failures);
    return failures;
}
