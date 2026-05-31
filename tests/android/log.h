#pragma once

#include <stdarg.h>
#include <stdio.h>

#define ANDROID_LOG_UNKNOWN 0
#define ANDROID_LOG_DEFAULT 1
#define ANDROID_LOG_VERBOSE 2
#define ANDROID_LOG_DEBUG   3
#define ANDROID_LOG_INFO    4
#define ANDROID_LOG_WARN    5
#define ANDROID_LOG_ERROR   6
#define ANDROID_LOG_FATAL   7
#define ANDROID_LOG_SILENT  8

static inline int __android_log_print(int prio, const char *tag, const char *fmt, ...) {
    (void)prio; (void)tag;
    va_list args;
    va_start(args, fmt);
    int ret = vfprintf(stderr, fmt, args);
    va_end(args);
    fprintf(stderr, "\n");
    return ret;
}

static inline int __android_log_vprint(int prio, const char *tag, const char *fmt, va_list ap) {
    (void)prio; (void)tag;
    return vfprintf(stderr, fmt, ap);
}

static inline void __android_log_assert(const char *cond, const char *tag, const char *fmt, ...) {
    if (cond) fprintf(stderr, "Assert: %s", cond);
}
