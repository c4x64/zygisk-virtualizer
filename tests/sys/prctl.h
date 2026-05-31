#pragma once

#include <stdint.h>

#define PR_SET_PDEATHSIG 1
#define PR_GET_PDEATHSIG 2
#define PR_GET_DUMPABLE 3
#define PR_SET_DUMPABLE 4
#define PR_GET_UNALIGN 5
#define PR_SET_UNALIGN 6
#define PR_GET_KEEPCAPS 7
#define PR_SET_KEEPCAPS 8
#define PR_GET_FPEMU 9
#define PR_SET_FPEMU 10
#define PR_GET_FPEXC 11
#define PR_SET_FPEXC 12
#define PR_GET_TIMING 13
#define PR_SET_TIMING 14
#define PR_SET_NAME 15
#define PR_GET_NAME 16
#define PR_GET_ENDIAN 19
#define PR_SET_ENDIAN 20
#define PR_GET_SECCOMP 21
#define PR_SET_SECCOMP 22
#define PR_CAPBSET_READ 23
#define PR_CAPBSET_DROP 24
#define PR_GET_TSC 25
#define PR_SET_TSC 26
#define PR_GET_SECUREBITS 27
#define PR_SET_SECUREBITS 28
#define PR_SET_TIMERSLACK 29
#define PR_GET_TIMERSLACK 30
#define PR_SET_NO_NEW_PRIVS 38
#define PR_GET_NO_NEW_PRIVS 39
#define PR_SET_FP_MODE 43
#define PR_GET_FP_MODE 44

#define SECCOMP_MODE_DISABLED 0
#define SECCOMP_MODE_STRICT 1
#define SECCOMP_MODE_FILTER 2

static inline int prctl(int option, ...) {
    (void)option;
    return 0;
}
