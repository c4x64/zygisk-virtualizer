#pragma once

#include <stdint.h>

#define EFD_SEMAPHORE 1
#define EFD_CLOEXEC 02000000
#define EFD_NONBLOCK 04000

typedef uint64_t eventfd_t;
