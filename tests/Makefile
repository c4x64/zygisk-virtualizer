# Test build for Zygisk Virtualizer
# These tests run on the host machine (not Android)
# They test core logic independent of Android/ARM
#
# NOTE: On macOS, you may need to adjust the include path for
# Linux/Android headers.  The virtualizer.h header includes
# Android-specific headers (<android/log.h>) and Linux headers
# (<linux/seccomp.h> etc.) that are not available on macOS.
# For a full build, use the NDK cross-compiler instead:
#
#   NDK=/path/to/ndk
#   $(NDK)/toolchains/llvm/prebuilt/darwin-x86_64/bin/aarch64-linux-android21-clang++ \
#       -std=c++17 -o test_trie test_trie.cpp ../../virtualizer_core.cpp

CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -Wno-psabi -g -O0 \
           -I. -I../.. \
           -DVIRT_LOG_LEVEL=0 \
           -D__ANDROID_API__=30

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
CXXFLAGS += -include test_compat.h
endif

all: test_trie test_cache test_rules

test_trie: test_trie.cpp ../../virtualizer_core.cpp ../../virtualizer.h
	$(CXX) $(CXXFLAGS) -o test_trie test_trie.cpp ../../virtualizer_core.cpp

test_cache: test_cache.cpp ../../virtualizer_core.cpp ../../virtualizer.h
	$(CXX) $(CXXFLAGS) -o test_cache test_cache.cpp ../../virtualizer_core.cpp

test_rules: test_rules.cpp ../../virtualizer_core.cpp ../../virtualizer.h
	$(CXX) $(CXXFLAGS) -o test_rules test_rules.cpp ../../virtualizer_core.cpp

clean:
	rm -f test_trie test_cache test_rules
