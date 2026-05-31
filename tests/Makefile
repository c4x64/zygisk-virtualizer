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
CXXFLAGS = -std=c++17 -Wall -Wextra -Wno-psabi -Wno-unused-parameter \
           -Wno-deprecated-declarations -g -O0 \
           -I. -I../.. -Iandroid -I. \
           -DVIRT_LOG_LEVEL=0 \
           -D__ANDROID_API__=30 \
           -include test_compat.h

SRCDIR := unit
CORE := ../virtualizer_core.cpp

all: $(SRCDIR)/test_trie $(SRCDIR)/test_cache $(SRCDIR)/test_rules \
     $(SRCDIR)/test_config $(SRCDIR)/test_proc_hider $(SRCDIR)/test_stats \
     $(SRCDIR)/test_mem $(SRCDIR)/test_signal $(SRCDIR)/test_mask

STUBS := test_stubs.cpp

$(SRCDIR)/test_trie: $(SRCDIR)/test_trie.cpp $(CORE) $(STUBS) ../virtualizer.h
	$(CXX) $(CXXFLAGS) -o $@ $< $(CORE) $(STUBS)

$(SRCDIR)/test_cache: $(SRCDIR)/test_cache.cpp $(CORE) $(STUBS) ../virtualizer.h
	$(CXX) $(CXXFLAGS) -o $@ $< $(CORE) $(STUBS)

$(SRCDIR)/test_rules: $(SRCDIR)/test_rules.cpp $(CORE) $(STUBS) ../virtualizer.h
	$(CXX) $(CXXFLAGS) -o $@ $< $(CORE) $(STUBS)

$(SRCDIR)/test_config: $(SRCDIR)/test_config.cpp $(CORE) $(STUBS) ../virtualizer.h
	$(CXX) $(CXXFLAGS) -o $@ $< $(CORE) $(STUBS)

$(SRCDIR)/test_proc_hider: $(SRCDIR)/test_proc_hider.cpp $(CORE) $(STUBS) ../virtualizer.h
	$(CXX) $(CXXFLAGS) -o $@ $< $(CORE) $(STUBS)

$(SRCDIR)/test_stats: $(SRCDIR)/test_stats.cpp $(CORE) $(STUBS) ../virtualizer.h
	$(CXX) $(CXXFLAGS) -o $@ $< $(CORE) $(STUBS)

$(SRCDIR)/test_mem: $(SRCDIR)/test_mem.cpp $(CORE) $(STUBS) ../virtualizer.h
	$(CXX) $(CXXFLAGS) -o $@ $< $(CORE) $(STUBS)

$(SRCDIR)/test_signal: $(SRCDIR)/test_signal.cpp $(CORE) $(STUBS) ../virtualizer.h
	$(CXX) $(CXXFLAGS) -o $@ $< $(CORE) $(STUBS)

$(SRCDIR)/test_mask: $(SRCDIR)/test_mask.cpp $(CORE) $(STUBS) ../virtualizer.h
	$(CXX) $(CXXFLAGS) -o $@ $< $(CORE) $(STUBS)

clean:
	rm -f $(SRCDIR)/test_trie $(SRCDIR)/test_cache $(SRCDIR)/test_rules \
	      $(SRCDIR)/test_config $(SRCDIR)/test_proc_hider $(SRCDIR)/test_stats \
	      $(SRCDIR)/test_mem $(SRCDIR)/test_signal $(SRCDIR)/test_mask
