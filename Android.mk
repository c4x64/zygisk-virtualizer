LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE := virtualizer
LOCAL_SRC_FILES := \
    zygisk_entry.cpp \
    seccomp_engine.cpp \
    virtualizer_core.cpp

LOCAL_C_INCLUDES := $(LOCAL_PATH)

LOCAL_CFLAGS := \
    -std=c++17 \
    -Wall -Wextra -Werror \
    -fvisibility=hidden \
    -fPIC \
    -O2 \
    -DLOG_TAG=\"Virtualizer\"

LOCAL_LDLIBS := -llog

LOCAL_MODULE_CLASS := SHARED_LIBRARIES
LOCAL_MODULE_SUFFIX := .so

include $(BUILD_SHARED_LIBRARY)
