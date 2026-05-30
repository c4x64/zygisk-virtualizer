cmake_minimum_required(VERSION 3.22)
project(virtualizer VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} \
    -Wall -Wextra -Werror \
    -fvisibility=hidden \
    -fPIC \
    -O2")

set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} \
    -Wl,--hash-style=sysv \
    -Wl,--build-id=sha1 \
    -Wl,-z,relro \
    -Wl,-z,now")

add_library(virtualizer SHARED
    zygisk_entry.cpp
)

target_include_directories(virtualizer PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/../zygisk/include
)

target_link_libraries(virtualizer
    log
    z
)

target_compile_options(virtualizer PRIVATE
    $<$<CONFIG:Release>:-O2 -DNDEBUG>
    $<$<CONFIG:Debug>:-g -O0 -UNDEBUG>
)

set_target_properties(virtualizer PROPERTIES
    POSITION_INDEPENDENT_CODE ON
    CXX_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN ON
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/libs/arm64-v8a"
)

install(TARGETS virtualizer
    LIBRARY DESTINATION libs/arm64-v8a
)
