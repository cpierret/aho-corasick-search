cmake_minimum_required(VERSION 3.8)
project(AhoCorasickSearch LANGUAGES CXX)

option(BUILD_EXAMPLES "Build example binaries" OFF)
option(BUILD_TESTS "Build tests" OFF)
option(ENABLE_ASAN "Build with AddressSanitizer" OFF)

set(ASAN_FLAGS -fsanitize=address -fno-omit-frame-pointer -g)

macro(enable_asan_for target)
    if(ENABLE_ASAN)
        if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
            target_compile_options(${target} PRIVATE ${ASAN_FLAGS})
            target_link_libraries(${target} ${ASAN_FLAGS})
        endif()
    endif()
endmacro()

add_library(aho_corasick_search
    src/aho_corasick.cc
)
enable_asan_for(aho_corasick_search)

# Require C++17 for the library and propagate to dependents
target_compile_features(aho_corasick_search PUBLIC cxx_std_17)

# Public include directory
target_include_directories(aho_corasick_search
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src>
)

# Require C++17
set_target_properties(aho_corasick_search PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED YES
    CXX_EXTENSIONS NO
)

if(BUILD_EXAMPLES)
    add_executable(example examples/example.cpp)
    target_link_libraries(example aho_corasick_search)
    enable_asan_for(example)
endif()

if(BUILD_TESTS)
    enable_testing()
    add_executable(test_basic tests/test_basic.cpp)
    target_link_libraries(test_basic aho_corasick_search)
    enable_asan_for(test_basic)
    add_test(NAME basic COMMAND test_basic)
endif()
