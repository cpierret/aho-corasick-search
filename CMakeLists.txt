cmake_minimum_required(VERSION 3.8)
project(AhoCorasickSearch LANGUAGES CXX)

option(BUILD_EXAMPLES "Build example binaries" OFF)
option(BUILD_TESTS "Build tests" OFF)

add_library(aho_corasick_search
    src/aho_corasick.cc
)

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
endif()

if(BUILD_TESTS)
    enable_testing()
    add_executable(test_basic tests/test_basic.cpp)
    target_link_libraries(test_basic aho_corasick_search)
    add_test(NAME basic COMMAND test_basic)
endif()
