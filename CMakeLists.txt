cmake_minimum_required(VERSION 3.8)
project(AhoCorasickSearch LANGUAGES CXX)

option(BUILD_EXAMPLES "Build example binaries" OFF)
option(BUILD_TESTS "Build tests" OFF)
option(ENABLE_ASAN "Build with AddressSanitizer" OFF)
option(ENABLE_COVERAGE "Build tests with code coverage instrumentation" OFF)

set(ASAN_FLAGS -fsanitize=address -fno-omit-frame-pointer -g)
set(COVERAGE_COMPILE_FLAGS --coverage -O0 -g)
set(COVERAGE_LINK_FLAGS --coverage)

macro(enable_asan_for target)
    if(ENABLE_ASAN)
        if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
            target_compile_options(${target} PRIVATE ${ASAN_FLAGS})
            target_link_libraries(${target} ${ASAN_FLAGS})
        endif()
    endif()
endmacro()

macro(enable_coverage_for target)
    if(ENABLE_COVERAGE)
        if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
            target_compile_options(${target} PRIVATE ${COVERAGE_COMPILE_FLAGS})
            target_link_libraries(${target} ${COVERAGE_LINK_FLAGS})
        else()
            message(FATAL_ERROR "ENABLE_COVERAGE requires GCC or Clang")
        endif()
    endif()
endmacro()

if(ENABLE_COVERAGE AND NOT BUILD_TESTS)
    message(WARNING "ENABLE_COVERAGE is intended for unit tests; enable BUILD_TESTS to add the coverage target")
endif()

add_library(aho_corasick_search
    src/aho_corasick.cc
)
enable_asan_for(aho_corasick_search)
enable_coverage_for(aho_corasick_search)

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
    enable_coverage_for(example)
endif()

if(BUILD_TESTS)
    enable_testing()
    add_executable(test_basic tests/test_basic.cpp)
    target_link_libraries(test_basic aho_corasick_search)
    enable_asan_for(test_basic)
    enable_coverage_for(test_basic)
    add_test(NAME basic COMMAND test_basic)

    if(ENABLE_COVERAGE)
        find_program(GCOV_EXECUTABLE gcov)
        if(NOT GCOV_EXECUTABLE)
            message(FATAL_ERROR "ENABLE_COVERAGE requires gcov")
        endif()

        add_custom_target(coverage
            COMMAND ${CMAKE_COMMAND}
                    -DCOVERAGE_BINARY_DIR=${CMAKE_CURRENT_BINARY_DIR}
                    -DCOVERAGE_OUTPUT_DIR=${CMAKE_CURRENT_BINARY_DIR}/coverage
                    -DCOVERAGE_CLEAN=ON
                    -P ${CMAKE_CURRENT_SOURCE_DIR}/cmake/RunGcov.cmake
            COMMAND ${CMAKE_CTEST_COMMAND} --output-on-failure
            COMMAND ${CMAKE_COMMAND}
                    -DGCOV_EXECUTABLE=${GCOV_EXECUTABLE}
                    -DCOVERAGE_BINARY_DIR=${CMAKE_CURRENT_BINARY_DIR}
                    -DCOVERAGE_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
                    -DCOVERAGE_OUTPUT_DIR=${CMAKE_CURRENT_BINARY_DIR}/coverage
                    -P ${CMAKE_CURRENT_SOURCE_DIR}/cmake/RunGcov.cmake
            WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
            DEPENDS test_basic
            COMMENT "Running unit tests and generating gcov coverage reports"
        )
    endif()
endif()
