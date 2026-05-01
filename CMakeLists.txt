cmake_minimum_required(VERSION 3.8)
project(AhoCorasickSearch LANGUAGES CXX)

option(BUILD_EXAMPLES "Build example binaries" OFF)
option(BUILD_TESTS "Build tests" OFF)
option(BUILD_PYTHON_EXTENSION "Build the native CPython extension" OFF)
option(ENABLE_ASAN "Build with AddressSanitizer" OFF)
option(ENABLE_COVERAGE "Build tests with code coverage instrumentation" OFF)
option(ENABLE_SEARCH_STATS "Enable native search instrumentation counters" OFF)
option(ENABLE_FAILURELESS_FULL_ROWS "Resolve full-row failure transitions at compile time" ON)
set(FULL_ROW_MIN_TRANSITIONS 4 CACHE STRING "Minimum transition count that stores a non-root row in full format")
set(SPARSE_FAILURELESS_MAX_TRANSITIONS 0 CACHE STRING "Maximum sparse-row transition count after failureless expansion; 0 disables expansion")
set(FAILURELESS_CACHE_MAX_STATES 0 CACHE STRING "Maximum states with precomputed failureless transitions; 0 disables the cache")

if("${FULL_ROW_MIN_TRANSITIONS}" MATCHES "^[0-9][0-9]*$")
else()
    message(FATAL_ERROR "FULL_ROW_MIN_TRANSITIONS must be an integer from 1 to 64")
endif()
if(FULL_ROW_MIN_TRANSITIONS LESS 1 OR FULL_ROW_MIN_TRANSITIONS GREATER 64)
    message(FATAL_ERROR "FULL_ROW_MIN_TRANSITIONS must be an integer from 1 to 64")
endif()
if("${SPARSE_FAILURELESS_MAX_TRANSITIONS}" MATCHES "^[0-9][0-9]*$")
else()
    message(FATAL_ERROR "SPARSE_FAILURELESS_MAX_TRANSITIONS must be an integer from 0 to 63")
endif()
if(SPARSE_FAILURELESS_MAX_TRANSITIONS GREATER 63)
    message(FATAL_ERROR "SPARSE_FAILURELESS_MAX_TRANSITIONS must be an integer from 0 to 63")
endif()
if("${FAILURELESS_CACHE_MAX_STATES}" MATCHES "^[0-9][0-9]*$")
else()
    message(FATAL_ERROR "FAILURELESS_CACHE_MAX_STATES must be a non-negative integer")
endif()

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

if(ENABLE_SEARCH_STATS)
    target_compile_definitions(aho_corasick_search PUBLIC AHO_CORASICK_SEARCH_STATS)
endif()
if(ENABLE_FAILURELESS_FULL_ROWS)
    target_compile_definitions(aho_corasick_search PUBLIC AHO_CORASICK_FAILURELESS_FULL_ROWS=1)
else()
    target_compile_definitions(aho_corasick_search PUBLIC AHO_CORASICK_FAILURELESS_FULL_ROWS=0)
endif()
target_compile_definitions(aho_corasick_search PUBLIC
    AHO_CORASICK_FULL_ROW_MIN_TRANSITIONS=${FULL_ROW_MIN_TRANSITIONS}
    AHO_CORASICK_SPARSE_FAILURELESS_MAX_TRANSITIONS=${SPARSE_FAILURELESS_MAX_TRANSITIONS}
    AHO_CORASICK_FAILURELESS_CACHE_MAX_STATES=${FAILURELESS_CACHE_MAX_STATES}
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

if(BUILD_PYTHON_EXTENSION)
    if(CMAKE_VERSION VERSION_LESS 3.15)
        message(FATAL_ERROR "BUILD_PYTHON_EXTENSION requires CMake 3.15 or newer")
    endif()

    find_package(Python 3.10 COMPONENTS Interpreter Development.Module REQUIRED)

    execute_process(
        COMMAND ${Python_EXECUTABLE} -m nanobind --cmake_dir
        OUTPUT_VARIABLE NANOBIND_CMAKE_DIR
        OUTPUT_STRIP_TRAILING_WHITESPACE
        ERROR_QUIET
        RESULT_VARIABLE NANOBIND_CMAKE_DIR_RESULT
    )
    if(NOT NANOBIND_CMAKE_DIR_RESULT EQUAL 0)
        message(FATAL_ERROR "BUILD_PYTHON_EXTENSION requires nanobind. Install it with: ${Python_EXECUTABLE} -m pip install nanobind")
    endif()

    list(APPEND CMAKE_PREFIX_PATH "${NANOBIND_CMAKE_DIR}")
    find_package(nanobind CONFIG REQUIRED)

    nanobind_add_module(aho_corasick_search_ext
        NOMINSIZE
        python/aho_corasick_search_ext.cpp
    )
    target_link_libraries(aho_corasick_search_ext PRIVATE aho_corasick_search)
    target_compile_features(aho_corasick_search_ext PRIVATE cxx_std_17)
    set_target_properties(aho_corasick_search_ext PROPERTIES
        CXX_STANDARD 17
        CXX_STANDARD_REQUIRED YES
        CXX_EXTENSIONS NO
    )
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

    if(BUILD_PYTHON_EXTENSION)
        add_test(
            NAME python_extension
            COMMAND ${Python_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_python_extension.py
        )
        set_tests_properties(python_extension PROPERTIES
            ENVIRONMENT "PYTHONPATH=$<TARGET_FILE_DIR:aho_corasick_search_ext>"
        )
    endif()
endif()
