if(NOT DEFINED COVERAGE_BINARY_DIR)
    message(FATAL_ERROR "COVERAGE_BINARY_DIR is required")
endif()

if(NOT DEFINED COVERAGE_OUTPUT_DIR)
    set(COVERAGE_OUTPUT_DIR "${COVERAGE_BINARY_DIR}/coverage")
endif()

if(NOT DEFINED COVERAGE_SOURCE_DIR)
    set(COVERAGE_SOURCE_DIR "${COVERAGE_BINARY_DIR}")
endif()

if(COVERAGE_CLEAN)
    file(GLOB_RECURSE STALE_COVERAGE_DATA_FILES "${COVERAGE_BINARY_DIR}/*.gcda")
    if(STALE_COVERAGE_DATA_FILES)
        file(REMOVE ${STALE_COVERAGE_DATA_FILES})
    endif()
    file(REMOVE_RECURSE "${COVERAGE_OUTPUT_DIR}")
    return()
endif()

if(NOT DEFINED GCOV_EXECUTABLE)
    message(FATAL_ERROR "GCOV_EXECUTABLE is required")
endif()

file(MAKE_DIRECTORY "${COVERAGE_OUTPUT_DIR}")
file(GLOB_RECURSE COVERAGE_DATA_FILES "${COVERAGE_BINARY_DIR}/*.gcda")

if(NOT COVERAGE_DATA_FILES)
    message(FATAL_ERROR "No coverage data files were found. Build and run the tests first.")
endif()

set(COVERAGE_WORK_DIR "${COVERAGE_OUTPUT_DIR}/.gcov-work")
file(REMOVE_RECURSE "${COVERAGE_WORK_DIR}")
file(MAKE_DIRECTORY "${COVERAGE_WORK_DIR}")

foreach(COVERAGE_SOURCE_ENTRY src tests examples)
    if(IS_DIRECTORY "${COVERAGE_SOURCE_DIR}/${COVERAGE_SOURCE_ENTRY}")
        execute_process(
            COMMAND "${CMAKE_COMMAND}" -E copy_directory
                    "${COVERAGE_SOURCE_DIR}/${COVERAGE_SOURCE_ENTRY}"
                    "${COVERAGE_WORK_DIR}/${COVERAGE_SOURCE_ENTRY}"
            RESULT_VARIABLE COPY_RESULT
        )

        if(NOT COPY_RESULT EQUAL 0)
            message(FATAL_ERROR "Failed to stage ${COVERAGE_SOURCE_ENTRY} sources for gcov")
        endif()
    endif()
endforeach()

foreach(COVERAGE_DATA_FILE IN LISTS COVERAGE_DATA_FILES)
    execute_process(
        COMMAND "${GCOV_EXECUTABLE}" -b -c -l -p -r
                -s "${COVERAGE_SOURCE_DIR}"
                "${COVERAGE_DATA_FILE}"
        WORKING_DIRECTORY "${COVERAGE_WORK_DIR}"
        RESULT_VARIABLE GCOV_RESULT
    )

    if(NOT GCOV_RESULT EQUAL 0)
        message(FATAL_ERROR "gcov failed for ${COVERAGE_DATA_FILE}")
    endif()
endforeach()

file(GLOB GCOV_REPORT_FILES "${COVERAGE_WORK_DIR}/*.gcov")
if(NOT GCOV_REPORT_FILES)
    message(FATAL_ERROR "gcov completed but did not produce any report files")
endif()

foreach(GCOV_REPORT_FILE IN LISTS GCOV_REPORT_FILES)
    get_filename_component(GCOV_REPORT_NAME "${GCOV_REPORT_FILE}" NAME)
    file(REMOVE "${COVERAGE_OUTPUT_DIR}/${GCOV_REPORT_NAME}")
    file(RENAME "${GCOV_REPORT_FILE}" "${COVERAGE_OUTPUT_DIR}/${GCOV_REPORT_NAME}")
endforeach()
file(REMOVE_RECURSE "${COVERAGE_WORK_DIR}")

message(STATUS "Coverage reports written to ${COVERAGE_OUTPUT_DIR}")
