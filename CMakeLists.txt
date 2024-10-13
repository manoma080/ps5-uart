cmake_minimum_required(VERSION 3.28)

project(ps5_uart_tools C CXX ASM)

option(ENABLE_DEBUG_STDIO
    "Creates additional cdc interface (0) for stdout/stdin; enables some debug spew")

# The code is built as ExternalProjects.
# I really wish this weren't the case, but I couldn't get cmake to
# play nicely with the different toolchains being used.

if(NOT ${CMAKE_BUILD_TYPE} STREQUAL MinSizeRel)
    message(FATAL_ERROR "CMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}. Use MinSizeRel instead.")
endif()

include(ExternalProject)
ExternalProject_Add(uart
    SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/uart
    CMAKE_ARGS
        -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
        -DCMAKE_INSTALL_PREFIX=${CMAKE_SOURCE_DIR}
        -DENABLE_DEBUG_STDIO=${ENABLE_DEBUG_STDIO}
    BUILD_ALWAYS TRUE
    )
ExternalProject_Add(bin_blobs
    SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/bin_blobs
    CMAKE_ARGS
        -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
        -DCMAKE_INSTALL_PREFIX=${CMAKE_SOURCE_DIR}
    BUILD_ALWAYS TRUE
    )

add_custom_target(ps5_uart_tools)
add_dependencies(ps5_uart_tools uart bin_blobs)
