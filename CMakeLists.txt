cmake_minimum_required(VERSION 3.10)
project(liteflow C)
message(STATUS "Running cmake version ${CMAKE_VERSION}")

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=gnu99")

set(CARES_SHARED OFF CACHE BOOL "Build as a shared library")
set(CARES_STATIC ON CACHE BOOL "Build as a static library")
set(CARES_STATIC_PIC ON CACHE BOOL "Build the static library as PIC (position independent)")
set(CARES_BUILD_TOOLS OFF CACHE BOOL "Build tools")

set(LITEFLOW_TOPLEVEL_DIR "${CMAKE_CURRENT_SOURCE_DIR}")

# Adding third party libraries
add_subdirectory(3rd/libev)
add_subdirectory(3rd/c-ares)
add_subdirectory(common)
add_subdirectory(src)

file(GLOB SCRIPT_FILES "scripts/*.sh")
if(SCRIPT_FILES STREQUAL "")
    message(FATAL_ERROR "No script file found in scripts/*.sh. Please check path.")
endif()
install(PROGRAMS ${SCRIPT_FILES}
        DESTINATION scripts)

file(GLOB SCRIPT_FILES "examples/liteflow.conf.*")
if(SCRIPT_FILES STREQUAL "")
    message(FATAL_ERROR "No conf file found in examples/liteflow.conf.*. Please check path.")
endif()
install(FILES ${SCRIPT_FILES}
        DESTINATION ${CMAKE_INSTALL_SYSCONFDIR})
