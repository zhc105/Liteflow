cmake_minimum_required(VERSION 3.10)
project(liteflow C)
message(STATUS "Running cmake version ${CMAKE_VERSION}")
include(ExternalProject)

set(CARES_SHARED OFF CACHE BOOL "Build as a shared library")
set(CARES_STATIC ON CACHE BOOL "Build as a static library")
set(CARES_STATIC_PIC ON CACHE BOOL "Build the static library as PIC (position independent)")
set(CARES_BUILD_TOOLS OFF CACHE BOOL "Build tools")

set(LITEFLOW_TOPLEVEL_DIR "${CMAKE_CURRENT_SOURCE_DIR}")
set(libev_INCLUDES "${LITEFLOW_TOPLEVEL_DIR}/3rd/libev")
set(libcares_INCLUDES "${LITEFLOW_TOPLEVEL_DIR}/3rd/c-ares/include")
set(jsonparser_INCLUDES "${LITEFLOW_TOPLEVEL_DIR}/3rd/json-parser")
set(libcommon_INCLUDES "${LITEFLOW_TOPLEVEL_DIR}/common")

# Adding third party libraries
add_subdirectory(3rd/libev)
add_subdirectory(3rd/c-ares)
add_subdirectory(common)
set(jsonparser_SOURCE 3rd/json-parser/json.c)

# Generating git-rev.c
file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/gen)
find_program(GIT_EXECUTABLE git DOC "Git version control")
# The 'real' git information file
SET(GITREV_BARE_FILE git-rev.c)
# The temporary git information file
SET(GITREV_BARE_TMP git-rev-tmp.c)
SET(GITREV_FILE ${CMAKE_CURRENT_BINARY_DIR}/gen/${GITREV_BARE_FILE})
SET(GITREV_TMP ${CMAKE_CURRENT_BINARY_DIR}/gen/${GITREV_BARE_TMP})

ADD_CUSTOM_COMMAND(
  OUTPUT ${GITREV_TMP} ${GITREV_FILE}
  COMMAND ${CMAKE_COMMAND} -E echo_append "#define GIT_BRANCH_STR " > ${GITREV_TMP}
  COMMAND ${GIT_EXECUTABLE} describe --tags --dirty=-unclean >> ${GITREV_TMP}
  COMMAND ${CMAKE_COMMAND} -E echo "#define STR(S) #S" >> ${GITREV_TMP}
  COMMAND ${CMAKE_COMMAND} -E echo "#define XSTR(S) STR(S)" >> ${GITREV_TMP}
  COMMAND ${CMAKE_COMMAND} -E echo "const char* liteflow_version = \"liteflow.git/\" XSTR(GIT_BRANCH_STR); " >> ${GITREV_TMP}
  COMMAND ${CMAKE_COMMAND} -E copy_if_different ${GITREV_TMP} ${GITREV_FILE}
  COMMAND ${CMAKE_COMMAND} -E remove ${GITREV_TMP}
  WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
  VERBATIM
)

message(STATUS "Includes: ${jsonparser_INCLUDES} ${libcares_INCLUDES} ${libev_INCLUDES} ${libcommon_INCLUDES}")
add_executable(liteflow
            main.c
            liteflow.c
            tcp.c
            udp.c
            litedt.c
            retrans.c
            ctrl.c
            fec.c
            config.c
            ${jsonparser_SOURCE}
            ${GITREV_FILE}
)
add_dependencies(liteflow ev)
add_dependencies(liteflow c-ares)
add_dependencies(liteflow common)
target_include_directories(liteflow PRIVATE ${jsonparser_INCLUDES} ${libcares_INCLUDES} ${libev_INCLUDES} ${libcommon_INCLUDES})
target_link_libraries(liteflow c-ares ev common m)

add_executable(litedt_test
    litedt_test.c
    litedt.c
    retrans.c
    ctrl.c
    fec.c
    config.c
    ${jsonparser_SOURCE}
)
add_dependencies(litedt_test common)
target_include_directories(litedt_test PRIVATE ${jsonparser_INCLUDES} ${libcommon_INCLUDES} ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(litedt_test common m)
