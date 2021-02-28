cmake_minimum_required(VERSION 3.12)
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

# Adding third party libraries
add_subdirectory(3rd/libev)
add_subdirectory(3rd/c-ares)
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

message(STATUS "Includes: ${jsonparser_INCLUDES} ${libcares_INCLUDES} ${libev_INCLUDES}")
add_executable(liteflow
            main.c
            liteflow.c
            tcp.c
            udp.c
            litedt.c
            retrans.c
            ctrl.c
            fec.c
            hashqueue.c
	    treemap.c
            rbuffer.c
            config.c
            stat.c
            ${jsonparser_SOURCE}
            ${GITREV_FILE}
)
add_dependencies(liteflow ev)
add_dependencies(liteflow c-ares)
target_include_directories(liteflow PRIVATE ${jsonparser_INCLUDES} ${libcares_INCLUDES} ${libev_INCLUDES})
target_link_libraries(liteflow c-ares ev m)

add_executable(test_rbuffer
    test/test_rbuffer.c
    rbuffer.c
)
target_include_directories(test_rbuffer PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(test_hashqueue
    test/test_hashqueue.c
    hashqueue.c
)
target_include_directories(test_hashqueue PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(test_treemap
    test/test_treemap.c
    treemap.c
)
target_include_directories(test_treemap PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

ADD_CUSTOM_COMMAND(
  TARGET test_treemap POST_BUILD
  COMMAND ${CMAKE_COMMAND} -E copy_directory ${CMAKE_SOURCE_DIR}/test/testdata $<TARGET_FILE_DIR:test_treemap>/testdata
)

add_executable(test_litedt
    test/test_litedt.c
    litedt.c
    retrans.c
    ctrl.c
    fec.c
    config.c
    hashqueue.c
    treemap.c
    rbuffer.c
    ${jsonparser_SOURCE}
)
target_include_directories(test_litedt PRIVATE ${jsonparser_INCLUDES} ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(test_litedt m)
