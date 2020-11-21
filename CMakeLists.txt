cmake_minimum_required(VERSION 3.7)

project(liteflow C)

# find_package(libev REQUIRED)
message(STATUS "Running cmake version ${CMAKE_VERSION}")

include(ExternalProject)

###################################
# Build submodule json-parser
ExternalProject_Add(
    json-parser 
    SOURCE_DIR ${CMAKE_CURRENT_BINARY_DIR}/3rd/json-parser
    PREFIX ${CMAKE_CURRENT_BINARY_DIR}/build/json-parser
    BUILD_IN_SOURCE true
    CONFIGURE_COMMAND sh <SOURCE_DIR>/configure
    BUILD_COMMAND ${MAKE}
    INSTALL_COMMAND ""
)

# Get json-parser source and binary directories from CMake project
ExternalProject_Get_Property(json-parser source_dir)

# Create a libjsonparser target to be used as a dependency by test programs
add_library(libjsonparser IMPORTED STATIC GLOBAL)
add_dependencies(libjsonparser json-parser)

# Set libjsonparser properties
set(libjsonparser_INCLUDES "${source_dir}")
set_target_properties(libjsonparser PROPERTIES
    "IMPORTED_LOCATION" "${source_dir}/libjsonparser.a"
    "IMPORTED_LINK_INTERFACE_LIBRARIES" "${CMAKE_THREAD_LIBS_INIT}"
)

###################################
# Build submodule udns
ExternalProject_Add(
    udns
    SOURCE_DIR ${CMAKE_CURRENT_BINARY_DIR}/3rd/udns
    PREFIX ${CMAKE_CURRENT_BINARY_DIR}/build/udns
    BUILD_IN_SOURCE true
    CONFIGURE_COMMAND sh <SOURCE_DIR>/configure
    BUILD_COMMAND ${MAKE}
    INSTALL_COMMAND ""
)

# Get udns source and binary directories from CMake project
ExternalProject_Get_Property(udns source_dir)

# Create a libudns target to be used as a dependency by test programs
add_library(libudns IMPORTED STATIC GLOBAL)
add_dependencies(libudns udns)

# Set libudns properties
set(libudns_INCLUDES "${source_dir}")
set_target_properties(libudns PROPERTIES
    "IMPORTED_LOCATION" "${source_dir}/libudns.a"
    "IMPORTED_LINK_INTERFACE_LIBRARIES" "${CMAKE_THREAD_LIBS_INIT}"
)

###################################
# Build submodule ev
ExternalProject_Add(ev
    BUILD_IN_SOURCE true
    SOURCE_DIR ${CMAKE_CURRENT_BINARY_DIR}/3rd/libev
    PREFIX ${CMAKE_CURRENT_BINARY_DIR}/build/libev
    CONFIGURE_COMMAND sh <SOURCE_DIR>/autogen.sh COMMAND sh <SOURCE_DIR>/configure
    BUILD_COMMAND ${MAKE}
    INSTALL_COMMAND ""
)

# Get udns source and binary directories from CMake project
ExternalProject_Get_Property(ev source_dir)

# Create a libev target to be used as a dependency by test programs
add_library(libev IMPORTED STATIC GLOBAL)
add_dependencies(libev ev)

# Set libev properties
set(libev_INCLUDES "${source_dir}")
set_target_properties(libev PROPERTIES
    "IMPORTED_LOCATION" "${source_dir}/.libs/libev.a"
    "IMPORTED_LINK_INTERFACE_LIBRARIES" "${CMAKE_THREAD_LIBS_INIT}"
)

###################################
file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/gen)
find_program(GIT_EXECUTABLE git DOC "Git version control")
# The 'real' git information file
SET(GITREV_BARE_FILE git-rev.c)
# The temporary git information file
SET(GITREV_BARE_TMP git-rev-tmp.c)
SET(GITREV_FILE ${CMAKE_BINARY_DIR}/gen/${GITREV_BARE_FILE})
SET(GITREV_TMP ${CMAKE_BINARY_DIR}/gen/${GITREV_BARE_TMP})

ADD_CUSTOM_COMMAND(
  OUTPUT ${GITREV_TMP} ${GITREV_FILE}
  COMMAND ${CMAKE_COMMAND} -E echo_append "#define GIT_BRANCH_STR " > ${GITREV_TMP}
  COMMAND ${GIT_EXECUTABLE} describe --tags --dirty=-unclean >> ${GITREV_TMP}  
  COMMAND ${CMAKE_COMMAND} -E echo "#define STR(S) #S" >> ${GITREV_TMP}
  COMMAND ${CMAKE_COMMAND} -E echo "#define XSTR(S) STR(S)" >> ${GITREV_TMP}
  COMMAND ${CMAKE_COMMAND} -E echo "const char* liteflow_version = \"liteflow.git/\" XSTR(GIT_BRANCH_STR); " >> ${GITREV_TMP}
  COMMAND ${CMAKE_COMMAND} -E copy_if_different ${GITREV_TMP} ${GITREV_FILE}
  COMMAND ${CMAKE_COMMAND} -E remove ${GITREV_TMP}
  WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
  VERBATIM
)

message(STATUS "Includes: ${libjsonparser_INCLUDES} ${libudns_INCLUDES} ${libev_INCLUDES}")
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
            rbuffer.c
            config.c
            stat.c
            ${GITREV_FILE}
)
target_include_directories(liteflow PRIVATE ${libjsonparser_INCLUDES} ${libudns_INCLUDES} ${libev_INCLUDES})
target_link_libraries(liteflow libjsonparser m libudns libev)

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

add_executable(test_litedt
    test/test_litedt.c
    litedt.c
    retrans.c
    ctrl.c
    fec.c
    config.c
    hashqueue.c
    rbuffer.c
)
target_include_directories(test_litedt PRIVATE ${libjsonparser_INCLUDES} ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(test_litedt libjsonparser m)
