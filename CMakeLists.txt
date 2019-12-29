cmake_minimum_required(VERSION 3.7)

project(liteflow C)

# find_package(libev REQUIRED)
message(STATUS "Running cmake version ${CMAKE_VERSION}")

include(ExternalProject)

###################################
# Download and install GoogleTest
ExternalProject_Add(
    udns
    URL http://www.corpit.ru/mjt/udns/udns-0.4.tar.gz
    PREFIX ${CMAKE_CURRENT_BINARY_DIR}/udns
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

ExternalProject_Add(ev
    BUILD_IN_SOURCE true
    URL http://dist.schmorp.de/libev/libev-4.31.tar.gz
    PREFIX ${CMAKE_CURRENT_BINARY_DIR}/ev
    CONFIGURE_COMMAND sh <SOURCE_DIR>/configure
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

find_program(GIT_EXECUTABLE git DOC "Git version control")
# The 'real' git information file
SET(GITREV_BARE_FILE git-rev.c)
# The temporary git information file
SET(GITREV_BARE_TMP git-rev-tmp.c)
SET(GITREV_FILE ${CMAKE_BINARY_DIR}/${GITREV_BARE_FILE})
SET(GITREV_TMP ${CMAKE_BINARY_DIR}/${GITREV_BARE_TMP})

ADD_CUSTOM_COMMAND(
  OUTPUT ${GITREV_TMP} ${GITREV_FILE}
  COMMAND ${CMAKE_COMMAND} -E echo_append "#define GIT_BRANCH_RAW " > ${GITREV_TMP}
  COMMAND ${GIT_EXECUTABLE} describe --tags --dirty=-unclean >> ${GITREV_TMP}  
  COMMAND ${CMAKE_COMMAND} -E echo_append "#define STR(S) #S" >> ${GITREV_TMP}
  COMMAND ${CMAKE_COMMAND} -E echo >> ${GITREV_TMP}
  COMMAND ${CMAKE_COMMAND} -E echo_append "const char* liteflow_version = \"liteflow.git/\" STR(GIT_BRANCH_STR); " >> ${GITREV_TMP}
  COMMAND ${CMAKE_COMMAND} -E copy_if_different ${GITREV_TMP} ${GITREV_FILE}
  COMMAND ${CMAKE_COMMAND} -E remove ${GITREV_TMP}
  WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
  VERBATIM
)

message(STATUS "Includes: ${libudns_INCLUDES} ${libev_INCLUDES}")
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
            json.c
            ${GITREV_FILE}
)
target_include_directories(liteflow PRIVATE ${libudns_INCLUDES} ${libev_INCLUDES})
target_link_libraries(liteflow m libudns libev)

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
    json.c
    hashqueue.c
    rbuffer.c
)
target_include_directories(test_litedt PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(test_litedt m)
