cmake_minimum_required(VERSION 3.12)
project(libcommon C)

set(COMMON_SRC 
  hashqueue.c
  rbuffer.c
  sha256.c
  treemap.c
  windowed_filter.c
)

add_library(common STATIC ${COMMON_SRC})
target_include_directories(common PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries (common m)

add_executable(test_hashqueue
    test_hashqueue.c
    hashqueue.c
)
target_include_directories(test_hashqueue PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(test_treemap
    test_treemap.c
    treemap.c
)
target_include_directories(test_treemap PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

ADD_CUSTOM_COMMAND(
  TARGET test_treemap POST_BUILD
  COMMAND ${CMAKE_COMMAND} -E copy_directory ${CMAKE_CURRENT_SOURCE_DIR}/testdata $<TARGET_FILE_DIR:test_treemap>/testdata
)

add_executable(test_rbuffer
    test_rbuffer.c
    treemap.c
    rbuffer.c
)
target_include_directories(test_rbuffer PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})