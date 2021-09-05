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

add_executable(hashqueue_test
    hashqueue_test.c
    hashqueue.c
)
target_include_directories(hashqueue_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(treemap_test
    treemap_test.c
    treemap.c
)
target_include_directories(treemap_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

ADD_CUSTOM_COMMAND(
  TARGET treemap_test POST_BUILD
  COMMAND ${CMAKE_COMMAND} -E copy_directory ${CMAKE_CURRENT_SOURCE_DIR}/testdata $<TARGET_FILE_DIR:treemap_test>/testdata
)

add_executable(rbuffer_test
    rbuffer_test.c
    treemap.c
    rbuffer.c
)
target_include_directories(rbuffer_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
