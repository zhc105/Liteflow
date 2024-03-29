cmake_minimum_required(VERSION 3.10)
project(libcommon C)

set(COMMON_SRC
  hashqueue.c
  rbuffer.c
  sha256.c
  hash_32.c
  timerlist.c
  treemap.c
  windowed_filter.c
)

add_library(common STATIC ${COMMON_SRC})
target_include_directories(common PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries (common m)

add_custom_target(
  testdata
  COMMAND ${CMAKE_COMMAND} -E copy_directory ${CMAKE_CURRENT_SOURCE_DIR}/testdata ${CMAKE_CURRENT_BINARY_DIR}/testdata
)

add_executable(hashqueue_test
  hashqueue_test.c
  hashqueue.c
  hash_32.c
)
target_include_directories(hashqueue_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(treemap_test
  treemap_test.c
  treemap.c
)
target_include_directories(treemap_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
add_dependencies(treemap_test testdata)

add_executable(timerlist_test
  timerlist_test.c
  timerlist.c
  hash_32.c
)
target_include_directories(timerlist_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
add_dependencies(timerlist_test testdata)

add_executable(rbuffer_test
  rbuffer_test.c
  treemap.c
  rbuffer.c
)
target_include_directories(rbuffer_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
