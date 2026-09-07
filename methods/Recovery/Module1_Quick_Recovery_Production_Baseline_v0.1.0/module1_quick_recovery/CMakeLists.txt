cmake_minimum_required(VERSION 3.20)
project(quick_recovery VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(QUICK_BUILD_TESTS "Build unit tests" ON)
option(QUICK_BUILD_TOOLS "Build CLI tools" ON)

add_library(quick_core
    src/source.cpp
    src/partition.cpp
    src/filesystem.cpp
    src/ntfs.cpp
    src/fat.cpp
    src/exfat.cpp
    src/recovery.cpp
    src/json.cpp
)

target_include_directories(quick_core PUBLIC include)
target_compile_definitions(quick_core PRIVATE QUICK_VERSION="${PROJECT_VERSION}")

if(MSVC)
  target_compile_options(quick_core PRIVATE /W4 /permissive- /EHsc)
else()
  target_compile_options(quick_core PRIVATE -Wall -Wextra -Wpedantic -Wconversion -Wshadow)
endif()

if(QUICK_BUILD_TOOLS)
  add_executable(quickscan src/main.cpp)
  target_link_libraries(quickscan PRIVATE quick_core)
endif()

if(QUICK_BUILD_TESTS)
  enable_testing()
  add_executable(quick_tests tests/test_main.cpp)
  target_link_libraries(quick_tests PRIVATE quick_core)
  add_test(NAME quick_tests COMMAND quick_tests)
endif()

install(TARGETS quickscan RUNTIME DESTINATION bin)
