cmake_minimum_required(VERSION 3.20)
project(filesystem_recovery VERSION 0.1.0 LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
option(FSREC_BUILD_TESTS "Build tests" ON)

add_library(fsrecover_core
 src/source.cpp src/partition.cpp src/detect.cpp src/ntfs.cpp
 src/fat.cpp src/exfat.cpp src/ext.cpp src/reconstruction.cpp src/json.cpp)
target_include_directories(fsrecover_core PUBLIC include)
if(MSVC)
 target_compile_options(fsrecover_core PRIVATE /W4 /permissive- /EHsc)
else()
 target_compile_options(fsrecover_core PRIVATE -Wall -Wextra -Wpedantic -Wconversion -Wshadow)
endif()

add_executable(fsrecover src/main.cpp)
target_link_libraries(fsrecover PRIVATE fsrecover_core)

if(FSREC_BUILD_TESTS)
 enable_testing()
 add_executable(fsrecover_tests tests/test_main.cpp)
 target_link_libraries(fsrecover_tests PRIVATE fsrecover_core)
 add_test(NAME fsrecover_tests COMMAND fsrecover_tests)
endif()

install(TARGETS fsrecover RUNTIME DESTINATION bin)
