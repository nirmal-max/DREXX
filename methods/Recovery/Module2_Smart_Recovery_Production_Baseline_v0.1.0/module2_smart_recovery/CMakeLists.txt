cmake_minimum_required(VERSION 3.20)
project(smart_recovery VERSION 0.1.0 LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
option(SMART_BUILD_TESTS "Build tests" ON)

add_library(quick_core
 module1_src/source.cpp module1_src/partition.cpp module1_src/filesystem.cpp
 module1_src/ntfs.cpp module1_src/fat.cpp module1_src/exfat.cpp
 module1_src/recovery.cpp module1_src/json.cpp)
target_include_directories(quick_core PUBLIC include)
if(MSVC)
 target_compile_options(quick_core PRIVATE /W4 /permissive- /EHsc)
else()
 target_compile_options(quick_core PRIVATE -Wall -Wextra -Wpedantic -Wconversion -Wshadow)
endif()

add_library(smart_core src/planner.cpp src/report.cpp)
target_include_directories(smart_core PUBLIC include)
target_link_libraries(smart_core PUBLIC quick_core)

add_executable(smartscan src/main.cpp)
target_link_libraries(smartscan PRIVATE smart_core quick_core)

if(SMART_BUILD_TESTS)
 enable_testing()
 add_executable(smart_tests tests/test_main.cpp)
 target_link_libraries(smart_tests PRIVATE smart_core quick_core)
 add_test(NAME smart_tests COMMAND smart_tests)
endif()

install(TARGETS smartscan RUNTIME DESTINATION bin)
