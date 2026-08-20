cmake_minimum_required(VERSION 3.20)
project(fastscrub LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(NOT MSVC)
    # Bypass the broken C++11 ABI in Conda's GCC 16 by forcing the universally compatible legacy ABI
    add_compile_options(-O3 -march=native -D_GLIBCXX_USE_CXX11_ABI=0)
endif()

find_package(Python COMPONENTS Interpreter Development REQUIRED)
find_package(nanobind CONFIG REQUIRED)

nanobind_add_module(fastscrub_backend
    STABLE_ABI
    NB_STATIC
    src/main.cpp
    src/engine.cpp
    src/matcher.cpp
    src/swar_scanner.cpp
    src/secret_parsers.cpp
)

if(WIN32 AND NOT MSVC)
    # Target-specific static linking (prevents nanobind from dropping directory-level link options)
    target_link_options(fastscrub_backend PRIVATE -static -static-libstdc++ -static-libgcc -Wl,-Bstatic)
    target_link_libraries(fastscrub_backend PRIVATE stdc++)
endif()

install(TARGETS fastscrub_backend DESTINATION fastscrub)

option(FASTSCRUB_BUILD_BENCHMARKS "Build C++ microbenchmarks" OFF)

if(FASTSCRUB_BUILD_BENCHMARKS)
    add_executable(bench_matcher bench/bench_matcher.cpp src/engine.cpp src/matcher.cpp src/swar_scanner.cpp src/secret_parsers.cpp)
    target_link_libraries(bench_matcher PRIVATE stdc++)
    if(NOT MSVC)
        target_compile_options(bench_matcher PRIVATE -O3 -march=native)
    endif()

    add_executable(bench_hardware_limits bench/bench_hardware_limits.cpp src/engine.cpp src/matcher.cpp src/swar_scanner.cpp src/secret_parsers.cpp)
    target_link_libraries(bench_hardware_limits PRIVATE stdc++)
    if(NOT MSVC)
        target_compile_options(bench_hardware_limits PRIVATE -O3 -march=native)
    endif()
endif()
