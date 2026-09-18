cmake_minimum_required(VERSION 3.25)

# This directory can be added by the product build or configured directly for
# a portable, mock-only benchmark build.
if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
    project(KDBGBenchmarks VERSION 1.1.0 LANGUAGES CXX)

    option(KDBG_WARNINGS_AS_ERRORS "Treat warnings as errors" ON)
    set(CMAKE_CXX_STANDARD 20)
    set(CMAKE_CXX_STANDARD_REQUIRED ON)
    set(CMAKE_CXX_EXTENSIONS OFF)

    include(../cmake/CompilerWarnings.cmake)

    add_library(kdbg_benchmark_core
        ../core/memory/MemoryAccess.cpp
        ../core/memory/MockMemoryBackend.cpp
        ../core/memory/PhysicalPageSession.cpp
        ../core/paging/X64PageTable.cpp
        ../core/pfn/PfnAddress.cpp
        ../core/process/MockProcessMemory.cpp
        ../core/scanner/AobPattern.cpp
        ../core/scanner/MemoryScanner.cpp
        ../core/scanner/PointerScanner.cpp
        ../core/scanner/ValueCodec.cpp
        ../core/snapshot/MemorySnapshot.cpp
    )
    target_include_directories(kdbg_benchmark_core PUBLIC ..)
    if(WIN32)
        target_compile_definitions(kdbg_benchmark_core PUBLIC NOMINMAX)
    endif()
    kdbg_set_project_warnings(kdbg_benchmark_core)
    kdbg_enable_sanitizers(kdbg_benchmark_core)
    kdbg_enable_msvc_analysis(kdbg_benchmark_core)
    set(KDBG_BENCHMARK_CORE_TARGET kdbg_benchmark_core)
else()
    set(KDBG_BENCHMARK_CORE_TARGET kdbg_core)
endif()

add_executable(kdbg_benchmarks benchmark_main.cpp)
target_link_libraries(kdbg_benchmarks PRIVATE ${KDBG_BENCHMARK_CORE_TARGET})
target_include_directories(kdbg_benchmarks PRIVATE ..)
if(WIN32)
    target_compile_definitions(kdbg_benchmarks PRIVATE NOMINMAX WIN32_LEAN_AND_MEAN)
    target_link_libraries(kdbg_benchmarks PRIVATE Psapi)
endif()
kdbg_set_project_warnings(kdbg_benchmarks)
kdbg_enable_sanitizers(kdbg_benchmarks)
kdbg_enable_msvc_analysis(kdbg_benchmarks)
