cmake_minimum_required(VERSION 3.25)

project(KDBGLiveVerify LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

function(kdbg_live_warnings target)
    if(MSVC)
        target_compile_options(${target} PRIVATE /W4 /WX /permissive-)
    else()
        target_compile_options(${target} PRIVATE
            -Wall -Wextra -Wpedantic -Wconversion -Wsign-conversion
            -Wshadow -Werror)
    endif()
endfunction()

add_library(kdbg_live_verify_core
    LiveVerify.cpp
    ../../core/memory/PhysicalPageSession.cpp
    ../../core/pfn/PfnAddress.cpp)
target_include_directories(kdbg_live_verify_core PUBLIC
    "${CMAKE_CURRENT_LIST_DIR}"
    "${CMAKE_CURRENT_LIST_DIR}/../..")
kdbg_live_warnings(kdbg_live_verify_core)

if(WIN32)
    enable_language(RC)
    add_executable(kdbg_live_verify
        main.cpp
        resources/kdbg_live_verify.rc
        ../../core/memory/KDbgBackend.cpp
        ../../core/memory/ProbeClient.cpp
        ../../core/paging/X64PageTable.cpp)
    target_link_libraries(kdbg_live_verify PRIVATE
        kdbg_live_verify_core
        Advapi32
        Bcrypt)
    target_compile_definitions(kdbg_live_verify PRIVATE
        UNICODE _UNICODE NOMINMAX WIN32_LEAN_AND_MEAN)
    kdbg_live_warnings(kdbg_live_verify)
endif()

enable_testing()
add_executable(kdbg_live_verify_tests
    tests/live_verify_tests.cpp
    ../../core/memory/MockMemoryBackend.cpp)
target_link_libraries(kdbg_live_verify_tests PRIVATE
    kdbg_live_verify_core)
kdbg_live_warnings(kdbg_live_verify_tests)
add_test(NAME kdbg_live_verify_tests COMMAND kdbg_live_verify_tests)
