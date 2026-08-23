cmake_minimum_required(VERSION 3.25)

project(KDBG VERSION 1.0.0 LANGUAGES CXX)

option(KDBG_BUILD_TESTS "Build platform-independent core tests" ON)
option(KDBG_BUILD_GUI "Build the Windows KDBG GUI" OFF)
option(KDBG_BUILD_MEMPROCFS_BRIDGE "Build the isolated MemProcFS PFN bridge" ON)
option(KDBG_BUILD_BENCHMARKS "Build deterministic mock performance benchmarks" OFF)
option(KDBG_WARNINGS_AS_ERRORS "Treat warnings as errors in KDBG-owned code" ON)
option(KDBG_ENABLE_SANITIZERS "Enable AddressSanitizer and UndefinedBehaviorSanitizer" OFF)
option(KDBG_ENABLE_MSVC_ANALYZE "Enable MSVC native code analysis" OFF)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

include(cmake/CompilerWarnings.cmake)

add_library(kdbg_core
    core/address/AddressList.cpp
    core/address/PointerResolver.cpp
    core/memory/MemoryAccess.cpp
    core/memory/MockMemoryBackend.cpp
    core/memory/PhysicalPageSession.cpp
    core/memory/ProcessMemorySession.cpp
    core/memory/VerifiedWriter.cpp
    core/paging/X64PageTable.cpp
    core/pfn/MemProcFsProvider.cpp
    core/pfn/PageTableReverseMapper.cpp
    core/pfn/PfnAddress.cpp
    core/process/MockProcessMemory.cpp
    core/scanner/AobPattern.cpp
    core/scanner/MemoryScanner.cpp
    core/scanner/PointerScanner.cpp
    core/scanner/ValueCodec.cpp
    core/scanner/WatchList.cpp
    core/snapshot/MemorySnapshot.cpp
)
target_include_directories(kdbg_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
if(WIN32)
    target_compile_definitions(kdbg_core PUBLIC NOMINMAX)
endif()
kdbg_set_project_warnings(kdbg_core)
kdbg_enable_sanitizers(kdbg_core)
kdbg_enable_msvc_analysis(kdbg_core)

if(WIN32)
    enable_language(RC)

    add_library(kdbg_windows
        core/memory/KDbgBackend.cpp
        core/memory/ProbeClient.cpp
        core/process/ProcessCatalog.cpp
        core/process/Win32ProcessMemory.cpp
        core/windows/DriverService.cpp
    )
    target_include_directories(kdbg_windows PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
    target_link_libraries(kdbg_windows PUBLIC kdbg_core Psapi)
    target_compile_definitions(kdbg_windows PUBLIC
        UNICODE _UNICODE NOMINMAX WIN32_LEAN_AND_MEAN)
    kdbg_set_project_warnings(kdbg_windows)
    kdbg_enable_sanitizers(kdbg_windows)
    kdbg_enable_msvc_analysis(kdbg_windows)

    if(KDBG_BUILD_MEMPROCFS_BRIDGE)
        add_executable(kdbg_memprocfs_bridge
            plugins/memprocfs_bridge/main.cpp
            plugins/memprocfs_bridge/resources/kdbg_memprocfs_bridge.rc)
        set_target_properties(kdbg_memprocfs_bridge PROPERTIES
            OUTPUT_NAME "kdbg_memprocfs_bridge")
        target_compile_definitions(kdbg_memprocfs_bridge PRIVATE
            UNICODE _UNICODE NOMINMAX WIN32_LEAN_AND_MEAN)
        kdbg_set_project_warnings(kdbg_memprocfs_bridge)
        kdbg_enable_sanitizers(kdbg_memprocfs_bridge)
        kdbg_enable_msvc_analysis(kdbg_memprocfs_bridge)
    endif()
endif()

if(KDBG_BUILD_GUI)
    if(NOT WIN32)
        message(FATAL_ERROR "KDBG_BUILD_GUI requires Windows")
    endif()

    include(cmake/Dependencies.cmake)
    kdbg_setup_gui_dependencies()

    add_executable(KDBG WIN32
        app/main.cpp
        app/Application.cpp
        app/LocalDiagnostics.cpp
        app/disasm/ZydisDisassembler.cpp
        app/ui/AsyncScanController.cpp
        app/ui/DisassemblyPanel.cpp
        app/ui/HexEditorPanel.cpp
        app/ui/MainWindow.cpp
        app/ui/MemoryMapPanel.cpp
        app/ui/PageTablePanel.cpp
        app/ui/PfnInputPanel.cpp
        app/ui/PointerScanPanel.cpp
        app/ui/ProcessMemoryPanel.cpp
        app/ui/ProcessScannerPanel.cpp
        app/ui/ProcessUsagePanel.cpp
        app/ui/SnapshotPanel.cpp
        app/ui/WriteReviewModal.cpp
        app/resources/KDBG.rc
    )
    target_link_libraries(KDBG PRIVATE
        kdbg_core
        kdbg_windows
        kdbg_imgui
        Zydis
        d3d11
        dxgi
        Dbghelp
        Psapi
    )
    target_compile_definitions(KDBG PRIVATE
        UNICODE _UNICODE NOMINMAX WIN32_LEAN_AND_MEAN)
    kdbg_set_project_warnings(KDBG)
    kdbg_enable_sanitizers(KDBG)
    kdbg_enable_msvc_analysis(KDBG)

    if(TARGET kdbg_memprocfs_bridge)
        add_dependencies(KDBG kdbg_memprocfs_bridge)
        add_custom_command(TARGET KDBG POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E make_directory
                "$<TARGET_FILE_DIR:KDBG>/plugins/memprocfs_bridge"
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
                "$<TARGET_FILE:kdbg_memprocfs_bridge>"
                "$<TARGET_FILE_DIR:KDBG>/plugins/memprocfs_bridge/$<TARGET_FILE_NAME:kdbg_memprocfs_bridge>"
            VERBATIM)
    endif()
endif()

if(KDBG_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

if(KDBG_BUILD_BENCHMARKS)
    add_subdirectory(benchmarks)
endif()
