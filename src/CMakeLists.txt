cmake_minimum_required(VERSION 3.25)

project(KDBG VERSION 1.1.0 LANGUAGES CXX)

option(KDBG_BUILD_TESTS "Build platform-independent core tests" ON)
option(KDBG_BUILD_GUI "Build the Windows KDBG GUI" OFF)
option(KDBG_BUILD_MEMPROCFS_BRIDGE "Build the isolated MemProcFS PFN bridge" ON)
option(KDBG_BUILD_BENCHMARKS "Build deterministic mock performance benchmarks" OFF)
option(KDBG_BUILD_LIVE_VERIFY "Build the disposable-VM live verification CLI" ON)
option(KDBG_BUILD_PROCESS_FIXTURE "Build the deterministic process-memory fixture" ON)
option(KDBG_WARNINGS_AS_ERRORS "Treat warnings as errors in KDBG-owned code" ON)
option(KDBG_ENABLE_SANITIZERS "Enable AddressSanitizer and UndefinedBehaviorSanitizer" OFF)
option(KDBG_ENABLE_MSVC_ANALYZE "Enable MSVC native code analysis" OFF)
option(KDBG_REPRODUCIBLE_RELEASE_SYMBOLS
    "Map repository paths and enable deterministic MSVC Release debug data" ON)
set(KDBG_BUILD_ID "${PROJECT_VERSION}" CACHE STRING
    "Stable build identifier embedded in the KDBG executable")
set(KDBG_TEST_SOURCE_ROOT "" CACHE PATH
    "Optional physical source root used only by post-build CTest commands")
set(KDBG_TEST_BINARY_ROOT "" CACHE PATH
    "Optional physical build root used only by post-build CTest commands")

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Release artifacts must start on a clean supported Windows VM without a
# separately installed Visual C++ Redistributable.  Apply the static MSVC
# runtime globally so KDBG-owned targets and fetched static dependencies agree
# on the same runtime model.
if(MSVC)
    set(CMAKE_MSVC_RUNTIME_LIBRARY
        "MultiThreaded$<$<CONFIG:Debug>:Debug>")

    # Public symbols must not disclose the checkout or build location.  Both
    # source and preset build directories are below the repository root, so a
    # single compiler path map gives every owned target and fetched dependency
    # the same stable logical root.  /pathmap is ignored by MSVC unless the
    # deterministic compiler mode is enabled.
    if(KDBG_REPRODUCIBLE_RELEASE_SYMBOLS)
        get_filename_component(KDBG_REPOSITORY_ROOT
            "${CMAKE_CURRENT_SOURCE_DIR}/.." ABSOLUTE)
        file(TO_NATIVE_PATH "${KDBG_REPOSITORY_ROOT}"
            KDBG_REPOSITORY_ROOT_NATIVE)
        add_compile_options(
            "$<$<CONFIG:Release>:/experimental:deterministic>"
            "$<$<CONFIG:Release>:/Zf>"
            "$<$<CONFIG:Release>:/pathmap:${KDBG_REPOSITORY_ROOT_NATIVE}=KDBG_ROOT>")
    endif()
endif()

include(cmake/CompilerWarnings.cmake)

add_library(kdbg_core
    core/address/AddressList.cpp
    core/address/PointerResolver.cpp
    core/kernel/KernelModule.cpp
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
if(NOT WIN32)
    # The resolver has a platform-independent disconnected/stub path used by
    # portable core tests.  The live Windows implementation remains part of
    # kdbg_windows below, where DbgHelp and Psapi are linked.
    target_sources(kdbg_core PRIVATE core/kernel/LocalSymbolResolver.cpp)
endif()
if(WIN32)
    target_compile_definitions(kdbg_core PUBLIC NOMINMAX)
endif()
kdbg_set_project_warnings(kdbg_core)
kdbg_enable_sanitizers(kdbg_core)
kdbg_enable_msvc_analysis(kdbg_core)
kdbg_enable_release_symbols(kdbg_core)

add_library(kdbg_app_telemetry
    app/PerformanceTelemetry.cpp)
target_include_directories(kdbg_app_telemetry PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(kdbg_app_telemetry PUBLIC kdbg_core)
kdbg_set_project_warnings(kdbg_app_telemetry)
kdbg_enable_sanitizers(kdbg_app_telemetry)
kdbg_enable_msvc_analysis(kdbg_app_telemetry)
kdbg_enable_release_symbols(kdbg_app_telemetry)

add_library(kdbg_app_localization
    app/ui/Localization.cpp)
target_include_directories(kdbg_app_localization PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
kdbg_set_project_warnings(kdbg_app_localization)
kdbg_enable_sanitizers(kdbg_app_localization)
kdbg_enable_msvc_analysis(kdbg_app_localization)
kdbg_enable_release_symbols(kdbg_app_localization)

if(KDBG_BUILD_LIVE_VERIFY OR KDBG_BUILD_TESTS)
    add_library(kdbg_live_verify_core
        tools/live_verify/LiveVerify.cpp)
    target_include_directories(kdbg_live_verify_core PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}/tools/live_verify)
    target_link_libraries(kdbg_live_verify_core PUBLIC kdbg_core)
    kdbg_set_project_warnings(kdbg_live_verify_core)
    kdbg_enable_sanitizers(kdbg_live_verify_core)
    kdbg_enable_msvc_analysis(kdbg_live_verify_core)
    kdbg_enable_release_symbols(kdbg_live_verify_core)
endif()

if(WIN32)
    enable_language(RC)

    add_executable(KDBGSetup WIN32
        tools/setup/main.cpp
        tools/setup/resources/KDBGSetup.rc)
    target_compile_definitions(KDBGSetup PRIVATE
        UNICODE _UNICODE NOMINMAX WIN32_LEAN_AND_MEAN
        WINVER=0x0A00 _WIN32_WINNT=0x0A00)
    if(MINGW)
        target_link_options(KDBGSetup PRIVATE -municode)
    endif()
    kdbg_set_project_warnings(KDBGSetup)
    kdbg_enable_sanitizers(KDBGSetup)
    kdbg_enable_msvc_analysis(KDBGSetup)
    kdbg_enable_release_symbols(KDBGSetup)

    add_library(kdbg_windows
        core/kernel/KernelModuleCatalog.cpp
        core/kernel/LocalSymbolResolver.cpp
        core/memory/KDbgBackend.cpp
        core/memory/ProbeClient.cpp
        core/process/ProcessCatalog.cpp
        core/process/Win32ProcessMemory.cpp
        core/windows/DriverService.cpp
    )
    target_include_directories(kdbg_windows PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
    target_link_libraries(kdbg_windows PUBLIC kdbg_core Psapi Dbghelp)
    target_compile_definitions(kdbg_windows PUBLIC
        UNICODE _UNICODE NOMINMAX WIN32_LEAN_AND_MEAN
        WINVER=0x0A00 _WIN32_WINNT=0x0A00)
    kdbg_set_project_warnings(kdbg_windows)
    kdbg_enable_sanitizers(kdbg_windows)
    kdbg_enable_msvc_analysis(kdbg_windows)
    kdbg_enable_release_symbols(kdbg_windows)

    if(KDBG_BUILD_MEMPROCFS_BRIDGE)
        add_executable(kdbg_memprocfs_bridge
            plugins/memprocfs_bridge/main.cpp
            plugins/memprocfs_bridge/resources/kdbg_memprocfs_bridge.rc)
        set_target_properties(kdbg_memprocfs_bridge PROPERTIES
            OUTPUT_NAME "kdbg_memprocfs_bridge")
        target_compile_definitions(kdbg_memprocfs_bridge PRIVATE
            UNICODE _UNICODE NOMINMAX WIN32_LEAN_AND_MEAN
            WINVER=0x0A00 _WIN32_WINNT=0x0A00)
        kdbg_set_project_warnings(kdbg_memprocfs_bridge)
        kdbg_enable_sanitizers(kdbg_memprocfs_bridge)
        kdbg_enable_msvc_analysis(kdbg_memprocfs_bridge)
        kdbg_enable_release_symbols(kdbg_memprocfs_bridge)
    endif()

    if(KDBG_BUILD_LIVE_VERIFY)
        add_executable(kdbg_live_verify
            tools/live_verify/main.cpp
            tools/live_verify/resources/kdbg_live_verify.rc)
        target_link_libraries(kdbg_live_verify PRIVATE
            kdbg_live_verify_core
            kdbg_windows
            Advapi32
            Bcrypt)
        target_compile_definitions(kdbg_live_verify PRIVATE
            UNICODE _UNICODE NOMINMAX WIN32_LEAN_AND_MEAN
            WINVER=0x0A00 _WIN32_WINNT=0x0A00)
        kdbg_set_project_warnings(kdbg_live_verify)
        kdbg_enable_sanitizers(kdbg_live_verify)
        kdbg_enable_msvc_analysis(kdbg_live_verify)
        kdbg_enable_release_symbols(kdbg_live_verify)
    endif()

    if(KDBG_BUILD_PROCESS_FIXTURE)
        add_executable(kdbg_process_fixture
            fixtures/process_fixture/main.cpp
            fixtures/process_fixture/resources/kdbg_process_fixture.rc)
        target_link_libraries(kdbg_process_fixture PRIVATE Advapi32 Bcrypt)
        target_compile_definitions(kdbg_process_fixture PRIVATE
            UNICODE _UNICODE NOMINMAX WIN32_LEAN_AND_MEAN
            WINVER=0x0A00 _WIN32_WINNT=0x0A00)
        kdbg_set_project_warnings(kdbg_process_fixture)
        kdbg_enable_sanitizers(kdbg_process_fixture)
        kdbg_enable_msvc_analysis(kdbg_process_fixture)
        kdbg_enable_release_symbols(kdbg_process_fixture)
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
        app/ui/KernelExplorerPanel.cpp
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
        kdbg_app_localization
        kdbg_app_telemetry
        kdbg_windows
        kdbg_imgui
        Zydis
        d3d11
        d3dcompiler
        dwmapi
        dxgi
        Dbghelp
        Psapi
    )
    target_compile_definitions(KDBG PRIVATE
        UNICODE _UNICODE NOMINMAX WIN32_LEAN_AND_MEAN
        WINVER=0x0A00 _WIN32_WINNT=0x0A00
        KDBG_BUILD_ID="${KDBG_BUILD_ID}")
    if(MINGW)
        target_link_options(KDBG PRIVATE -municode)
    endif()
    kdbg_set_project_warnings(KDBG)
    kdbg_enable_sanitizers(KDBG)
    kdbg_enable_msvc_analysis(KDBG)
    kdbg_enable_release_symbols(KDBG)

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
