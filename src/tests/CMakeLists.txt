add_executable(kdbg_core_tests
    test_main.cpp
    test_page_session.cpp
    test_page_table.cpp
    test_process_memory_session.cpp
    test_pfn_address.cpp
    test_scanner.cpp
    test_advanced.cpp
    test_kdbg_abi_layout.cpp
)

target_link_libraries(kdbg_core_tests PRIVATE kdbg_core)
target_include_directories(kdbg_core_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
kdbg_set_project_warnings(kdbg_core_tests)
kdbg_enable_sanitizers(kdbg_core_tests)
kdbg_enable_msvc_analysis(kdbg_core_tests)

add_test(NAME kdbg_core_tests COMMAND kdbg_core_tests)
