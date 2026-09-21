add_executable(kdbg_core_tests
    test_main.cpp
    test_address_watch_durability.cpp
    test_page_session.cpp
    test_page_table.cpp
    test_process_memory_session.cpp
    test_persistence_migration.cpp
    test_pfn_address.cpp
    test_scanner.cpp
    test_advanced.cpp
    test_kdbg_abi_layout.cpp
    test_kernel_module.cpp
    test_localization.cpp
    test_performance_telemetry.cpp
)

set(KDBG_CTEST_SOURCE_ROOT "${CMAKE_SOURCE_DIR}")
set(KDBG_CTEST_BINARY_ROOT "${CMAKE_BINARY_DIR}")
if(KDBG_TEST_SOURCE_ROOT)
    set(KDBG_CTEST_SOURCE_ROOT "${KDBG_TEST_SOURCE_ROOT}")
endif()
if(KDBG_TEST_BINARY_ROOT)
    set(KDBG_CTEST_BINARY_ROOT "${KDBG_TEST_BINARY_ROOT}")
endif()

target_link_libraries(kdbg_core_tests PRIVATE
    kdbg_core
    kdbg_app_localization
    kdbg_app_telemetry)
target_include_directories(kdbg_core_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
kdbg_set_project_warnings(kdbg_core_tests)
kdbg_enable_sanitizers(kdbg_core_tests)
kdbg_enable_msvc_analysis(kdbg_core_tests)
if(MSVC AND KDBG_ENABLE_MSVC_ANALYZE)
    # The aggregate deterministic test dispatcher intentionally keeps many
    # independent fixtures in one function; production targets retain the
    # stricter default analyzer stack threshold.
    target_compile_options(kdbg_core_tests PRIVATE /analyze:stacksize 65536)
endif()

if(WIN32)
    target_link_libraries(kdbg_core_tests PRIVATE kdbg_windows)
    add_executable(kdbg_memprocfs_provider_test_helper
        memprocfs_provider_test_helper.cpp)
    kdbg_set_project_warnings(kdbg_memprocfs_provider_test_helper)
    kdbg_enable_sanitizers(kdbg_memprocfs_provider_test_helper)
    kdbg_enable_msvc_analysis(kdbg_memprocfs_provider_test_helper)
    add_dependencies(kdbg_core_tests kdbg_memprocfs_provider_test_helper)
    if(KDBG_TEST_BINARY_ROOT)
        target_compile_definitions(kdbg_core_tests PRIVATE
            "KDBG_MEMPROCFS_PROVIDER_TEST_HELPER_PATH=\"${KDBG_TEST_BINARY_ROOT}/tests/$<TARGET_FILE_NAME:kdbg_memprocfs_provider_test_helper>\"")
    else()
        target_compile_definitions(kdbg_core_tests PRIVATE
            "KDBG_MEMPROCFS_PROVIDER_TEST_HELPER_PATH=\"$<TARGET_FILE:kdbg_memprocfs_provider_test_helper>\"")
    endif()
endif()

find_package(Python3 COMPONENTS Interpreter QUIET)
if(Python3_Interpreter_FOUND)
    add_test(
        NAME kdbg_release_validator_tests
        COMMAND "${Python3_EXECUTABLE}"
            "${KDBG_CTEST_SOURCE_ROOT}/tests/test_validate_release.py")
    add_test(
        NAME kdbg_verified_page_transaction_source_tests
        COMMAND "${Python3_EXECUTABLE}"
            "${KDBG_CTEST_SOURCE_ROOT}/tests/test_verified_page_transaction_source.py")
endif()

add_test(NAME kdbg_core_tests COMMAND
    "${KDBG_CTEST_BINARY_ROOT}/tests/$<TARGET_FILE_NAME:kdbg_core_tests>")

if(TARGET kdbg_process_fixture)
    add_test(
        NAME kdbg_process_fixture_self_test
        COMMAND "${KDBG_CTEST_BINARY_ROOT}/$<TARGET_FILE_NAME:kdbg_process_fixture>"
            --self-test)
endif()

if(TARGET kdbg_live_verify_core)
    set(KDBG_LIVE_VERIFY_TEST_DIR
        "${CMAKE_CURRENT_SOURCE_DIR}/../tools/live_verify/tests")
    set(KDBG_LIVE_VERIFY_TEST_SOURCE "live_verify_tests.cpp")
    add_executable(kdbg_live_verify_tests
        "${KDBG_LIVE_VERIFY_TEST_DIR}/${KDBG_LIVE_VERIFY_TEST_SOURCE}")
    target_link_libraries(kdbg_live_verify_tests PRIVATE
        kdbg_live_verify_core)
    kdbg_set_project_warnings(kdbg_live_verify_tests)
    kdbg_enable_sanitizers(kdbg_live_verify_tests)
    kdbg_enable_msvc_analysis(kdbg_live_verify_tests)
    add_test(NAME kdbg_live_verify_tests COMMAND
        "${KDBG_CTEST_BINARY_ROOT}/tests/$<TARGET_FILE_NAME:kdbg_live_verify_tests>")
endif()

if(WIN32)
    find_program(KDBG_POWERSHELL_EXECUTABLE NAMES pwsh powershell)
    if(KDBG_POWERSHELL_EXECUTABLE)
        if(TARGET kdbg_process_fixture)
            add_test(
                NAME kdbg_process_fixture_protocol_tests
                COMMAND "${KDBG_POWERSHELL_EXECUTABLE}"
                    -NoLogo -NoProfile -NonInteractive
                    -ExecutionPolicy Bypass
                    -File "${KDBG_CTEST_SOURCE_ROOT}/tests/process_fixture_tests.ps1"
                    -FixturePath "${KDBG_CTEST_BINARY_ROOT}/$<TARGET_FILE_NAME:kdbg_process_fixture>")
        endif()
        add_test(
            NAME kdbg_package_lifecycle_tests
            COMMAND "${KDBG_POWERSHELL_EXECUTABLE}"
                -NoLogo -NoProfile -NonInteractive
                -ExecutionPolicy Bypass
                -File "${KDBG_CTEST_SOURCE_ROOT}/tests/package_lifecycle_tests.ps1")
        add_test(
            NAME kdbg_target_profile_contract_tests
            COMMAND "${KDBG_POWERSHELL_EXECUTABLE}"
                -NoLogo -NoProfile -NonInteractive
                -ExecutionPolicy Bypass
                -File "${KDBG_CTEST_SOURCE_ROOT}/tools/package/tests/TargetProfile.Contract.ps1")
        add_test(
            NAME kdbg_setup_contract_tests
            COMMAND "${KDBG_POWERSHELL_EXECUTABLE}"
                -NoLogo -NoProfile -NonInteractive
                -ExecutionPolicy Bypass
                -File "${KDBG_CTEST_SOURCE_ROOT}/tests/setup_contract_tests.ps1")
        add_test(
            NAME kdbg_production_signing_contract_tests
            COMMAND "${KDBG_POWERSHELL_EXECUTABLE}"
                -NoLogo -NoProfile -NonInteractive
                -ExecutionPolicy Bypass
                -File "${KDBG_CTEST_SOURCE_ROOT}/tests/production_signing_contract_tests.ps1")
        add_test(
            NAME kdbg_win11_harness_tests
            COMMAND "${KDBG_POWERSHELL_EXECUTABLE}"
                -NoLogo -NoProfile -NonInteractive
                -ExecutionPolicy Bypass
                -File "${KDBG_CTEST_SOURCE_ROOT}/tests/win11_harness_tests.ps1")
        add_test(
            NAME kdbg_win11_test_signed_package_contract_tests
            COMMAND "${KDBG_POWERSHELL_EXECUTABLE}"
                -NoLogo -NoProfile -NonInteractive
                -ExecutionPolicy Bypass
                -File "${KDBG_CTEST_SOURCE_ROOT}/tools/win11_validation/New-Win11TestSignedPackage.Contract.Tests.ps1")
        add_test(
            NAME kdbg_win11_workspace_generator_contract_tests
            COMMAND "${KDBG_POWERSHELL_EXECUTABLE}"
                -NoLogo -NoProfile -NonInteractive
                -ExecutionPolicy Bypass
                -File "${KDBG_CTEST_SOURCE_ROOT}/tools/win11_validation/workspace/Test-Win11ValidationWorkspaceGenerator.Contract.ps1")
        add_test(
            NAME kdbg_win11_baremetal_validation_contract_tests
            COMMAND "${KDBG_POWERSHELL_EXECUTABLE}"
                -NoLogo -NoProfile -NonInteractive
                -ExecutionPolicy Bypass
                -File "${KDBG_CTEST_SOURCE_ROOT}/tools/win11_baremetal_validation/Win11BareMetalValidation.Contract.Tests.ps1")
    endif()
endif()
