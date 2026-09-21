function(kdbg_set_project_warnings target)
    if(MSVC)
        target_compile_options(${target} PRIVATE
            /W4
            /permissive-
            /Zc:__cplusplus
            /utf-8
        )
        if(KDBG_WARNINGS_AS_ERRORS)
            target_compile_options(${target} PRIVATE /WX)
        endif()
    else()
        target_compile_options(${target} PRIVATE
            -Wall
            -Wextra
            -Wpedantic
            -Wconversion
            -Wsign-conversion
            -Wshadow
        )
        if(KDBG_WARNINGS_AS_ERRORS)
            target_compile_options(${target} PRIVATE -Werror)
        endif()
    endif()
endfunction()

function(kdbg_enable_sanitizers target)
    if(NOT KDBG_ENABLE_SANITIZERS)
        return()
    endif()

    if(MSVC)
        message(FATAL_ERROR
            "KDBG_ENABLE_SANITIZERS requires a Clang or GCC-style toolchain")
    endif()
    if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang|GNU")
        message(FATAL_ERROR
            "Unsupported sanitizer compiler: ${CMAKE_CXX_COMPILER_ID}")
    endif()

    target_compile_options(${target} PRIVATE
        -fsanitize=address,undefined
        -fno-omit-frame-pointer)
    get_target_property(kdbg_target_type ${target} TYPE)
    if(NOT kdbg_target_type STREQUAL "STATIC_LIBRARY")
        target_link_options(${target} PRIVATE
            -fsanitize=address,undefined
            -fno-omit-frame-pointer)

        if(WIN32 AND CMAKE_CXX_COMPILER_ID MATCHES "Clang")
            if(NOT DEFINED KDBG_CLANG_ASAN_RUNTIME)
                execute_process(
                    COMMAND ${CMAKE_CXX_COMPILER} --print-resource-dir
                    OUTPUT_VARIABLE kdbg_clang_resource_dir
                    OUTPUT_STRIP_TRAILING_WHITESPACE
                    RESULT_VARIABLE kdbg_clang_resource_result)
                if(NOT kdbg_clang_resource_result EQUAL 0)
                    message(FATAL_ERROR
                        "Unable to locate the Clang sanitizer resource directory")
                endif()
                if(NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
                    message(FATAL_ERROR
                        "The KDBG sanitizer preset currently supports Windows x64 only")
                endif()
                set(KDBG_CLANG_ASAN_RUNTIME
                    "${kdbg_clang_resource_dir}/lib/windows/clang_rt.asan_dynamic-x86_64.dll"
                    CACHE INTERNAL "Clang ASan runtime copied beside test executables")
            endif()
            if(NOT EXISTS "${KDBG_CLANG_ASAN_RUNTIME}")
                message(FATAL_ERROR
                    "Clang ASan runtime was not found: ${KDBG_CLANG_ASAN_RUNTIME}")
            endif()
            add_custom_command(TARGET ${target} POST_BUILD
                COMMAND ${CMAKE_COMMAND} -E copy_if_different
                    "${KDBG_CLANG_ASAN_RUNTIME}"
                    "$<TARGET_FILE_DIR:${target}>/clang_rt.asan_dynamic-x86_64.dll"
                VERBATIM)
        endif()
    endif()
endfunction()

function(kdbg_enable_msvc_analysis target)
    if(NOT KDBG_ENABLE_MSVC_ANALYZE)
        return()
    endif()

    if(NOT MSVC)
        message(FATAL_ERROR
            "KDBG_ENABLE_MSVC_ANALYZE requires the MSVC toolchain")
    endif()
    target_compile_options(${target} PRIVATE /analyze)
endfunction()

function(kdbg_enable_release_symbols target)
    if(NOT MSVC)
        return()
    endif()

    # The distributable Release package has a separate symbols archive. Embed
    # object debug records with /Z7 so compiler PDB temporaries cannot carry a
    # user-profile path into the final linker PDB.  Keep only the PDB basename
    # in PE CodeView and request deterministic linker output.
    target_compile_options(${target} PRIVATE
        "$<$<CONFIG:Release>:/Z7>")
    get_target_property(kdbg_target_type ${target} TYPE)
    if(NOT kdbg_target_type STREQUAL "STATIC_LIBRARY")
        target_link_options(${target} PRIVATE
            "$<$<CONFIG:Release>:/DEBUG:FULL>"
            "$<$<CONFIG:Release>:/PDBALTPATH:%_PDB%>"
            "$<$<AND:$<CONFIG:Release>,$<BOOL:${KDBG_REPRODUCIBLE_RELEASE_SYMBOLS}>>:/Brepro>")
        set_target_properties(${target} PROPERTIES
            PDB_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}")
    endif()
endfunction()
