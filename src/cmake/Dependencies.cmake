include(FetchContent)

function(kdbg_setup_gui_dependencies)
    # Pinned values are mirrored in THIRD_PARTY.lock.json.
    FetchContent_Declare(
        dear_imgui
        GIT_REPOSITORY https://github.com/ocornut/imgui.git
        GIT_TAG fd13a1e8923a0a7077b404fc36fd063b25a0c0b5
        GIT_SHALLOW FALSE
    )
    FetchContent_Declare(
        imgui_club
        GIT_REPOSITORY https://github.com/ocornut/imgui_club.git
        GIT_TAG a436e793fe44a2c8e827bfcbf138fcbe11940476
        GIT_SHALLOW FALSE
    )
    set(ZYDIS_BUILD_TOOLS OFF CACHE BOOL "" FORCE)
    set(ZYDIS_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
    set(ZYDIS_BUILD_DOXYGEN OFF CACHE BOOL "" FORCE)
    FetchContent_Declare(
        zydis
        GIT_REPOSITORY https://github.com/zyantific/zydis.git
        GIT_TAG a2278f1d254e492f6a6b39f6cb5d1f5d515659dc
        GIT_SHALLOW FALSE
    )

    FetchContent_MakeAvailable(dear_imgui imgui_club zydis)

    add_library(kdbg_imgui STATIC
        ${dear_imgui_SOURCE_DIR}/imgui.cpp
        ${dear_imgui_SOURCE_DIR}/imgui_demo.cpp
        ${dear_imgui_SOURCE_DIR}/imgui_draw.cpp
        ${dear_imgui_SOURCE_DIR}/imgui_tables.cpp
        ${dear_imgui_SOURCE_DIR}/imgui_widgets.cpp
        ${dear_imgui_SOURCE_DIR}/backends/imgui_impl_dx11.cpp
        ${dear_imgui_SOURCE_DIR}/backends/imgui_impl_win32.cpp
    )

    target_include_directories(kdbg_imgui SYSTEM PUBLIC
        ${dear_imgui_SOURCE_DIR}
        ${dear_imgui_SOURCE_DIR}/backends
        ${imgui_club_SOURCE_DIR}/imgui_memory_editor
    )
    target_compile_definitions(kdbg_imgui PUBLIC IMGUI_DISABLE_OBSOLETE_FUNCTIONS)
endfunction()
