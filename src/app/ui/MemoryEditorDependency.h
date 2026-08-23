#pragma once

#include <imgui.h>

// imgui_memory_editor's pinned U64 formatter passes a signed long long to
// "%llu". Scope the MSVC analyzer suppression to that third-party header;
// KDBG-owned translation units retain /analyze /WX for C6340.
#if defined(_MSC_VER)
#pragma warning(push)
#pragma warning(disable : 6340)
#endif
#include <imgui_memory_editor.h>
#if defined(_MSC_VER)
#pragma warning(pop)
#endif
