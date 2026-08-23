#pragma once

#ifdef _WIN32
#include <Windows.h>
#endif

namespace kdbg {

class Application {
public:
#ifdef _WIN32
    int Run(HINSTANCE instance, int show_command);
#else
    int Run();
#endif
};

}  // namespace kdbg
