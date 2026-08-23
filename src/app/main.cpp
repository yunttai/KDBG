#include "app/Application.h"
#include "app/LocalDiagnostics.h"

#ifdef _WIN32
#include <Windows.h>

#include <exception>

int WINAPI wWinMain(
    _In_ HINSTANCE instance,
    _In_opt_ HINSTANCE,
    _In_ PWSTR,
    _In_ int show_command) {
    kdbg::InitializeLocalDiagnostics();
    kdbg::LogDiagnostic(kdbg::DiagnosticEvent::ApplicationStarting);
    int exit_code = 0;
    try {
        kdbg::Application application;
        exit_code = application.Run(instance, show_command);
    } catch (const std::exception& exception) {
        kdbg::LogDiagnostic(kdbg::DiagnosticEvent::FatalStandardException);
        MessageBoxA(
            nullptr,
            exception.what(),
            "KDBG fatal error",
            MB_OK | MB_ICONERROR | MB_TASKMODAL);
        exit_code = 100;
    } catch (...) {
        kdbg::LogDiagnostic(kdbg::DiagnosticEvent::FatalUnknownException);
        MessageBoxW(
            nullptr,
            L"KDBG terminated after an unknown fatal error.",
            L"KDBG fatal error",
            MB_OK | MB_ICONERROR | MB_TASKMODAL);
        exit_code = 101;
    }
    kdbg::LogDiagnostic(
        kdbg::DiagnosticEvent::ApplicationStopped,
        static_cast<std::uint64_t>(exit_code));
    kdbg::ShutdownLocalDiagnostics();
    return exit_code;
}
#else
int main() {
    kdbg::Application application;
    return application.Run();
}
#endif
