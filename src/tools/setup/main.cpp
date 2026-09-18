#include <windows.h>

#include <array>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace {

constexpr wchar_t kWindowClass[] = L"KDBGSetupWindow";
constexpr wchar_t kWindowTitle[] = L"KDBG Setup 1.1.0";
constexpr UINT kAppendOutput = WM_APP + 1U;
constexpr UINT kOperationFinished = WM_APP + 2U;
constexpr int kConfirmVmId = 1001;
constexpr int kConfirmSnapshotId = 1002;
constexpr int kInstallId = 1101;
constexpr int kRepairId = 1102;
constexpr int kUpdateId = 1103;
constexpr int kUninstallId = 1104;
constexpr int kOutputId = 1201;

struct WindowState {
    HWND window{};
    HWND output{};
    HWND confirmVm{};
    HWND confirmSnapshot{};
    std::array<HWND, 4> actionButtons{};
    HANDLE worker{};
    bool operationRunning{};
    std::wstring pendingAction;
};

struct WorkerInput {
    HWND window{};
    std::wstring action;
};

std::wstring FormatWin32Error(const DWORD code) {
    wchar_t* buffer = nullptr;
    const DWORD length = FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
            FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr, code, 0, reinterpret_cast<wchar_t*>(&buffer), 0, nullptr);
    std::wstring message = length == 0U ? L"Unknown Windows error"
                                        : std::wstring(buffer, length);
    if (buffer != nullptr) {
        LocalFree(buffer);
    }
    while (!message.empty() &&
           (message.back() == L'\r' || message.back() == L'\n')) {
        message.pop_back();
    }
    return message;
}

std::wstring QuoteArgument(const std::wstring_view value) {
    if (value.find_first_of(L" \t\n\v\"") == std::wstring_view::npos) {
        return std::wstring(value);
    }
    std::wstring quoted(1, L'"');
    std::size_t backslashes = 0;
    for (const wchar_t character : value) {
        if (character == L'\\') {
            ++backslashes;
            continue;
        }
        if (character == L'"') {
            quoted.append(backslashes * 2U + 1U, L'\\');
            quoted.push_back(L'"');
            backslashes = 0;
            continue;
        }
        quoted.append(backslashes, L'\\');
        backslashes = 0;
        quoted.push_back(character);
    }
    quoted.append(backslashes * 2U, L'\\');
    quoted.push_back(L'"');
    return quoted;
}

std::optional<std::filesystem::path> ModuleDirectory(std::wstring& error) {
    std::vector<wchar_t> buffer(512U, L'\0');
    for (;;) {
        const DWORD length = GetModuleFileNameW(
            nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
        if (length == 0U) {
            error = L"GetModuleFileNameW failed: " +
                    FormatWin32Error(GetLastError());
            return std::nullopt;
        }
        if (length < buffer.size() - 1U) {
            return std::filesystem::path(
                       std::wstring(buffer.data(), length))
                .parent_path();
        }
        if (buffer.size() >= 32768U) {
            error = L"Setup executable path exceeds the Windows path limit.";
            return std::nullopt;
        }
        buffer.resize(buffer.size() * 2U, L'\0');
    }
}

void PostOutput(const HWND window, std::wstring message) {
    auto text = std::make_unique<std::wstring>(std::move(message));
    if (!PostMessageW(window, kAppendOutput, 0,
                      reinterpret_cast<LPARAM>(text.get()))) {
        return;
    }
    static_cast<void>(text.release());
}

std::wstring DecodeOutput(const std::vector<std::uint8_t>& bytes) {
    if (bytes.empty()) {
        return {};
    }
    const int needed = MultiByteToWideChar(
        CP_UTF8, MB_ERR_INVALID_CHARS,
        reinterpret_cast<const char*>(bytes.data()),
        static_cast<int>(bytes.size()), nullptr, 0);
    if (needed > 0) {
        std::wstring output(static_cast<std::size_t>(needed), L'\0');
        static_cast<void>(MultiByteToWideChar(
            CP_UTF8, MB_ERR_INVALID_CHARS,
            reinterpret_cast<const char*>(bytes.data()),
            static_cast<int>(bytes.size()), output.data(), needed));
        return output;
    }
    const int fallbackNeeded = MultiByteToWideChar(
        CP_ACP, 0, reinterpret_cast<const char*>(bytes.data()),
        static_cast<int>(bytes.size()), nullptr, 0);
    if (fallbackNeeded <= 0) {
        return L"[Setup could not decode child-process output.]\r\n";
    }
    std::wstring output(static_cast<std::size_t>(fallbackNeeded), L'\0');
    static_cast<void>(MultiByteToWideChar(
        CP_ACP, 0, reinterpret_cast<const char*>(bytes.data()),
        static_cast<int>(bytes.size()), output.data(), fallbackNeeded));
    return output;
}

DWORD WINAPI RunOperation(void* rawInput) {
    const std::unique_ptr<WorkerInput> input(
        static_cast<WorkerInput*>(rawInput));
    std::wstring moduleError;
    const auto packageRoot = ModuleDirectory(moduleError);
    if (!packageRoot.has_value()) {
        PostOutput(input->window, moduleError + L"\r\n");
        PostMessageW(input->window, kOperationFinished, 1U, 0);
        return 1U;
    }
    const auto script = *packageRoot / L"tools" / L"setup.ps1";
    if (!std::filesystem::is_regular_file(script)) {
        PostOutput(input->window,
                   L"Required setup script is missing: " + script.wstring() +
                       L"\r\n");
        PostMessageW(input->window, kOperationFinished, 1U, 0);
        return 1U;
    }

    wchar_t systemDirectory[MAX_PATH]{};
    const UINT systemLength = GetSystemDirectoryW(systemDirectory, MAX_PATH);
    if (systemLength == 0U || systemLength >= MAX_PATH) {
        PostOutput(input->window,
                   L"Windows PowerShell location could not be resolved.\r\n");
        PostMessageW(input->window, kOperationFinished, 1U, 0);
        return 1U;
    }
    const auto powershell = std::filesystem::path(systemDirectory) /
                            L"WindowsPowerShell" / L"v1.0" /
                            L"powershell.exe";
    if (!std::filesystem::is_regular_file(powershell)) {
        PostOutput(input->window,
                   L"Windows PowerShell is unavailable: " +
                       powershell.wstring() + L"\r\n");
        PostMessageW(input->window, kOperationFinished, 1U, 0);
        return 1U;
    }

    SECURITY_ATTRIBUTES security{};
    security.nLength = sizeof(security);
    security.bInheritHandle = TRUE;
    HANDLE readPipeRaw = nullptr;
    HANDLE writePipeRaw = nullptr;
    if (!CreatePipe(&readPipeRaw, &writePipeRaw, &security, 0U)) {
        PostOutput(input->window,
                   L"Output pipe creation failed: " +
                       FormatWin32Error(GetLastError()) + L"\r\n");
        PostMessageW(input->window, kOperationFinished, 1U, 0);
        return 1U;
    }
    const auto closeHandle = [](HANDLE handle) {
        if (handle != nullptr && handle != INVALID_HANDLE_VALUE) {
            CloseHandle(handle);
        }
    };
    std::unique_ptr<void, decltype(closeHandle)> readPipe(
        readPipeRaw, closeHandle);
    std::unique_ptr<void, decltype(closeHandle)> writePipe(
        writePipeRaw, closeHandle);
    if (!SetHandleInformation(readPipe.get(), HANDLE_FLAG_INHERIT, 0U)) {
        PostOutput(input->window,
                   L"Output pipe configuration failed: " +
                       FormatWin32Error(GetLastError()) + L"\r\n");
        PostMessageW(input->window, kOperationFinished, 1U, 0);
        return 1U;
    }

    std::wstring command = QuoteArgument(powershell.wstring()) +
        L" -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File " +
        QuoteArgument(script.wstring()) + L" -Action " + input->action +
        L" -ConfirmDedicatedVm -ConfirmSnapshot -HostProcessId " +
        std::to_wstring(GetCurrentProcessId());
    std::vector<wchar_t> mutableCommand(command.begin(), command.end());
    mutableCommand.push_back(L'\0');

    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    startup.dwFlags = STARTF_USESTDHANDLES;
    startup.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    startup.hStdOutput = writePipe.get();
    startup.hStdError = writePipe.get();
    PROCESS_INFORMATION process{};
    const BOOL created = CreateProcessW(
        powershell.c_str(), mutableCommand.data(), nullptr, nullptr, TRUE,
        CREATE_NO_WINDOW, nullptr, packageRoot->c_str(), &startup, &process);
    if (!created) {
        PostOutput(input->window,
                   L"PowerShell launch failed: " +
                       FormatWin32Error(GetLastError()) + L"\r\n");
        PostMessageW(input->window, kOperationFinished, 1U, 0);
        return 1U;
    }
    CloseHandle(process.hThread);
    writePipe.reset();

    std::array<std::uint8_t, 4096> buffer{};
    for (;;) {
        DWORD read = 0;
        const BOOL succeeded = ReadFile(
            readPipe.get(), buffer.data(), static_cast<DWORD>(buffer.size()),
            &read, nullptr);
        if (succeeded && read > 0U) {
            std::vector<std::uint8_t> chunk(
                buffer.begin(), buffer.begin() + static_cast<std::ptrdiff_t>(read));
            PostOutput(input->window, DecodeOutput(chunk));
            continue;
        }
        if (!succeeded && GetLastError() != ERROR_BROKEN_PIPE) {
            PostOutput(input->window,
                       L"Output capture failed: " +
                           FormatWin32Error(GetLastError()) + L"\r\n");
        }
        break;
    }

    static_cast<void>(WaitForSingleObject(process.hProcess, INFINITE));
    DWORD exitCode = 1U;
    if (!GetExitCodeProcess(process.hProcess, &exitCode)) {
        PostOutput(input->window,
                   L"Setup exit status could not be read: " +
                       FormatWin32Error(GetLastError()) + L"\r\n");
        exitCode = 1U;
    }
    CloseHandle(process.hProcess);
    PostMessageW(input->window, kOperationFinished,
                 static_cast<WPARAM>(exitCode), 0);
    return exitCode;
}

void AppendOutput(const WindowState& state, const std::wstring_view text) {
    const LRESULT length = SendMessageW(state.output, WM_GETTEXTLENGTH, 0, 0);
    SendMessageW(state.output, EM_SETSEL,
                 static_cast<WPARAM>(length), static_cast<LPARAM>(length));
    SendMessageW(state.output, EM_REPLACESEL, FALSE,
                 reinterpret_cast<LPARAM>(text.data()));
    SendMessageW(state.output, EM_SCROLLCARET, 0, 0);
}

void SetControlsEnabled(const WindowState& state, const BOOL enabled) {
    EnableWindow(state.confirmVm, enabled);
    EnableWindow(state.confirmSnapshot, enabled);
    for (const HWND button : state.actionButtons) {
        EnableWindow(button, enabled);
    }
}

void StartOperation(WindowState& state, std::wstring action) {
    if (state.operationRunning) {
        return;
    }
    if (SendMessageW(state.confirmVm, BM_GETCHECK, 0, 0) != BST_CHECKED ||
        SendMessageW(state.confirmSnapshot, BM_GETCHECK, 0, 0) != BST_CHECKED) {
        MessageBoxW(state.window,
                    L"Confirm both the dedicated disposable VM and its restorable snapshot before continuing.",
                    kWindowTitle, MB_OK | MB_ICONWARNING);
        return;
    }
    state.operationRunning = true;
    state.pendingAction = std::move(action);
    SetControlsEnabled(state, FALSE);
    AppendOutput(state, L"\r\n=== " + state.pendingAction + L" ===\r\n");
    auto input = std::make_unique<WorkerInput>();
    input->window = state.window;
    input->action = state.pendingAction;
    state.worker = CreateThread(nullptr, 0, RunOperation, input.get(), 0, nullptr);
    if (state.worker == nullptr) {
        AppendOutput(state,
                     L"Worker creation failed: " +
                         FormatWin32Error(GetLastError()) + L"\r\n");
        state.operationRunning = false;
        SetControlsEnabled(state, TRUE);
        return;
    }
    static_cast<void>(input.release());
}

HWND CreateControl(const wchar_t* className, const wchar_t* text,
                   const DWORD style, const int x, const int y,
                   const int width, const int height, const HWND parent,
                   const int id) {
    return CreateWindowExW(
        0, className, text, WS_CHILD | WS_VISIBLE | style, x, y, width,
        height, parent, reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)),
        GetModuleHandleW(nullptr), nullptr);
}

LRESULT CALLBACK WindowProcedure(const HWND window, const UINT message,
                                 const WPARAM wParam, const LPARAM lParam) {
    auto* state = reinterpret_cast<WindowState*>(
        GetWindowLongPtrW(window, GWLP_USERDATA));
    switch (message) {
    case WM_CREATE: {
        auto owned = std::make_unique<WindowState>();
        owned->window = window;
        SetWindowLongPtrW(window, GWLP_USERDATA,
                          reinterpret_cast<LONG_PTR>(owned.get()));
        const HFONT font = static_cast<HFONT>(GetStockObject(DEFAULT_GUI_FONT));
        const HWND heading = CreateControl(
            L"STATIC", L"KDBG product setup", SS_LEFT, 18, 16, 700, 24,
            window, 0);
        const HWND scope = CreateControl(
            L"STATIC",
            L"Installs or services the hash-verified package in Program Files. Driver catalog trust is checked by the packaged transactional lifecycle.",
            SS_LEFT, 18, 44, 730, 38, window, 0);
        owned->confirmVm = CreateControl(
            L"BUTTON", L"This is the dedicated disposable KDBG VM",
            BS_AUTOCHECKBOX | WS_TABSTOP, 18, 86, 350, 24, window,
            kConfirmVmId);
        owned->confirmSnapshot = CreateControl(
            L"BUTTON", L"A restorable snapshot exists",
            BS_AUTOCHECKBOX | WS_TABSTOP, 390, 86, 310, 24, window,
            kConfirmSnapshotId);
        const std::array<std::pair<const wchar_t*, int>, 4> actions{{
            {L"Install", kInstallId}, {L"Repair", kRepairId},
            {L"Update", kUpdateId}, {L"Uninstall", kUninstallId}}};
        for (std::size_t index = 0; index < actions.size(); ++index) {
            owned->actionButtons[index] = CreateControl(
                L"BUTTON", actions[index].first,
                BS_PUSHBUTTON | WS_TABSTOP,
                18 + static_cast<int>(index) * 182, 122, 164, 32,
                window, actions[index].second);
        }
        owned->output = CreateControl(
            L"EDIT",
            L"Ready. Package integrity and driver catalog trust are checked before mutation. User-mode publisher signing is a separate release gate.\r\nAll output, rollback details, and errors remain visible here.\r\n",
            ES_MULTILINE | ES_AUTOVSCROLL | ES_READONLY | WS_VSCROLL |
                WS_BORDER,
            18, 170, 730, 330, window, kOutputId);
        for (const HWND control : std::array<HWND, 8>{
                 heading, scope, owned->confirmVm, owned->confirmSnapshot,
                 owned->actionButtons[0], owned->actionButtons[1],
                 owned->actionButtons[2], owned->actionButtons[3]}) {
            SendMessageW(control, WM_SETFONT,
                         reinterpret_cast<WPARAM>(font), TRUE);
        }
        SendMessageW(owned->output, WM_SETFONT,
                     reinterpret_cast<WPARAM>(font), TRUE);
        state = owned.release();

        const std::wstring commandLine = GetCommandLineW();
        if (commandLine.find(L"/uninstall") != std::wstring::npos) {
            AppendOutput(*state,
                L"Windows Apps & Features requested uninstall. Confirm the VM and snapshot, then choose Uninstall.\r\n");
            SetFocus(state->confirmVm);
        } else if (commandLine.find(L"/repair") != std::wstring::npos) {
            AppendOutput(*state,
                L"Windows Apps & Features requested repair. Confirm the VM and snapshot, then choose Repair.\r\n");
            SetFocus(state->confirmVm);
        }
        return 0;
    }
    case WM_COMMAND:
        if (state == nullptr || HIWORD(wParam) != BN_CLICKED) {
            break;
        }
        switch (LOWORD(wParam)) {
        case kInstallId: StartOperation(*state, L"Install"); return 0;
        case kRepairId: StartOperation(*state, L"Repair"); return 0;
        case kUpdateId: StartOperation(*state, L"Update"); return 0;
        case kUninstallId: StartOperation(*state, L"Uninstall"); return 0;
        default: break;
        }
        break;
    case kAppendOutput:
        if (state != nullptr) {
            const std::unique_ptr<std::wstring> text(
                reinterpret_cast<std::wstring*>(lParam));
            AppendOutput(*state, *text);
        }
        return 0;
    case kOperationFinished:
        if (state != nullptr) {
            const DWORD exitCode = static_cast<DWORD>(wParam);
            if (state->worker != nullptr) {
                CloseHandle(state->worker);
                state->worker = nullptr;
            }
            state->operationRunning = false;
            SetControlsEnabled(*state, TRUE);
            if (exitCode != 0U) {
                AppendOutput(*state,
                    L"=== Operation failed; review the exact error and rollback output above ===\r\n");
            } else if (state->pendingAction == L"Uninstall") {
                AppendOutput(*state,
                    L"=== Uninstall service phase succeeded; package purge remains pending. Review the PURGE_SCHEDULED status file after Setup exits. ===\r\n");
            } else {
                AppendOutput(*state,
                    L"=== Operation completed successfully ===\r\n");
            }
        }
        return 0;
    case WM_CLOSE:
        if (state != nullptr && state->operationRunning) {
            MessageBoxW(window,
                        L"Setup is still running. Wait for the current transaction and rollback handling to finish.",
                        kWindowTitle, MB_OK | MB_ICONINFORMATION);
            return 0;
        }
        DestroyWindow(window);
        return 0;
    case WM_DESTROY:
        delete state;
        SetWindowLongPtrW(window, GWLP_USERDATA, 0);
        PostQuitMessage(0);
        return 0;
    default:
        break;
    }
    return DefWindowProcW(window, message, wParam, lParam);
}

}  // namespace

int WINAPI wWinMain(
    _In_ HINSTANCE instance,
    _In_opt_ HINSTANCE,
    _In_ PWSTR,
    _In_ int showCommand) {
    WNDCLASSEXW windowClass{};
    windowClass.cbSize = sizeof(windowClass);
    windowClass.style = CS_HREDRAW | CS_VREDRAW;
    windowClass.lpfnWndProc = WindowProcedure;
    windowClass.hInstance = instance;
    windowClass.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    windowClass.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1);
    windowClass.lpszClassName = kWindowClass;
    if (RegisterClassExW(&windowClass) == 0U) {
        return static_cast<int>(GetLastError());
    }
    const HWND window = CreateWindowExW(
        0, kWindowClass, kWindowTitle,
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
        CW_USEDEFAULT, CW_USEDEFAULT, 784, 558, nullptr, nullptr, instance,
        nullptr);
    if (window == nullptr) {
        return static_cast<int>(GetLastError());
    }
    ShowWindow(window, showCommand);
    UpdateWindow(window);
    MSG message{};
    while (GetMessageW(&message, nullptr, 0, 0) > 0) {
        TranslateMessage(&message);
        DispatchMessageW(&message);
    }
    return static_cast<int>(message.wParam);
}
