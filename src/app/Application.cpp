#include "app/Application.h"

#include "app/LocalDiagnostics.h"
#include "app/PerformanceTelemetry.h"
#include "app/ui/MainWindow.h"

#ifdef _WIN32

#include <d3d11.h>
#include <imgui.h>
#include <imgui_impl_dx11.h>
#include <imgui_impl_win32.h>
#include <windowsx.h>

#include <algorithm>
#include <iterator>
#include <cmath>
#include <filesystem>
#include <memory>
#include <string>

extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(
    HWND window,
    UINT message,
    WPARAM w_param,
    LPARAM l_param);

namespace {

ID3D11Device* g_device = nullptr;
ID3D11DeviceContext* g_context = nullptr;
IDXGISwapChain* g_swap_chain = nullptr;
ID3D11RenderTargetView* g_render_target = nullptr;
float g_current_dpi_scale = 1.0F;
float g_pending_dpi_scale = 0.0F;
ImGuiStyle g_unscaled_style{};
bool g_unscaled_style_ready = false;

std::string WideToUtf8(std::wstring_view value) {
    if (value.empty()) return {};
    const int required = WideCharToMultiByte(
        CP_UTF8, WC_ERR_INVALID_CHARS,
        value.data(), static_cast<int>(value.size()),
        nullptr, 0, nullptr, nullptr);
    if (required <= 0) return {};
    std::string output(static_cast<std::size_t>(required), '\0');
    if (WideCharToMultiByte(
            CP_UTF8, WC_ERR_INVALID_CHARS,
            value.data(), static_cast<int>(value.size()),
            output.data(), required, nullptr, nullptr) != required) {
        return {};
    }
    return output;
}

std::string SettingsPath() {
    std::wstring local_app_data(32768, L'\0');
    const DWORD length = GetEnvironmentVariableW(
        L"LOCALAPPDATA",
        local_app_data.data(),
        static_cast<DWORD>(local_app_data.size()));
    std::filesystem::path directory;
    if (length != 0 && length < local_app_data.size()) {
        local_app_data.resize(length);
        directory = std::filesystem::path(local_app_data) / L"KDBG";
    } else {
        directory = std::filesystem::current_path();
    }
    std::error_code error;
    std::filesystem::create_directories(directory, error);
    return WideToUtf8((directory / L"KDBG-1.0-imgui.ini").native());
}

void ApplyDpiScale(float scale, bool recreate_device_objects) {
    scale = std::clamp(scale, 1.0F, 4.0F);
    if (std::abs(scale - g_current_dpi_scale) < 0.01F &&
        recreate_device_objects) {
        return;
    }
    ImGuiIO& io = ImGui::GetIO();
    io.Fonts->Clear();
    ImFontConfig font_config{};
    font_config.SizePixels = 13.0F * scale;
    io.Fonts->AddFontDefault(&font_config);
    if (!g_unscaled_style_ready) {
        ImGui::StyleColorsDark();
        g_unscaled_style = ImGui::GetStyle();
        g_unscaled_style_ready = true;
    }
    ImGui::GetStyle() = g_unscaled_style;
    ImGui::GetStyle().ScaleAllSizes(scale);
    g_current_dpi_scale = scale;
    if (recreate_device_objects) {
        ImGui_ImplDX11_InvalidateDeviceObjects();
        ImGui_ImplDX11_CreateDeviceObjects();
    }
}

void CreateRenderTarget() {
    ID3D11Texture2D* back_buffer = nullptr;
    if (SUCCEEDED(g_swap_chain->GetBuffer(
            0,
            IID_PPV_ARGS(&back_buffer)))) {
        static_cast<void>(g_device->CreateRenderTargetView(
            back_buffer,
            nullptr,
            &g_render_target));
        back_buffer->Release();
    }
}

void CleanupRenderTarget() {
    if (g_render_target != nullptr) {
        g_render_target->Release();
        g_render_target = nullptr;
    }
}

bool CreateDeviceD3D(HWND window) {
    DXGI_SWAP_CHAIN_DESC descriptor{};
    descriptor.BufferCount = 2;
    descriptor.BufferDesc.Width = 0;
    descriptor.BufferDesc.Height = 0;
    descriptor.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    descriptor.BufferDesc.RefreshRate.Numerator = 60;
    descriptor.BufferDesc.RefreshRate.Denominator = 1;
    descriptor.Flags = DXGI_SWAP_CHAIN_FLAG_ALLOW_MODE_SWITCH;
    descriptor.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    descriptor.OutputWindow = window;
    descriptor.SampleDesc.Count = 1;
    descriptor.SampleDesc.Quality = 0;
    descriptor.Windowed = TRUE;
    descriptor.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;

    constexpr D3D_FEATURE_LEVEL feature_levels[] = {
        D3D_FEATURE_LEVEL_11_0,
        D3D_FEATURE_LEVEL_10_0
    };
    D3D_FEATURE_LEVEL selected_level{};

    const auto result = D3D11CreateDeviceAndSwapChain(
        nullptr,
        D3D_DRIVER_TYPE_HARDWARE,
        nullptr,
        0,
        feature_levels,
        static_cast<UINT>(std::size(feature_levels)),
        D3D11_SDK_VERSION,
        &descriptor,
        &g_swap_chain,
        &g_device,
        &selected_level,
        &g_context);
    if (FAILED(result)) {
        return false;
    }

    CreateRenderTarget();
    return g_render_target != nullptr;
}

void CleanupDeviceD3D() {
    CleanupRenderTarget();
    if (g_swap_chain != nullptr) {
        g_swap_chain->Release();
        g_swap_chain = nullptr;
    }
    if (g_context != nullptr) {
        g_context->Release();
        g_context = nullptr;
    }
    if (g_device != nullptr) {
        g_device->Release();
        g_device = nullptr;
    }
}

LRESULT WINAPI WindowProcedure(
    HWND window,
    UINT message,
    WPARAM w_param,
    LPARAM l_param) {
    if (ImGui_ImplWin32_WndProcHandler(
            window,
            message,
            w_param,
            l_param) != 0) {
        return 1;
    }

    switch (message) {
    case WM_SIZE:
        if (g_device != nullptr && w_param != SIZE_MINIMIZED) {
            CleanupRenderTarget();
            static_cast<void>(g_swap_chain->ResizeBuffers(
                0,
                static_cast<UINT>(LOWORD(l_param)),
                static_cast<UINT>(HIWORD(l_param)),
                DXGI_FORMAT_UNKNOWN,
                0));
            CreateRenderTarget();
        }
        return 0;
    case WM_GETMINMAXINFO: {
        auto* limits = reinterpret_cast<MINMAXINFO*>(l_param);
        const UINT dpi = GetDpiForWindow(window);
        limits->ptMinTrackSize.x = MulDiv(1100, static_cast<int>(dpi), 96);
        limits->ptMinTrackSize.y = MulDiv(700, static_cast<int>(dpi), 96);
        return 0;
    }
    case WM_DPICHANGED: {
        const auto* suggested = reinterpret_cast<const RECT*>(l_param);
        SetWindowPos(
            window,
            nullptr,
            suggested->left,
            suggested->top,
            suggested->right - suggested->left,
            suggested->bottom - suggested->top,
            SWP_NOACTIVATE | SWP_NOZORDER);
        g_pending_dpi_scale =
            static_cast<float>(HIWORD(w_param)) / 96.0F;
        return 0;
    }
    case WM_SYSCOMMAND:
        if ((w_param & 0xFFF0U) == SC_KEYMENU) {
            return 0;
        }
        break;
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    default:
        break;
    }

    return DefWindowProc(window, message, w_param, l_param);
}

}  // namespace

namespace kdbg {

int Application::Run(HINSTANCE instance, int show_command) {
    ImGui_ImplWin32_EnableDpiAwareness();
    const wchar_t* class_name = L"KDBGWindow";

    WNDCLASSEXW window_class{};
    window_class.cbSize = sizeof(window_class);
    window_class.style = CS_CLASSDC;
    window_class.lpfnWndProc = WindowProcedure;
    window_class.hInstance = instance;
    window_class.lpszClassName = class_name;

    if (RegisterClassExW(&window_class) == 0) {
        LogDiagnostic(
            DiagnosticEvent::WindowClassRegistrationFailed,
            1, GetLastError());
        return 1;
    }

    HWND window = CreateWindowW(
        class_name,
        L"KDBG",
        WS_OVERLAPPEDWINDOW,
        100,
        100,
        1500,
        900,
        nullptr,
        nullptr,
        instance,
        nullptr);
    if (window == nullptr) {
        LogDiagnostic(
            DiagnosticEvent::WindowCreationFailed,
            2, GetLastError());
        UnregisterClassW(class_name, instance);
        return 2;
    }

    if (!CreateDeviceD3D(window)) {
        LogDiagnostic(DiagnosticEvent::GraphicsInitializationFailed, 3);
        DestroyWindow(window);
        UnregisterClassW(class_name, instance);
        return 3;
    }

    ShowWindow(window, show_command);
    UpdateWindow(window);

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO();
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
#ifdef IMGUI_HAS_DOCK
    io.ConfigFlags |= ImGuiConfigFlags_DockingEnable;
#endif
    io.ConfigWindowsMoveFromTitleBarOnly = true;
    static const std::string settings_path = SettingsPath();
    io.IniFilename = settings_path.empty() ? nullptr : settings_path.c_str();

    ApplyDpiScale(ImGui_ImplWin32_GetDpiScaleForHwnd(window), false);
    ImGui_ImplWin32_Init(window);
    ImGui_ImplDX11_Init(g_device, g_context);

    auto main_window = std::make_unique<MainWindow>();
    auto& telemetry = RuntimePerformanceTelemetry();
    static_cast<void>(telemetry.StartFromEnvironment());
    LogDiagnostic(
        DiagnosticEvent::ApplicationStarted,
        static_cast<std::uint64_t>(telemetry.LastStartStatus()),
        telemetry.LastStartNativeCode());
    bool done = false;
    while (!done) {
        MSG message{};
        while (PeekMessage(&message, nullptr, 0, 0, PM_REMOVE) != FALSE) {
            TranslateMessage(&message);
            DispatchMessage(&message);
            if (message.message == WM_QUIT) {
                done = true;
            }
        }
        if (done) {
            break;
        }

        if (g_pending_dpi_scale > 0.0F) {
            const float requested_scale = g_pending_dpi_scale;
            g_pending_dpi_scale = 0.0F;
            ApplyDpiScale(requested_scale, true);
        }

        ImGui_ImplDX11_NewFrame();
        ImGui_ImplWin32_NewFrame();
        ImGui::NewFrame();
        telemetry.RecordFrame();

        main_window->Draw();

        ImGui::Render();
        constexpr float clear_color[4] = {
            0.08F,
            0.08F,
            0.09F,
            1.00F
        };
        g_context->OMSetRenderTargets(
            1,
            &g_render_target,
            nullptr);
        g_context->ClearRenderTargetView(
            g_render_target,
            clear_color);
        ImGui_ImplDX11_RenderDrawData(
            ImGui::GetDrawData());

        static_cast<void>(g_swap_chain->Present(1, 0));
    }

    LogDiagnostic(DiagnosticEvent::ApplicationStopping);
    main_window.reset();
    telemetry.Stop();
    ImGui_ImplDX11_Shutdown();
    ImGui_ImplWin32_Shutdown();
    ImGui::DestroyContext();

    CleanupDeviceD3D();
    DestroyWindow(window);
    UnregisterClassW(class_name, instance);
    return 0;
}

}  // namespace kdbg

#else

namespace kdbg {

int Application::Run() {
    return 1;
}

}  // namespace kdbg

#endif
