#pragma once

#include "core/common/Result.h"

#include <filesystem>
#include <string>

namespace kdbg {

class DriverService {
public:
    static Result<void> InstallOrUpdate(
        const std::wstring& service_name,
        const std::wstring& display_name,
        const std::filesystem::path& driver_path);
    static Result<void> Start(const std::wstring& service_name);
    static Result<void> Stop(const std::wstring& service_name);
    static Result<void> Remove(const std::wstring& service_name);
    static Result<bool> IsRunning(const std::wstring& service_name);
};

}  // namespace kdbg
