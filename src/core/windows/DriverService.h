#pragma once

#include "core/common/Result.h"

#include <cstdint>
#include <filesystem>
#include <string>

namespace kdbg {

struct DriverServiceConfiguration {
    bool exists{false};
    bool running{false};
    std::uint32_t service_type{0};
    std::uint32_t start_type{0};
    std::uint32_t error_control{0};
    std::wstring binary_path;
    std::wstring display_name;
};

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
    static Result<DriverServiceConfiguration> QueryConfiguration(
        const std::wstring& service_name);
    static Result<void> RestoreConfiguration(
        const std::wstring& service_name,
        const DriverServiceConfiguration& configuration);
};

}  // namespace kdbg
