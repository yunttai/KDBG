#pragma once

#include "core/common/Result.h"

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace kdbg {

constexpr std::size_t kMaximumKernelModules = 4096;
constexpr std::uint32_t kMaximumKernelReadBytes = 64U * 1024U;

struct PeImageMetadata {
    std::uint16_t machine{0};
    std::uint16_t section_count{0};
    std::uint32_t timestamp{0};
    std::uint32_t image_size{0};
    std::uint32_t checksum{0};
};

struct KernelModule {
    std::uint64_t base{0};
    std::uint32_t image_size{0};
    std::uint32_t timestamp{0};
    std::uint32_t checksum{0};
    std::string name;
    std::filesystem::path image_path;
    std::string metadata_status;

    [[nodiscard]] bool Contains(std::uint64_t address) const noexcept;
};

struct KernelModuleSnapshot {
    std::vector<KernelModule> modules;
    std::vector<std::string> diagnostics;
};

struct KernelModuleEnumerationControl {
    std::atomic_bool* cancel_requested{nullptr};
    std::atomic_size_t* completed{nullptr};
    std::atomic_size_t* total{nullptr};
    bool la57{false};
};

[[nodiscard]] bool IsCanonicalX64Address(
    std::uint64_t address,
    bool la57 = false) noexcept;
[[nodiscard]] bool IsCanonicalX64KernelAddress(
    std::uint64_t address,
    bool la57 = false) noexcept;

Result<PeImageMetadata> ParsePe64ImageMetadata(
    std::span<const std::uint8_t> bytes);

Result<std::vector<std::filesystem::path>> ParseLocalSymbolPath(
    std::string_view text);

Result<KernelModuleSnapshot> EnumerateKernelModules(
    const KernelModuleEnumerationControl& control = {});

}  // namespace kdbg
