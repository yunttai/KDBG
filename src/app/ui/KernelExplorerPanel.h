#pragma once

#include "app/disasm/ZydisDisassembler.h"
#include "core/kernel/KernelModule.h"
#include "core/kernel/LocalSymbolResolver.h"
#include "core/memory/IMemoryBackend.h"

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <future>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace kdbg {

[[nodiscard]] inline std::optional<std::size_t> PeHeaderSpanForEvidence(
    std::span<const std::uint8_t> bytes) noexcept {
    const auto read16 = [&](std::size_t offset) -> std::optional<std::uint16_t> {
        if (offset > bytes.size() || bytes.size() - offset < 2U) {
            return std::nullopt;
        }
        return static_cast<std::uint16_t>(
            static_cast<std::uint16_t>(bytes[offset]) |
            (static_cast<std::uint16_t>(bytes[offset + 1U]) << 8U));
    };
    const auto read32 = [&](std::size_t offset) -> std::optional<std::uint32_t> {
        if (offset > bytes.size() || bytes.size() - offset < 4U) {
            return std::nullopt;
        }
        return static_cast<std::uint32_t>(bytes[offset]) |
            (static_cast<std::uint32_t>(bytes[offset + 1U]) << 8U) |
            (static_cast<std::uint32_t>(bytes[offset + 2U]) << 16U) |
            (static_cast<std::uint32_t>(bytes[offset + 3U]) << 24U);
    };
    const auto pe_offset = read32(0x3CU);
    if (!pe_offset.has_value() || *pe_offset > bytes.size() ||
        bytes.size() - *pe_offset < 24U ||
        read32(*pe_offset).value_or(0) != 0x00004550U) {
        return std::nullopt;
    }
    const auto section_count = read16(*pe_offset + 6U);
    const auto optional_size = read16(*pe_offset + 20U);
    const auto optional_offset = static_cast<std::size_t>(*pe_offset) + 24U;
    if (!section_count.has_value() || !optional_size.has_value() ||
        *section_count == 0 || *optional_size < 64U ||
        read16(optional_offset).value_or(0) != 0x20BU) {
        return std::nullopt;
    }
    const auto size_of_headers = read32(optional_offset + 60U);
    const auto section_table_end = optional_offset + *optional_size +
        static_cast<std::size_t>(*section_count) * 40U;
    if (!size_of_headers.has_value() || *size_of_headers < 256U ||
        *size_of_headers > 4096U || *size_of_headers > bytes.size() ||
        section_table_end > *size_of_headers) {
        return std::nullopt;
    }
    return static_cast<std::size_t>(*size_of_headers);
}

struct PeHeaderEvidenceComparison {
    std::size_t header_span{0};
    std::size_t image_base_offset{0};
    std::uint64_t live_image_base{0};
    std::uint64_t local_preferred_image_base{0};
};

// The Windows image loader rewrites OptionalHeader.ImageBase in a loaded
// kernel image to the selected runtime base. Every other byte covered by
// SizeOfHeaders must remain identical to the packaged image.
[[nodiscard]] inline std::optional<PeHeaderEvidenceComparison>
CompareLoadedPeHeadersForEvidence(
    std::span<const std::uint8_t> live,
    std::span<const std::uint8_t> local,
    std::uint64_t loaded_module_base) noexcept {
    const auto live_span = PeHeaderSpanForEvidence(live);
    const auto local_span = PeHeaderSpanForEvidence(local);
    if (!live_span.has_value() || live_span != local_span) {
        return std::nullopt;
    }
    const auto read32 = [](std::span<const std::uint8_t> bytes,
                           std::size_t offset)
            -> std::optional<std::uint32_t> {
        if (offset > bytes.size() || bytes.size() - offset < 4U) {
            return std::nullopt;
        }
        return static_cast<std::uint32_t>(bytes[offset]) |
            (static_cast<std::uint32_t>(bytes[offset + 1U]) << 8U) |
            (static_cast<std::uint32_t>(bytes[offset + 2U]) << 16U) |
            (static_cast<std::uint32_t>(bytes[offset + 3U]) << 24U);
    };
    const auto read64 = [](std::span<const std::uint8_t> bytes,
                           std::size_t offset)
            -> std::optional<std::uint64_t> {
        if (offset > bytes.size() || bytes.size() - offset < 8U) {
            return std::nullopt;
        }
        std::uint64_t value = 0;
        for (std::size_t index = 0; index < 8U; ++index) {
            value |= static_cast<std::uint64_t>(bytes[offset + index])
                << (index * 8U);
        }
        return value;
    };
    const auto live_pe = read32(live, 0x3CU);
    const auto local_pe = read32(local, 0x3CU);
    if (!live_pe.has_value() || live_pe != local_pe) {
        return std::nullopt;
    }
    constexpr std::size_t kPeAndCoffBytes = 24U;
    constexpr std::size_t kPe32PlusImageBaseOffset = 24U;
    if (*local_pe > *local_span ||
        *local_span - *local_pe <
            kPeAndCoffBytes + kPe32PlusImageBaseOffset + 8U) {
        return std::nullopt;
    }
    const auto image_base_offset = static_cast<std::size_t>(*local_pe) +
        kPeAndCoffBytes + kPe32PlusImageBaseOffset;
    const auto live_image_base = read64(live, image_base_offset);
    const auto local_image_base = read64(local, image_base_offset);
    if (!live_image_base.has_value() || !local_image_base.has_value() ||
        *live_image_base != loaded_module_base) {
        return std::nullopt;
    }
    for (std::size_t index = 0; index < *local_span; ++index) {
        const bool loader_image_base_byte =
            index >= image_base_offset && index < image_base_offset + 8U;
        if (!loader_image_base_byte && live[index] != local[index]) {
            return std::nullopt;
        }
    }
    return PeHeaderEvidenceComparison{
        *local_span,
        image_base_offset,
        *live_image_base,
        *local_image_base};
}

struct KernelExplorerEvidenceSnapshot {
    KernelModule module;
    LocalSymbolModuleProof symbol_proof;
    ResolvedKernelSymbol symbol;
    std::uint64_t read_address{0};
    std::uint32_t requested_bytes{0};
    std::vector<std::uint8_t> read_bytes;
    DisassemblyReport disassembly;
};

class KernelExplorerPanel {
public:
    KernelExplorerPanel() = default;
    ~KernelExplorerPanel();

    KernelExplorerPanel(const KernelExplorerPanel&) = delete;
    KernelExplorerPanel& operator=(const KernelExplorerPanel&) = delete;

    void Attach(IMemoryBackend* backend) noexcept;
    void Draw();
    void Poll();
    void RequestReadCancel() noexcept;
    void CancelAndWait() noexcept;
    [[nodiscard]] bool Busy() const noexcept;
    [[nodiscard]] bool ReadBusy() const noexcept;
    [[nodiscard]] std::optional<std::uint64_t>
    ConsumePageTableNavigation() noexcept;
    [[nodiscard]] std::optional<KernelExplorerEvidenceSnapshot>
    CurrentEvidence() const;

private:
    struct ModuleOutcome {
        std::optional<KernelModuleSnapshot> snapshot;
        Error error;
    };

    struct ReadOutcome {
        std::uint64_t address{0};
        std::uint32_t requested_bytes{0};
        std::vector<std::uint8_t> bytes;
        DisassemblyReport disassembly;
        Error error;
    };

    struct SymbolOutcome {
        std::unique_ptr<LocalSymbolResolver> resolver;
        std::optional<LocalSymbolLoadReport> report;
        Error error;
    };

    struct SymbolResolveOutcome {
        std::optional<ResolvedKernelSymbol> symbol;
        std::string query;
        bool by_name{false};
        std::uint64_t query_address{0};
        Error error;
    };

    void StartModuleRefresh();
    void StartRead();
    void StartSymbolLoad();
    void StartAddressResolve(std::uint64_t address);
    void StartNameResolve();
    void PollJobs();
    void SelectModule(std::size_t index);
    [[nodiscard]] const KernelModule* ModuleForAddress(
        std::uint64_t address) const noexcept;

    IMemoryBackend* backend_{nullptr};
    std::vector<KernelModule> modules_;
    std::vector<std::string> module_diagnostics_;
    std::vector<DisassembledInstruction> instructions_;
    std::vector<std::uint8_t> read_bytes_;
    DisassemblyReport last_disassembly_;
    std::unique_ptr<LocalSymbolResolver> symbols_;
    std::optional<std::uint64_t> page_table_navigation_;

    std::future<ModuleOutcome> module_future_;
    std::future<ReadOutcome> read_future_;
    std::future<SymbolOutcome> symbol_future_;
    std::future<SymbolResolveOutcome> resolve_future_;
    std::atomic_bool module_cancel_{false};
    std::atomic_bool read_cancel_{false};
    std::atomic_bool symbol_cancel_{false};
    std::atomic_size_t module_completed_{0};
    std::atomic_size_t module_total_{0};
    std::atomic_size_t symbol_completed_{0};
    std::atomic_size_t symbol_total_{0};
    std::atomic_uint32_t read_progress_{0};

    std::array<char, 64> address_{};
    std::array<char, 256> module_filter_{};
    std::array<char, 2048> symbol_path_{};
    std::array<char, 512> symbol_name_{};
    int byte_count_{4096};
    int selected_module_{-1};
    std::uint64_t last_read_address_{0};
    std::uint32_t last_read_requested_{0};
    std::string module_status_;
    std::string read_status_;
    std::string symbol_status_;
    std::string resolved_symbol_;
    std::string resolve_status_;
    std::optional<std::uint64_t> resolved_address_;
    std::optional<ResolvedKernelSymbol> resolved_symbol_evidence_;
    std::optional<std::uint64_t> resolved_query_address_;
};

}  // namespace kdbg
