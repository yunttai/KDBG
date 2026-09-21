#pragma once

#include "core/common/Result.h"
#include "core/kernel/KernelModule.h"

#include <cstdint>
#include <atomic>
#include <filesystem>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace kdbg {

struct LocalSymbolLoadReport {
    std::size_t loaded_modules{0};
    std::size_t failed_modules{0};
    std::vector<std::string> diagnostics;
};

struct ResolvedKernelSymbol {
    std::string name;
    std::uint64_t address{0};
    std::uint64_t displacement{0};
};

struct LocalSymbolLoadControl {
    std::atomic_bool* cancel_requested{nullptr};
    std::atomic_size_t* completed{nullptr};
    std::atomic_size_t* total{nullptr};
};

struct LocalSymbolModuleProof {
    std::uint64_t module_base{0};
    std::uint32_t module_size{0};
    std::string module_name;
    std::filesystem::path image_path;
    std::string image_sha256;
    std::string image_codeview_pdb_basename;
    std::string image_codeview_guid;
    std::uint32_t image_codeview_age{0};
    // Canonical local provenance used to hash the exact PDB accepted by
    // DbgHelp. Evidence exporters should publish only the basename/hash.
    std::filesystem::path loaded_pdb_path;
    std::string loaded_pdb_basename;
    std::string loaded_pdb_sha256;
    std::string loaded_pdb_guid;
    std::uint32_t loaded_pdb_age{0};
    bool identity_match{false};

    [[nodiscard]] bool Contains(std::uint64_t address) const noexcept {
        return module_size != 0 && address >= module_base &&
            address - module_base < module_size;
    }
};

class LocalSymbolResolver {
public:
    LocalSymbolResolver();
    ~LocalSymbolResolver();

    LocalSymbolResolver(const LocalSymbolResolver&) = delete;
    LocalSymbolResolver& operator=(const LocalSymbolResolver&) = delete;

    Result<LocalSymbolLoadReport> Configure(
        std::string_view local_path,
        const std::vector<KernelModule>& modules,
        const LocalSymbolLoadControl& control = {});
    Result<ResolvedKernelSymbol> Resolve(std::uint64_t address) const;
    Result<ResolvedKernelSymbol> ResolveName(std::string_view name) const;
    Result<LocalSymbolModuleProof> ProofForAddress(
        std::uint64_t address) const;
    void Reset() noexcept;
    [[nodiscard]] bool Ready() const noexcept;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace kdbg
