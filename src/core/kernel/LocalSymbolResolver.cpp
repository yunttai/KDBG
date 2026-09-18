#include "core/kernel/LocalSymbolResolver.h"

#include <algorithm>
#include <array>
#include <bit>
#include <cstdio>
#include <cwctype>
#include <filesystem>
#include <limits>
#include <mutex>
#include <set>
#include <sstream>
#include <vector>

#ifdef _WIN32
#include <Windows.h>
#include <DbgHelp.h>
#include <Wincrypt.h>
#endif

namespace kdbg {
namespace {

#ifdef _WIN32
std::wstring Utf8ToWide(std::string_view value) {
    if (value.empty()) return {};
    const int required = MultiByteToWideChar(
        CP_UTF8, MB_ERR_INVALID_CHARS,
        value.data(), static_cast<int>(value.size()), nullptr, 0);
    if (required <= 0) return {};
    std::wstring output(static_cast<std::size_t>(required), L'\0');
    if (MultiByteToWideChar(
            CP_UTF8, MB_ERR_INVALID_CHARS,
            value.data(), static_cast<int>(value.size()),
            output.data(), required) != required) {
        return {};
    }
    return output;
}

std::string WideToUtf8(std::wstring_view value) {
    if (value.empty()) return {};
    if (value.size() > static_cast<std::size_t>(
            std::numeric_limits<int>::max())) {
        return {};
    }
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

std::wstring Lower(std::wstring value) {
    std::transform(value.begin(), value.end(), value.begin(),
        [](wchar_t ch) { return static_cast<wchar_t>(std::towlower(ch)); });
    return value;
}

std::recursive_mutex& DbgHelpMutex() {
    static std::recursive_mutex mutex;
    return mutex;
}

std::string GuidString(const GUID& guid) {
    std::array<char, 37> text{};
    const int written = std::snprintf(
        text.data(), text.size(),
        "%08lx-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
        static_cast<unsigned long>(guid.Data1),
        static_cast<unsigned>(guid.Data2),
        static_cast<unsigned>(guid.Data3),
        static_cast<unsigned>(guid.Data4[0]),
        static_cast<unsigned>(guid.Data4[1]),
        static_cast<unsigned>(guid.Data4[2]),
        static_cast<unsigned>(guid.Data4[3]),
        static_cast<unsigned>(guid.Data4[4]),
        static_cast<unsigned>(guid.Data4[5]),
        static_cast<unsigned>(guid.Data4[6]),
        static_cast<unsigned>(guid.Data4[7]));
    return written == 36 ? std::string(text.data(), 36U) : std::string{};
}

std::string AsciiLower(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(),
        [](unsigned char ch) {
            return static_cast<char>(std::tolower(ch));
        });
    return value;
}

Result<std::string> FileSha256(const std::filesystem::path& path) {
    HANDLE file = CreateFileW(
        path.c_str(), GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        return Result<std::string>::Failure(MakeError(
            ErrorCode::IoFailure,
            "Unable to open the local module image for SHA-256",
            "LocalSymbolResolver::Configure.FileSha256",
            GetLastError()));
    }
    HCRYPTPROV provider = 0;
    HCRYPTHASH hash = 0;
    auto cleanup = [&]() {
        if (hash != 0) CryptDestroyHash(hash);
        if (provider != 0) CryptReleaseContext(provider, 0);
        CloseHandle(file);
    };
    if (CryptAcquireContextW(
            &provider, nullptr, nullptr, PROV_RSA_AES,
            CRYPT_VERIFYCONTEXT) == FALSE ||
        CryptCreateHash(provider, CALG_SHA_256, 0, 0, &hash) == FALSE) {
        const auto native = GetLastError();
        cleanup();
        return Result<std::string>::Failure(MakeError(
            ErrorCode::IoFailure,
            "Unable to initialize SHA-256 for the local module image",
            "LocalSymbolResolver::Configure.FileSha256",
            native));
    }
    std::vector<BYTE> buffer(64U * 1024U);
    for (;;) {
        DWORD completed = 0;
        if (ReadFile(
                file, buffer.data(), static_cast<DWORD>(buffer.size()),
                &completed, nullptr) == FALSE) {
            const auto native = GetLastError();
            cleanup();
            return Result<std::string>::Failure(MakeError(
                ErrorCode::IoFailure,
                "Unable to read the local module image for SHA-256",
                "LocalSymbolResolver::Configure.FileSha256",
                native));
        }
        if (completed == 0) break;
        if (CryptHashData(hash, buffer.data(), completed, 0) == FALSE) {
            const auto native = GetLastError();
            cleanup();
            return Result<std::string>::Failure(MakeError(
                ErrorCode::IoFailure,
                "Unable to update the local module SHA-256",
                "LocalSymbolResolver::Configure.FileSha256",
                native));
        }
    }
    std::array<BYTE, 32> digest{};
    DWORD digest_size = static_cast<DWORD>(digest.size());
    if (CryptGetHashParam(
            hash, HP_HASHVAL, digest.data(), &digest_size, 0) == FALSE ||
        digest_size != digest.size()) {
        const auto native = GetLastError();
        cleanup();
        return Result<std::string>::Failure(MakeError(
            ErrorCode::IoFailure,
            "Unable to finish the local module SHA-256",
            "LocalSymbolResolver::Configure.FileSha256",
            native));
    }
    cleanup();
    constexpr char digits[] = "0123456789abcdef";
    std::string output(digest.size() * 2U, '0');
    for (std::size_t index = 0; index < digest.size(); ++index) {
        output[index * 2U] = digits[digest[index] >> 4U];
        output[index * 2U + 1U] = digits[digest[index] & 0x0FU];
    }
    return Result<std::string>::Success(std::move(output));
}

Result<LocalSymbolModuleProof> CaptureModuleProof(
    const KernelModule& module,
    const IMAGEHLP_MODULE64& loaded) {
    SYMSRV_INDEX_INFOW image_index{};
    image_index.sizeofstruct = sizeof(image_index);
    if (SymSrvGetFileIndexInfoW(
            module.image_path.c_str(), &image_index, 0) == FALSE) {
        return Result<LocalSymbolModuleProof>::Failure(MakeError(
            ErrorCode::ParseError,
            "Unable to read the PE CodeView identity from the local module image",
            "LocalSymbolResolver::Configure.SymSrvGetFileIndexInfoW",
            GetLastError()));
    }
    const auto sha256 = FileSha256(module.image_path);
    if (!sha256) {
        return Result<LocalSymbolModuleProof>::Failure(sha256.GetError());
    }
    LocalSymbolModuleProof proof{};
    proof.module_base = module.base;
    proof.module_size = module.image_size;
    proof.module_name = module.name;
    proof.image_path = module.image_path;
    proof.image_sha256 = sha256.Value();
    proof.image_codeview_pdb_basename = WideToUtf8(
        std::filesystem::path(image_index.pdbfile).filename().native());
    proof.image_codeview_guid = GuidString(image_index.guid);
    proof.image_codeview_age = image_index.age;
    const std::filesystem::path reported_pdb(loaded.LoadedPdbName);
    std::error_code path_error;
    proof.loaded_pdb_path = std::filesystem::canonical(
        reported_pdb, path_error);
    if (path_error || proof.loaded_pdb_path.empty() ||
        !proof.loaded_pdb_path.is_absolute()) {
        return Result<LocalSymbolModuleProof>::Failure(MakeError(
            ErrorCode::IoFailure,
            "DbgHelp did not expose a canonical loaded PDB path",
            "LocalSymbolResolver::Configure.CaptureModuleProof",
            static_cast<std::uint64_t>(path_error.value())));
    }
    proof.loaded_pdb_basename =
        proof.loaded_pdb_path.filename().string();
    const auto pdb_sha256 = FileSha256(proof.loaded_pdb_path);
    if (!pdb_sha256) {
        return Result<LocalSymbolModuleProof>::Failure(
            pdb_sha256.GetError());
    }
    proof.loaded_pdb_sha256 = pdb_sha256.Value();
    proof.loaded_pdb_guid = GuidString(loaded.PdbSig70);
    proof.loaded_pdb_age = loaded.PdbAge;
    proof.identity_match =
        !proof.image_codeview_pdb_basename.empty() &&
        !proof.loaded_pdb_basename.empty() &&
        !proof.image_codeview_guid.empty() &&
        proof.image_codeview_guid == proof.loaded_pdb_guid &&
        proof.image_codeview_age == proof.loaded_pdb_age &&
        AsciiLower(proof.image_codeview_pdb_basename) ==
            AsciiLower(proof.loaded_pdb_basename) &&
        loaded.PdbUnmatched == FALSE;
    if (!proof.identity_match) {
        return Result<LocalSymbolModuleProof>::Failure(MakeError(
            ErrorCode::VerificationMismatch,
            "Loaded PDB basename/GUID/age does not match the PE CodeView identity",
            "LocalSymbolResolver::Configure.CaptureModuleProof"));
    }
    return Result<LocalSymbolModuleProof>::Success(std::move(proof));
}
#endif

}  // namespace

struct LocalSymbolResolver::Impl {
#ifdef _WIN32
    HANDLE session{nullptr};
#endif
    bool ready{false};
    std::vector<LocalSymbolModuleProof> proofs;
};

LocalSymbolResolver::LocalSymbolResolver() : impl_(std::make_unique<Impl>()) {}

LocalSymbolResolver::~LocalSymbolResolver() {
    Reset();
}

void LocalSymbolResolver::Reset() noexcept {
#ifdef _WIN32
    const std::lock_guard lock(DbgHelpMutex());
    if (impl_->ready && impl_->session != nullptr) {
        static_cast<void>(SymCleanup(impl_->session));
    }
    impl_->session = nullptr;
#endif
    impl_->ready = false;
    impl_->proofs.clear();
}

bool LocalSymbolResolver::Ready() const noexcept {
    return impl_->ready;
}

Result<LocalSymbolLoadReport> LocalSymbolResolver::Configure(
    std::string_view local_path,
    const std::vector<KernelModule>& modules,
    const LocalSymbolLoadControl& control) {
#ifdef _WIN32
    // DbgHelp is process-global and single-threaded. Keep every Sym* call for
    // every resolver instance under the same lock, including Reset().
    const std::lock_guard lock(DbgHelpMutex());
#endif
    Reset();
    if (control.completed != nullptr) {
        control.completed->store(0, std::memory_order_relaxed);
    }
    if (control.total != nullptr) {
        control.total->store(modules.size(), std::memory_order_relaxed);
    }
    if (control.cancel_requested != nullptr &&
        control.cancel_requested->load(std::memory_order_relaxed)) {
        return Result<LocalSymbolLoadReport>::Failure(MakeError(
            ErrorCode::Cancelled,
            "Local symbol loading was cancelled before initialization",
            "LocalSymbolResolver::Configure"));
    }
    if (modules.empty()) {
        return Result<LocalSymbolLoadReport>::Failure(MakeError(
            ErrorCode::InvalidArgument,
            "Enumerate kernel modules before loading symbols",
            "LocalSymbolResolver::Configure"));
    }
    const auto parsed = ParseLocalSymbolPath(local_path);
    if (!parsed) {
        return Result<LocalSymbolLoadReport>::Failure(parsed.GetError());
    }
#ifdef _WIN32
    std::set<std::filesystem::path> directories;
    for (const auto& entry : parsed.Value()) {
        if (!entry.is_absolute()) {
            return Result<LocalSymbolLoadReport>::Failure(MakeError(
                ErrorCode::InvalidArgument,
                "Every local symbol path entry must be absolute",
                "LocalSymbolResolver::Configure"));
        }
        std::error_code error;
        if (std::filesystem::is_directory(entry, error)) {
            directories.insert(entry.lexically_normal());
        } else if (!error && std::filesystem::is_regular_file(entry, error) &&
                   Lower(entry.extension().native()) == L".pdb") {
            // The file form is a convenience for selecting its directory.
            // Never substitute a same-stem PDB for the module image: DbgHelp
            // must match the PDB signature recorded by the local PE image.
            directories.insert(entry.parent_path().lexically_normal());
        } else {
            return Result<LocalSymbolLoadReport>::Failure(MakeError(
                ErrorCode::NotFound,
                "Local symbol entry does not exist or is not a directory/PDB file",
                "LocalSymbolResolver::Configure",
                static_cast<std::uint64_t>(
                    static_cast<std::uint32_t>(error.value()))));
        }
    }
    std::wstring search_path;
    for (const auto& directory : directories) {
        if (!search_path.empty()) search_path.push_back(L';');
        search_path.append(directory.native());
    }
    if (search_path.empty()) {
        return Result<LocalSymbolLoadReport>::Failure(MakeError(
            ErrorCode::InvalidArgument,
            "No local symbol directory was configured",
            "LocalSymbolResolver::Configure"));
    }

    impl_->session = reinterpret_cast<HANDLE>(this);
    constexpr DWORD kDeferredLoads = static_cast<DWORD>(SYMOPT_DEFERRED_LOADS);
    SymSetOptions(
        (SymGetOptions() & ~kDeferredLoads) | SYMOPT_UNDNAME |
        SYMOPT_LOAD_LINES | SYMOPT_FAIL_CRITICAL_ERRORS |
        SYMOPT_NO_PROMPTS | SYMOPT_EXACT_SYMBOLS);
    if (SymInitializeW(impl_->session, search_path.c_str(), FALSE) == FALSE) {
        const auto native = GetLastError();
        impl_->session = nullptr;
        return Result<LocalSymbolLoadReport>::Failure(MakeError(
            ErrorCode::IoFailure,
            "DbgHelp could not initialize the local symbol session",
            "LocalSymbolResolver::Configure.SymInitializeW",
            native));
    }
    impl_->ready = true;

    using LoadModuleFunction = DWORD64 (WINAPI*)(
        HANDLE, HANDLE, PCWSTR, PCWSTR, DWORD64, DWORD, PMODLOAD_DATA, DWORD);
    const HMODULE dbghelp = GetModuleHandleW(L"dbghelp.dll");
    const auto load_module = dbghelp == nullptr
        ? nullptr
        : std::bit_cast<LoadModuleFunction>(
            GetProcAddress(dbghelp, "SymLoadModuleExW"));
    if (load_module == nullptr) {
        const auto native = GetLastError();
        Reset();
        return Result<LocalSymbolLoadReport>::Failure(MakeError(
            ErrorCode::NotFound,
            "DbgHelp does not export SymLoadModuleExW",
            "LocalSymbolResolver::Configure.GetProcAddress",
            native));
    }

    LocalSymbolLoadReport report;
    report.diagnostics.reserve(modules.size());
    for (std::size_t index = 0; index < modules.size(); ++index) {
        if (control.cancel_requested != nullptr &&
            control.cancel_requested->load(std::memory_order_relaxed)) {
            Reset();
            return Result<LocalSymbolLoadReport>::Failure(MakeError(
                ErrorCode::Cancelled,
                "Local symbol loading was cancelled",
                "LocalSymbolResolver::Configure",
                0,
                modules.size(),
                index));
        }
        const auto& module = modules[index];
        const std::filesystem::path& image = module.image_path;
        if (image.empty() || module.image_size == 0) {
            ++report.failed_modules;
            report.diagnostics.push_back(
                module.name +
                ": a verified local PE image is unavailable; symbols skipped");
            if (control.completed != nullptr) {
                control.completed->store(index + 1U, std::memory_order_relaxed);
            }
            continue;
        }
        const auto module_name = Utf8ToWide(module.name);
        SetLastError(ERROR_SUCCESS);
        const DWORD64 loaded = load_module(
            impl_->session,
            nullptr,
            image.empty() ? nullptr : image.c_str(),
            module_name.empty() ? nullptr : module_name.c_str(),
            module.base,
            module.image_size,
            nullptr,
            0);
        if (loaded == 0) {
            ++report.failed_modules;
            const auto native = GetLastError();
            std::ostringstream message;
            message << module.name << ": local symbols unavailable (native="
                    << native << ')';
            report.diagnostics.push_back(message.str());
        } else {
            IMAGEHLP_MODULE64 module_info{};
            module_info.SizeOfStruct = sizeof(module_info);
            SetLastError(ERROR_SUCCESS);
            const BOOL described = SymGetModuleInfo64(
                impl_->session,
                loaded,
                &module_info);
            const auto native = GetLastError();
            if (described == FALSE || module_info.SymType != SymPdb) {
                static_cast<void>(SymUnloadModule64(impl_->session, loaded));
                ++report.failed_modules;
                std::ostringstream message;
                message << module.name
                        << ": module registered but an exact PDB was not loaded"
                        << " (sym_type="
                        << (described == FALSE
                                ? -1
                                : static_cast<int>(module_info.SymType))
                        << ", native=" << native << ')';
                report.diagnostics.push_back(message.str());
            } else {
                const auto proof = CaptureModuleProof(module, module_info);
                if (!proof) {
                    static_cast<void>(SymUnloadModule64(
                        impl_->session, loaded));
                    ++report.failed_modules;
                    report.diagnostics.push_back(
                        module.name + ": " + proof.GetError().message);
                } else {
                    impl_->proofs.push_back(proof.Value());
                    ++report.loaded_modules;
                }
            }
        }
        if (control.completed != nullptr) {
            control.completed->store(index + 1U, std::memory_order_relaxed);
        }
    }
    if (control.cancel_requested != nullptr &&
        control.cancel_requested->load(std::memory_order_relaxed)) {
        Reset();
        return Result<LocalSymbolLoadReport>::Failure(MakeError(
            ErrorCode::Cancelled,
            "Local symbol loading was cancelled",
            "LocalSymbolResolver::Configure",
            0,
            modules.size(),
            modules.size()));
    }
    if (report.loaded_modules == 0) {
        Reset();
        return Result<LocalSymbolLoadReport>::Failure(MakeError(
            ErrorCode::NotFound,
            "DbgHelp did not load symbols for any enumerated kernel module",
            "LocalSymbolResolver::Configure",
            0,
            modules.size(),
            report.failed_modules));
    }
    return Result<LocalSymbolLoadReport>::Success(std::move(report));
#else
    (void)local_path;
    (void)modules;
    (void)control;
    return Result<LocalSymbolLoadReport>::Failure(MakeError(
        ErrorCode::Unsupported,
        "Local kernel symbol resolution is available only on Windows",
        "LocalSymbolResolver::Configure"));
#endif
}

Result<ResolvedKernelSymbol> LocalSymbolResolver::Resolve(
    std::uint64_t address) const {
#ifdef _WIN32
    const std::lock_guard lock(DbgHelpMutex());
#endif
    if (!impl_->ready) {
        return Result<ResolvedKernelSymbol>::Failure(MakeError(
            ErrorCode::BackendDisconnected,
            "Local symbol session is not configured",
            "LocalSymbolResolver::Resolve"));
    }
#ifdef _WIN32
    constexpr std::size_t kMaximumSymbolName = 2048;
    std::vector<std::uint8_t> storage(
        sizeof(SYMBOL_INFO) + kMaximumSymbolName);
    auto* symbol = reinterpret_cast<SYMBOL_INFO*>(storage.data());
    symbol->SizeOfStruct = sizeof(SYMBOL_INFO);
    symbol->MaxNameLen = static_cast<ULONG>(kMaximumSymbolName);
    DWORD64 displacement = 0;
    if (SymFromAddr(impl_->session, address, &displacement, symbol) == FALSE) {
        return Result<ResolvedKernelSymbol>::Failure(MakeError(
            ErrorCode::NotFound,
            "No local symbol resolves this kernel address",
            "LocalSymbolResolver::Resolve.SymFromAddr",
            GetLastError()));
    }
    return Result<ResolvedKernelSymbol>::Success(ResolvedKernelSymbol{
        std::string(symbol->Name, symbol->NameLen),
        symbol->Address,
        displacement});
#else
    (void)address;
    return Result<ResolvedKernelSymbol>::Failure(MakeError(
        ErrorCode::Unsupported,
        "Local kernel symbol resolution is available only on Windows",
        "LocalSymbolResolver::Resolve"));
#endif
}

Result<ResolvedKernelSymbol> LocalSymbolResolver::ResolveName(
    std::string_view name) const {
#ifdef _WIN32
    const std::lock_guard lock(DbgHelpMutex());
#endif
    if (!impl_->ready) {
        return Result<ResolvedKernelSymbol>::Failure(MakeError(
            ErrorCode::BackendDisconnected,
            "Local symbol session is not configured",
            "LocalSymbolResolver::ResolveName"));
    }
    constexpr std::size_t kMaximumSymbolName = 2048;
    if (name.empty() || name.size() > kMaximumSymbolName ||
        name.find('\0') != std::string_view::npos) {
        return Result<ResolvedKernelSymbol>::Failure(MakeError(
            ErrorCode::InvalidArgument,
            "Symbol name is empty, oversized, or contains an embedded NUL",
            "LocalSymbolResolver::ResolveName",
            0,
            kMaximumSymbolName,
            name.size()));
    }
#ifdef _WIN32
    std::vector<std::uint8_t> storage(
        sizeof(SYMBOL_INFO) + kMaximumSymbolName);
    auto* symbol = reinterpret_cast<SYMBOL_INFO*>(storage.data());
    symbol->SizeOfStruct = sizeof(SYMBOL_INFO);
    symbol->MaxNameLen = static_cast<ULONG>(kMaximumSymbolName);
    const std::string query(name);
    if (SymFromName(impl_->session, query.c_str(), symbol) == FALSE) {
        return Result<ResolvedKernelSymbol>::Failure(MakeError(
            ErrorCode::NotFound,
            "No exact local symbol matches this name",
            "LocalSymbolResolver::ResolveName.SymFromName",
            GetLastError()));
    }
    return Result<ResolvedKernelSymbol>::Success(ResolvedKernelSymbol{
        std::string(symbol->Name, symbol->NameLen),
        symbol->Address,
        0});
#else
    (void)name;
    return Result<ResolvedKernelSymbol>::Failure(MakeError(
        ErrorCode::Unsupported,
        "Local kernel symbol resolution is available only on Windows",
        "LocalSymbolResolver::ResolveName"));
#endif
}

Result<LocalSymbolModuleProof> LocalSymbolResolver::ProofForAddress(
    std::uint64_t address) const {
#ifdef _WIN32
    const std::lock_guard lock(DbgHelpMutex());
#endif
    if (!impl_->ready) {
        return Result<LocalSymbolModuleProof>::Failure(MakeError(
            ErrorCode::BackendDisconnected,
            "Local symbol session is not configured",
            "LocalSymbolResolver::ProofForAddress"));
    }
    const auto proof = std::find_if(
        impl_->proofs.begin(), impl_->proofs.end(),
        [address](const LocalSymbolModuleProof& item) {
            return item.Contains(address);
        });
    if (proof == impl_->proofs.end()) {
        return Result<LocalSymbolModuleProof>::Failure(MakeError(
            ErrorCode::NotFound,
            "No identity-verified local PDB covers this kernel address",
            "LocalSymbolResolver::ProofForAddress"));
    }
    return Result<LocalSymbolModuleProof>::Success(*proof);
}

}  // namespace kdbg
