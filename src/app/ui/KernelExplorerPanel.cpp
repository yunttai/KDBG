#include "app/ui/KernelExplorerPanel.h"

#include "app/ui/Localization.h"

#include <imgui.h>

#include <algorithm>
#include <cctype>
#include <charconv>
#include <chrono>
#include <cstdio>
#include <exception>
#include <iomanip>
#include <limits>
#include <sstream>
#include <string_view>

namespace kdbg {

using ui::UiLabel;
using ui::UiText;

namespace {

bool ParseAddress(const char* input, std::uint64_t& value) {
    std::string_view text(input == nullptr ? "" : input);
    int base = 10;
    if (text.starts_with("0x") || text.starts_with("0X")) {
        text.remove_prefix(2);
        base = 16;
    }
    if (text.empty()) return false;
    const auto result = std::from_chars(
        text.data(), text.data() + text.size(), value, base);
    return result.ec == std::errc{} && result.ptr == text.data() + text.size();
}

std::string ErrorText(const Error& error) {
    std::ostringstream stream;
    stream << error.message;
    if (!error.operation.empty()) stream << " [" << error.operation << ']';
    if (error.native_code != 0) stream << " native=" << error.native_code;
    if (error.requested != 0 || error.completed != 0) {
        stream << " requested=" << error.requested
               << " completed=" << error.completed;
    }
    return stream.str();
}

std::string HexBytes(const std::vector<std::uint8_t>& bytes) {
    std::ostringstream stream;
    for (std::size_t index = 0; index < bytes.size(); ++index) {
        if (index != 0) stream << ' ';
        stream << std::uppercase << std::hex << std::setw(2)
               << std::setfill('0') << static_cast<unsigned>(bytes[index]);
    }
    return stream.str();
}

std::string Lower(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(),
        [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
    return value;
}

}  // namespace

KernelExplorerPanel::~KernelExplorerPanel() {
    CancelAndWait();
}

void KernelExplorerPanel::Attach(IMemoryBackend* backend) noexcept {
    backend_ = backend;
}

bool KernelExplorerPanel::Busy() const noexcept {
    return module_future_.valid() || read_future_.valid() ||
        symbol_future_.valid() || resolve_future_.valid();
}

bool KernelExplorerPanel::ReadBusy() const noexcept {
    return read_future_.valid();
}

std::optional<KernelExplorerEvidenceSnapshot>
KernelExplorerPanel::CurrentEvidence() const {
    if (Busy() || symbols_ == nullptr || !symbols_->Ready() ||
        read_bytes_.empty() || last_read_requested_ == 0 ||
        read_bytes_.size() != last_read_requested_ ||
        last_disassembly_.read_bytes != read_bytes_.size() ||
        last_disassembly_.requested_bytes != last_read_requested_ ||
        last_disassembly_.consumed_bytes != read_bytes_.size() ||
        last_disassembly_.truncated ||
        last_disassembly_.instructions.empty() ||
        !resolved_symbol_evidence_.has_value() ||
        !resolved_query_address_.has_value() ||
        *resolved_query_address_ != last_read_address_ ||
        resolved_symbol_evidence_->address >
            std::numeric_limits<std::uint64_t>::max() -
                resolved_symbol_evidence_->displacement ||
        resolved_symbol_evidence_->address +
                resolved_symbol_evidence_->displacement != last_read_address_) {
        return std::nullopt;
    }
    const auto* module = ModuleForAddress(last_read_address_);
    if (module == nullptr ||
        last_read_address_ >
            std::numeric_limits<std::uint64_t>::max() -
                (read_bytes_.size() - 1U) ||
        !module->Contains(last_read_address_ + read_bytes_.size() - 1U)) {
        return std::nullopt;
    }
    const auto proof = symbols_->ProofForAddress(last_read_address_);
    if (!proof || !proof.Value().identity_match ||
        proof.Value().module_base != module->base ||
        proof.Value().module_size != module->image_size ||
        !proof.Value().Contains(last_read_address_ + read_bytes_.size() - 1U)) {
        return std::nullopt;
    }
    return KernelExplorerEvidenceSnapshot{
        *module,
        proof.Value(),
        *resolved_symbol_evidence_,
        last_read_address_,
        last_read_requested_,
        read_bytes_,
        last_disassembly_};
}

void KernelExplorerPanel::Poll() {
    PollJobs();
}

void KernelExplorerPanel::RequestReadCancel() noexcept {
    read_cancel_.store(true, std::memory_order_relaxed);
}

std::optional<std::uint64_t>
KernelExplorerPanel::ConsumePageTableNavigation() noexcept {
    auto navigation = page_table_navigation_;
    page_table_navigation_.reset();
    return navigation;
}

void KernelExplorerPanel::CancelAndWait() noexcept {
    module_cancel_.store(true, std::memory_order_relaxed);
    RequestReadCancel();
    symbol_cancel_.store(true, std::memory_order_relaxed);
    try {
        if (module_future_.valid()) static_cast<void>(module_future_.get());
        if (read_future_.valid()) static_cast<void>(read_future_.get());
        if (symbol_future_.valid()) static_cast<void>(symbol_future_.get());
        if (resolve_future_.valid()) static_cast<void>(resolve_future_.get());
    } catch (...) {
        // Destruction/reconnect continues after a worker exception.
    }
}

void KernelExplorerPanel::StartModuleRefresh() {
    if (module_future_.valid()) return;
    if (symbol_future_.valid() || resolve_future_.valid()) {
        module_status_ = UiText(
            "Finish the current local-symbol operation before refreshing modules.");
        return;
    }
    module_cancel_.store(false, std::memory_order_relaxed);
    module_completed_.store(0, std::memory_order_relaxed);
    module_total_.store(0, std::memory_order_relaxed);
    module_status_ = UiText("Enumerating loaded x64 kernel modules...");
    const bool la57 = backend_ != nullptr && backend_->Info().supports_la57;
    module_future_ = std::async(std::launch::async, [this, la57] {
        ModuleOutcome outcome;
        try {
            const auto result = EnumerateKernelModules(
                KernelModuleEnumerationControl{
                    &module_cancel_, &module_completed_, &module_total_, la57});
            if (result) outcome.snapshot = result.Value();
            else outcome.error = result.GetError();
        } catch (const std::exception& exception) {
            outcome.error = MakeError(
                ErrorCode::InternalInvariant,
                "Kernel module worker failed: " + std::string(exception.what()),
                "KernelExplorerPanel::StartModuleRefresh");
        } catch (...) {
            outcome.error = MakeError(
                ErrorCode::InternalInvariant,
                "Kernel module worker failed with an unknown exception",
                "KernelExplorerPanel::StartModuleRefresh");
        }
        return outcome;
    });
}

void KernelExplorerPanel::StartRead() {
    if (read_future_.valid()) return;
    if (backend_ == nullptr || !backend_->Info().connected) {
        read_status_ = UiText(
            "Kernel virtual read unavailable: KDBG backend is disconnected.");
        return;
    }
    std::uint64_t address = 0;
    const bool la57 = backend_->Info().supports_la57;
    if (!ParseAddress(address_.data(), address) ||
        !IsCanonicalX64KernelAddress(address, la57)) {
        read_status_ = UiText(
            "Enter a canonical x64 kernel virtual address.");
        return;
    }
    byte_count_ = std::clamp(
        byte_count_, 16, static_cast<int>(kMaximumKernelReadBytes));
    const auto length = static_cast<std::uint32_t>(byte_count_);
    if (address > std::numeric_limits<std::uint64_t>::max() - (length - 1U)) {
        read_status_ = UiText(
            "Kernel virtual read range overflows 64-bit address space.");
        return;
    }

    read_cancel_.store(false, std::memory_order_relaxed);
    read_progress_.store(0, std::memory_order_relaxed);
    read_status_ = UiText("Reading kernel virtual memory...");
    IMemoryBackend* const backend = backend_;
    read_future_ = std::async(std::launch::async, [this, backend, address, length] {
        ReadOutcome outcome;
        outcome.address = address;
        outcome.requested_bytes = length;
        try {
            if (read_cancel_.load(std::memory_order_relaxed)) {
                outcome.error = MakeError(
                    ErrorCode::Cancelled, "Kernel read was cancelled",
                    "KernelExplorerPanel::StartRead");
                return outcome;
            }
            const auto bytes = backend->ReadKernelVirtual(address, length);
            read_progress_.store(1, std::memory_order_relaxed);
            if (!bytes) {
                outcome.error = bytes.GetError();
                return outcome;
            }
            if (read_cancel_.load(std::memory_order_relaxed)) {
                outcome.error = MakeError(
                    ErrorCode::Cancelled, "Kernel read result was discarded",
                    "KernelExplorerPanel::StartRead");
                return outcome;
            }
            outcome.bytes = bytes.Value();
            if (outcome.bytes.size() != length) {
                outcome.error = MakeError(
                    ErrorCode::ShortRead,
                    "Kernel virtual read did not complete the exact requested transfer",
                    "KernelExplorerPanel::StartRead",
                    0,
                    length,
                    outcome.bytes.size());
                return outcome;
            }
            ZydisDisassembler disassembler;
            const auto decoded = disassembler.DecodeBytesDetailed(
                outcome.bytes, address, true, 4096);
            read_progress_.store(2, std::memory_order_relaxed);
            if (!decoded) outcome.error = decoded.GetError();
            else outcome.disassembly = decoded.Value();
        } catch (const std::exception& exception) {
            outcome.error = MakeError(
                ErrorCode::InternalInvariant,
                "Kernel read worker failed: " + std::string(exception.what()),
                "KernelExplorerPanel::StartRead");
        } catch (...) {
            outcome.error = MakeError(
                ErrorCode::InternalInvariant,
                "Kernel read worker failed with an unknown exception",
                "KernelExplorerPanel::StartRead");
        }
        return outcome;
    });
}

void KernelExplorerPanel::StartSymbolLoad() {
    if (symbol_future_.valid()) return;
    if (module_future_.valid() || resolve_future_.valid()) {
        symbol_status_ = UiText(
            "Finish the current module refresh or symbol lookup before loading local symbols.");
        return;
    }
    if (modules_.empty()) {
        symbol_status_ = UiText(
            "Enumerate modules before loading local symbols.");
        return;
    }
    const std::string path(symbol_path_.data());
    const auto modules = modules_;
    symbol_cancel_.store(false, std::memory_order_relaxed);
    symbol_completed_.store(0, std::memory_order_relaxed);
    symbol_total_.store(modules.size(), std::memory_order_relaxed);
    symbol_status_ = UiText(
        "Loading explicitly configured local symbols...");
    symbol_future_ = std::async(std::launch::async, [this, path, modules] {
        SymbolOutcome outcome;
        try {
            auto resolver = std::make_unique<LocalSymbolResolver>();
            const auto configured = resolver->Configure(
                path,
                modules,
                LocalSymbolLoadControl{
                    &symbol_cancel_, &symbol_completed_, &symbol_total_});
            if (!configured) {
                outcome.error = configured.GetError();
                return outcome;
            }
            outcome.report = configured.Value();
            outcome.resolver = std::move(resolver);
        } catch (const std::exception& exception) {
            outcome.error = MakeError(
                ErrorCode::InternalInvariant,
                "Local symbol worker failed: " + std::string(exception.what()),
                "KernelExplorerPanel::StartSymbolLoad");
        } catch (...) {
            outcome.error = MakeError(
                ErrorCode::InternalInvariant,
                "Local symbol worker failed with an unknown exception",
                "KernelExplorerPanel::StartSymbolLoad");
        }
        return outcome;
    });
}

void KernelExplorerPanel::StartAddressResolve(std::uint64_t address) {
    if (resolve_future_.valid() || symbol_future_.valid() ||
        module_future_.valid()) {
        resolve_status_ = UiText(
            "Finish the current module or symbol operation before resolving an address.");
        return;
    }
    if (symbols_ == nullptr || !symbols_->Ready()) {
        resolve_status_ = UiText(
            "Load exact-signature local symbols before resolving an address.");
        return;
    }
    LocalSymbolResolver* const resolver = symbols_.get();
    resolve_status_ = UiText(
        "Resolving address through the local symbol session...");
    resolve_future_ = std::async(std::launch::async, [resolver, address] {
        SymbolResolveOutcome outcome;
        outcome.query_address = address;
        outcome.query = "0x";
        std::ostringstream value;
        value << std::hex << address;
        outcome.query += value.str();
        try {
            const auto resolved = resolver->Resolve(address);
            if (resolved) outcome.symbol = resolved.Value();
            else outcome.error = resolved.GetError();
        } catch (const std::exception& exception) {
            outcome.error = MakeError(
                ErrorCode::InternalInvariant,
                "Address-to-symbol worker failed: " + std::string(exception.what()),
                "KernelExplorerPanel::StartAddressResolve");
        } catch (...) {
            outcome.error = MakeError(
                ErrorCode::InternalInvariant,
                "Address-to-symbol worker failed with an unknown exception",
                "KernelExplorerPanel::StartAddressResolve");
        }
        return outcome;
    });
}

void KernelExplorerPanel::StartNameResolve() {
    if (resolve_future_.valid() || symbol_future_.valid() ||
        module_future_.valid()) {
        resolve_status_ = UiText(
            "Finish the current module or symbol operation before resolving a name.");
        return;
    }
    if (symbols_ == nullptr || !symbols_->Ready()) {
        resolve_status_ = UiText(
            "Load exact-signature local symbols before resolving a name.");
        return;
    }
    const std::string query(symbol_name_.data());
    if (query.empty()) {
        resolve_status_ = UiText(
            "Enter a symbol name such as nt!KeBugCheckEx.");
        return;
    }
    LocalSymbolResolver* const resolver = symbols_.get();
    resolve_status_ = UiText(
        "Resolving symbol name through the local symbol session...");
    resolve_future_ = std::async(std::launch::async, [resolver, query] {
        SymbolResolveOutcome outcome;
        outcome.query = query;
        outcome.by_name = true;
        try {
            const auto resolved = resolver->ResolveName(query);
            if (resolved) outcome.symbol = resolved.Value();
            else outcome.error = resolved.GetError();
        } catch (const std::exception& exception) {
            outcome.error = MakeError(
                ErrorCode::InternalInvariant,
                "Name-to-address worker failed: " + std::string(exception.what()),
                "KernelExplorerPanel::StartNameResolve");
        } catch (...) {
            outcome.error = MakeError(
                ErrorCode::InternalInvariant,
                "Name-to-address worker failed with an unknown exception",
                "KernelExplorerPanel::StartNameResolve");
        }
        return outcome;
    });
}

void KernelExplorerPanel::PollJobs() {
    using namespace std::chrono_literals;
    if (module_future_.valid() && module_future_.wait_for(0ms) == std::future_status::ready) {
        const auto outcome = module_future_.get();
        if (!outcome.snapshot.has_value()) {
            module_status_ = ErrorText(outcome.error);
        } else {
            modules_ = outcome.snapshot->modules;
            module_diagnostics_ = outcome.snapshot->diagnostics;
            selected_module_ = -1;
            symbols_.reset();
            resolved_symbol_.clear();
            resolved_address_.reset();
            resolved_symbol_evidence_.reset();
            resolved_query_address_.reset();
            resolve_status_.clear();
            symbol_status_ = UiText(
                "Module catalog changed; reload exact-signature local symbols.");
            char status[192]{};
            std::snprintf(
                status,
                sizeof(status),
                UiText("Enumerated %llu loaded x64 kernel module(s)."),
                static_cast<unsigned long long>(modules_.size()));
            module_status_ = status;
        }
    }
    if (read_future_.valid() && read_future_.wait_for(0ms) == std::future_status::ready) {
        auto outcome = read_future_.get();
        if (outcome.error.code != ErrorCode::None) {
            read_status_ = ErrorText(outcome.error);
            instructions_.clear();
            read_bytes_.clear();
            last_disassembly_ = {};
            last_read_requested_ = 0;
            resolved_symbol_.clear();
            resolved_address_.reset();
            resolved_symbol_evidence_.reset();
            resolved_query_address_.reset();
        } else {
            last_read_address_ = outcome.address;
            last_read_requested_ = outcome.requested_bytes;
            read_bytes_ = std::move(outcome.bytes);
            last_disassembly_ = std::move(outcome.disassembly);
            instructions_ = last_disassembly_.instructions;
            char status[192]{};
            std::snprintf(
                status,
                sizeof(status),
                UiText("Read %llu byte(s); decoded %llu instruction(s)."),
                static_cast<unsigned long long>(read_bytes_.size()),
                static_cast<unsigned long long>(instructions_.size()));
            read_status_ = status;
            resolved_symbol_.clear();
            resolved_address_.reset();
            resolved_symbol_evidence_.reset();
            resolved_query_address_.reset();
            if (symbol_future_.valid() || resolve_future_.valid()) {
                resolve_status_ = UiText(
                    "A local symbol operation is in progress; address resolution is deferred.");
            } else {
                StartAddressResolve(last_read_address_);
            }
        }
    }
    if (symbol_future_.valid() && symbol_future_.wait_for(0ms) == std::future_status::ready) {
        auto outcome = symbol_future_.get();
        if (!outcome.report.has_value()) {
            symbol_status_ = ErrorText(outcome.error);
        } else {
            symbols_ = std::move(outcome.resolver);
            char status[320]{};
            std::snprintf(
                status,
                sizeof(status),
                UiText(
                    "Loaded exact-signature local-image symbols for %llu module(s); "
                    "unavailable for %llu. Live in-memory PE identity is not "
                    "independently attested."),
                static_cast<unsigned long long>(outcome.report->loaded_modules),
                static_cast<unsigned long long>(outcome.report->failed_modules));
            symbol_status_ = status;
            if (last_read_address_ != 0 && !resolve_future_.valid()) {
                StartAddressResolve(last_read_address_);
            }
        }
    }
    if (resolve_future_.valid() &&
        resolve_future_.wait_for(0ms) == std::future_status::ready) {
        auto outcome = resolve_future_.get();
        if (!outcome.symbol.has_value()) {
            resolve_status_ = ErrorText(outcome.error);
            resolved_symbol_.clear();
            resolved_address_.reset();
            resolved_symbol_evidence_.reset();
            resolved_query_address_.reset();
        } else {
            const auto& symbol = *outcome.symbol;
            resolved_symbol_ = symbol.name;
            if (symbol.displacement != 0) {
                std::ostringstream offset;
                offset << "+0x" << std::hex << symbol.displacement;
                resolved_symbol_ += offset.str();
            }
            resolved_address_ = symbol.address;
            resolved_symbol_evidence_ = symbol;
            resolved_query_address_ = outcome.by_name
                ? std::optional<std::uint64_t>{}
                : std::optional<std::uint64_t>{outcome.query_address};
            char status[640]{};
            std::snprintf(
                status,
                sizeof(status),
                outcome.by_name
                    ? UiText(
                        "Resolved local symbol '%s' to an address. Live in-memory "
                        "PE identity remains unverified.")
                    : UiText(
                        "Resolved address %s in the local symbol session. Live "
                        "in-memory PE identity remains unverified."),
                outcome.query.c_str());
            resolve_status_ = status;
            if (outcome.by_name) {
                std::snprintf(
                    address_.data(), address_.size(), "0x%016llX",
                    static_cast<unsigned long long>(symbol.address));
            }
        }
    }
}

void KernelExplorerPanel::SelectModule(std::size_t index) {
    if (index >= modules_.size()) return;
    selected_module_ = static_cast<int>(index);
    std::snprintf(
        address_.data(), address_.size(), "0x%016llX",
        static_cast<unsigned long long>(modules_[index].base));
}

const KernelModule* KernelExplorerPanel::ModuleForAddress(
    std::uint64_t address) const noexcept {
    const auto found = std::find_if(modules_.begin(), modules_.end(),
        [address](const KernelModule& module) { return module.Contains(address); });
    return found == modules_.end() ? nullptr : &*found;
}

void KernelExplorerPanel::Draw() {
    PollJobs();
    const auto info = backend_ == nullptr ? BackendInfo{} : backend_->Info();
    ImGui::TextUnformatted(UiText(
        "Kernel Explorer (read-only inspection)"));
    ImGui::Text(UiText(
        "Memory space: KERNEL VIRTUAL | PID: N/A | Backend: %s"),
        info.name.empty() ? UiText("unavailable") : info.name.c_str());
    ImGui::Text(UiText(
        "Connection: %s | Write controls: not exposed in this panel"),
        info.connected ? "LIVE KDBG" : "DISCONNECTED");
    if (!info.connected) {
        ImGui::TextColored(
            ImVec4(1.0F, 0.60F, 0.25F, 1.0F),
            UiText(
                "Kernel reads are unavailable until the KDBG device is connected."));
    }

    ImGui::SeparatorText(UiText("Loaded kernel modules"));
    ImGui::BeginDisabled(symbol_future_.valid() || resolve_future_.valid());
    if (ImGui::Button(UiLabel(
            "Refresh Modules", "KernelExplorer.RefreshModules").c_str())) {
        StartModuleRefresh();
    }
    ImGui::EndDisabled();
    if (module_future_.valid()) {
        ImGui::SameLine();
        if (ImGui::Button(UiLabel(
                "Cancel Refresh", "KernelExplorer.CancelRefresh").c_str())) {
            module_cancel_.store(true, std::memory_order_relaxed);
        }
        const auto total = module_total_.load(std::memory_order_relaxed);
        const auto completed = module_completed_.load(std::memory_order_relaxed);
        const float fraction = total == 0 ? 0.0F :
            static_cast<float>(completed) / static_cast<float>(total);
        ImGui::ProgressBar(fraction, ImVec2(-1.0F, 0.0F));
    }
    if (!module_status_.empty()) ImGui::TextWrapped("%s", module_status_.c_str());
    ImGui::SetNextItemWidth(-1.0F);
    ImGui::InputTextWithHint(
        "##kernel-module-filter",
        UiText("filter module name or local image path"),
        module_filter_.data(), module_filter_.size());

    if (ImGui::BeginTable(
            "kernel-modules", 5,
            ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
                ImGuiTableFlags_Resizable | ImGuiTableFlags_ScrollY,
            ImVec2(0.0F, 260.0F))) {
        ImGui::TableSetupColumn(
            UiLabel("Module", "Module").c_str(),
            ImGuiTableColumnFlags_WidthFixed, 160.0F);
        ImGui::TableSetupColumn(
            UiLabel("Base", "Base").c_str(),
            ImGuiTableColumnFlags_WidthFixed, 150.0F);
        ImGui::TableSetupColumn(
            UiLabel("Size", "Size").c_str(),
            ImGuiTableColumnFlags_WidthFixed, 90.0F);
        ImGui::TableSetupColumn(
            UiLabel("Timestamp", "Timestamp").c_str(),
            ImGuiTableColumnFlags_WidthFixed, 95.0F);
        ImGui::TableSetupColumn(
            UiLabel("Local image / metadata", "Local image / metadata").c_str());
        ImGui::TableHeadersRow();
        const auto filter = Lower(module_filter_.data());
        std::vector<std::size_t> visible;
        visible.reserve(modules_.size());
        for (std::size_t index = 0; index < modules_.size(); ++index) {
            const auto& module = modules_[index];
            if (filter.empty() || Lower(module.name).find(filter) != std::string::npos ||
                Lower(module.image_path.string()).find(filter) != std::string::npos) {
                visible.push_back(index);
            }
        }
        ImGuiListClipper clipper;
        clipper.Begin(static_cast<int>(visible.size()));
        while (clipper.Step()) {
            for (int row = clipper.DisplayStart; row < clipper.DisplayEnd; ++row) {
                const auto index = visible[static_cast<std::size_t>(row)];
                const auto& module = modules_[index];
                ImGui::TableNextRow();
                ImGui::TableNextColumn();
                ImGui::PushID(static_cast<int>(index));
                if (ImGui::Selectable(
                        module.name.c_str(), selected_module_ == static_cast<int>(index),
                        ImGuiSelectableFlags_SpanAllColumns)) {
                    SelectModule(index);
                }
                ImGui::PopID();
                ImGui::TableNextColumn();
                ImGui::Text("0x%016llX", static_cast<unsigned long long>(module.base));
                ImGui::TableNextColumn();
                ImGui::Text("0x%X", module.image_size);
                ImGui::TableNextColumn();
                ImGui::Text("0x%08X", module.timestamp);
                ImGui::TableNextColumn();
                const auto path = module.image_path.string();
                ImGui::TextWrapped("%s | %s",
                    path.empty() ? UiText("<unavailable>") : path.c_str(),
                    module.metadata_status.c_str());
            }
        }
        ImGui::EndTable();
    }
    if (!module_diagnostics_.empty()) {
        ImGui::TextDisabled(
            UiText("Enumeration diagnostics: %zu"),
            module_diagnostics_.size());
    }

    ImGui::SeparatorText(UiText("Local symbols"));
    ImGui::TextWrapped(UiText(
        "Configure absolute local directories or PDB files separated by ';'. "
        "A PDB entry selects its parent directory; DbgHelp must match the exact "
        "PDB identity recorded in the OS-reported local PE image. Remote "
        "symbol-server syntax is intentionally not used."));
    ImGui::SetNextItemWidth(-1.0F);
    ImGui::InputText(
        UiLabel("Local symbol path", "KernelExplorer.SymbolPath").c_str(),
        symbol_path_.data(), symbol_path_.size());
    const bool symbol_busy =
        symbol_future_.valid() || module_future_.valid() || resolve_future_.valid();
    ImGui::BeginDisabled(symbol_busy);
    if (ImGui::Button(UiLabel(
            "Load Local Symbols", "KernelExplorer.LoadSymbols").c_str())) {
        StartSymbolLoad();
    }
    ImGui::EndDisabled();
    if (symbol_future_.valid()) {
        ImGui::SameLine();
        if (ImGui::Button(UiLabel(
                "Cancel Symbol Load",
                "KernelExplorer.CancelSymbolLoad").c_str())) {
            symbol_cancel_.store(true, std::memory_order_relaxed);
        }
        const auto total = symbol_total_.load(std::memory_order_relaxed);
        const auto completed = symbol_completed_.load(std::memory_order_relaxed);
        const float fraction = total == 0 ? 0.0F :
            static_cast<float>(completed) / static_cast<float>(total);
        ImGui::ProgressBar(fraction, ImVec2(-1.0F, 0.0F));
    }
    if (!symbol_status_.empty()) ImGui::TextWrapped("%s", symbol_status_.c_str());

    ImGui::SetNextItemWidth(-1.0F);
    ImGui::InputTextWithHint(
        "##kernel-symbol-name",
        UiText("symbol name, for example nt!KeBugCheckEx"),
        symbol_name_.data(), symbol_name_.size());
    const bool can_resolve = symbols_ != nullptr && symbols_->Ready() &&
        !resolve_future_.valid() && !symbol_future_.valid() &&
        !module_future_.valid();
    ImGui::BeginDisabled(!can_resolve);
    if (ImGui::Button(UiLabel(
            "Resolve Symbol -> Address",
            "KernelExplorer.ResolveSymbol").c_str())) {
        StartNameResolve();
    }
    ImGui::EndDisabled();
    if (resolve_future_.valid()) {
        ImGui::SameLine();
        ImGui::TextDisabled(UiText("Resolving..."));
    }
    if (!resolve_status_.empty()) ImGui::TextWrapped("%s", resolve_status_.c_str());
    if (resolved_address_.has_value()) {
        ImGui::Text(
            UiText("Resolved local-symbol address: 0x%016llX (%s)"),
            static_cast<unsigned long long>(*resolved_address_),
            resolved_symbol_.empty()
                ? UiText("unnamed") : resolved_symbol_.c_str());
        if (ImGui::Button(UiLabel(
                "Open Resolved VA in Page Tables",
                "KernelExplorer.OpenResolvedVa").c_str())) {
            page_table_navigation_ = *resolved_address_;
        }
        ImGui::SameLine();
        if (ImGui::Button(UiLabel(
                "Copy Resolved VA",
                "KernelExplorer.CopyResolvedVa").c_str())) {
            char value[32]{};
            std::snprintf(
                value, sizeof(value), "0x%016llX",
                static_cast<unsigned long long>(*resolved_address_));
            ImGui::SetClipboardText(value);
        }
    }

    ImGui::SeparatorText(UiText("Read and disassemble"));
    ImGui::SetNextItemWidth(280.0F);
    ImGui::InputText(
        UiLabel("Kernel VA", "KernelExplorer.KernelVa").c_str(),
        address_.data(), address_.size());
    ImGui::SetNextItemWidth(160.0F);
    ImGui::InputInt(
        UiLabel("Transfer bytes", "KernelExplorer.TransferBytes").c_str(),
        &byte_count_);
    byte_count_ = std::clamp(
        byte_count_, 16, static_cast<int>(kMaximumKernelReadBytes));
    std::uint64_t parsed_address = 0;
    const bool address_parsed = ParseAddress(address_.data(), parsed_address);
    if (address_parsed) {
        const auto* module = ModuleForAddress(parsed_address);
        if (module != nullptr) {
            ImGui::Text(UiText("Target: %s+0x%llX"), module->name.c_str(),
                static_cast<unsigned long long>(parsed_address - module->base));
        } else {
            ImGui::TextDisabled(UiText(
                "Target is not within a module with verified local size metadata."));
        }
        if (ImGui::Button(UiLabel(
                "Open VA in Page Tables",
                "KernelExplorer.OpenVa").c_str())) {
            page_table_navigation_ = parsed_address;
        }
        ImGui::SameLine();
        if (ImGui::Button(UiLabel(
                "Copy Kernel VA", "KernelExplorer.CopyKernelVa").c_str())) {
            char value[32]{};
            std::snprintf(
                value, sizeof(value), "0x%016llX",
                static_cast<unsigned long long>(parsed_address));
            ImGui::SetClipboardText(value);
        }
        ImGui::SameLine();
        ImGui::BeginDisabled(!can_resolve);
        if (ImGui::Button(UiLabel(
                "Resolve Address -> Symbol",
                "KernelExplorer.ResolveAddress").c_str())) {
            StartAddressResolve(parsed_address);
        }
        ImGui::EndDisabled();
    }
    const bool read_busy = read_future_.valid();
    ImGui::BeginDisabled(read_busy || !info.connected);
    if (ImGui::Button(UiLabel(
            "Read + Disassemble", "KernelExplorer.ReadDisassemble").c_str())) {
        StartRead();
    }
    ImGui::EndDisabled();
    if (read_busy) {
        ImGui::SameLine();
        if (ImGui::Button(UiLabel(
                "Cancel Read", "KernelExplorer.CancelRead").c_str())) {
            read_cancel_.store(true, std::memory_order_relaxed);
        }
        const auto progress = read_progress_.load(std::memory_order_relaxed);
        ImGui::ProgressBar(
            static_cast<float>(progress) / 2.0F,
            ImVec2(-1.0F, 0.0F),
            UiText(progress == 0 ? "reading" : "decoding"));
    }
    if (!read_status_.empty()) ImGui::TextWrapped("%s", read_status_.c_str());
    if (!read_bytes_.empty()) {
        const auto last_byte = last_read_address_ + read_bytes_.size() - 1U;
        ImGui::Text(
            UiText(
                "Displayed read result: 0x%016llX-0x%016llX (%zu byte(s))"),
            static_cast<unsigned long long>(last_read_address_),
            static_cast<unsigned long long>(last_byte),
            read_bytes_.size());
        if (!address_parsed || parsed_address != last_read_address_) {
            ImGui::TextColored(
                ImVec4(1.0F, 0.75F, 0.25F, 1.0F),
                UiText(
                    "The input address changed; the table below still belongs "
                    "to the displayed result range."));
        }
    }
    if (!resolved_symbol_.empty()) {
        ImGui::TextWrapped(
            UiText(
                "Local-image symbol result (live PE identity unverified): %s"),
            resolved_symbol_.c_str());
    }

    if (!instructions_.empty() && ImGui::BeginTable(
            "kernel-disassembly", 3,
            ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
                ImGuiTableFlags_Resizable | ImGuiTableFlags_ScrollY,
            ImVec2(0.0F, 480.0F))) {
        ImGui::TableSetupColumn(
            UiLabel("Kernel VA", "Kernel VA").c_str(),
            ImGuiTableColumnFlags_WidthFixed, 155.0F);
        ImGui::TableSetupColumn(
            UiLabel("Bytes", "Bytes").c_str(),
            ImGuiTableColumnFlags_WidthFixed, 230.0F);
        ImGui::TableSetupColumn(
            UiLabel("x64 instruction", "x64 instruction").c_str());
        ImGui::TableHeadersRow();
        ImGuiListClipper clipper;
        clipper.Begin(static_cast<int>(instructions_.size()));
        while (clipper.Step()) {
            for (int row = clipper.DisplayStart; row < clipper.DisplayEnd; ++row) {
                const auto& instruction = instructions_[static_cast<std::size_t>(row)];
                const auto bytes = HexBytes(instruction.bytes);
                ImGui::TableNextRow();
                ImGui::TableNextColumn();
                ImGui::Text("0x%016llX",
                    static_cast<unsigned long long>(instruction.address));
                ImGui::TableNextColumn();
                ImGui::TextUnformatted(bytes.c_str());
                ImGui::TableNextColumn();
                ImGui::TextUnformatted(instruction.text.c_str());
            }
        }
        ImGui::EndTable();
    }
}

}  // namespace kdbg
