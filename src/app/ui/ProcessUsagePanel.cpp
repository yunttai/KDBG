#include "app/ui/ProcessUsagePanel.h"

#include "core/pfn/MemProcFsProvider.h"
#include "core/pfn/PageTableReverseMapper.h"

#include <imgui.h>

#include <algorithm>
#include <climits>
#include <cstdio>
#include <filesystem>
#include <utility>

#ifdef _WIN32
#include <Windows.h>
#endif

namespace kdbg {
namespace {

std::filesystem::path ExecutableDirectory() {
#ifdef _WIN32
    std::wstring buffer(32768, L'\0');
    const DWORD length = GetModuleFileNameW(
        nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
    if (length != 0 && length < buffer.size()) {
        buffer.resize(length);
        return std::filesystem::path(buffer).parent_path();
    }
#endif
    return std::filesystem::current_path();
}

const char* ConfidenceName(MappingConfidence confidence) noexcept {
    switch (confidence) {
    case MappingConfidence::Unknown: return "unknown";
    case MappingConfidence::Low: return "low";
    case MappingConfidence::Medium: return "medium";
    case MappingConfidence::High: return "high";
    }
    return "unknown";
}

}  // namespace

ProcessUsagePanel::ProcessUsagePanel() {
    const auto bridge = ExecutableDirectory() / "plugins" /
        "memprocfs_bridge" / "kdbg_memprocfs_bridge.exe";
    const auto text = bridge.string();
    std::snprintf(
        bridge_path_.data(), bridge_path_.size(), "%s", text.c_str());
}

ProcessUsagePanel::~ProcessUsagePanel() { CancelAndWait(); }

void ProcessUsagePanel::CancelAndWait() {
    if (worker_.joinable()) {
        worker_.request_stop();
        worker_.join();
    }
    running_.store(false, std::memory_order_release);
}

bool ProcessUsagePanel::Busy() const noexcept {
    return running_.load(std::memory_order_acquire);
}

void ProcessUsagePanel::SetPhase(std::string phase) {
    std::scoped_lock lock(worker_mutex_);
    phase_ = std::move(phase);
}

void ProcessUsagePanel::Publish(Result<PfnUsageResult> result) {
    std::scoped_lock lock(worker_mutex_);
    if (result) {
        pending_result_ = result.TakeValue();
        pending_error_.reset();
    } else {
        pending_result_.reset();
        pending_error_ = result.GetError();
    }
    phase_ = "Finishing";
    running_.store(false, std::memory_order_release);
}

void ProcessUsagePanel::StartMemProcFs(std::uint64_t pfn) {
    if (Busy()) return;
    if (worker_.joinable()) worker_.join();
    const std::filesystem::path bridge(bridge_path_.data());
    {
        std::scoped_lock lock(worker_mutex_);
        pending_result_.reset();
        pending_error_.reset();
        phase_ = "Launching isolated MemProcFS bridge";
    }
    job_pfn_ = pfn;
    job_started_ = std::chrono::steady_clock::now();
    running_.store(true, std::memory_order_release);
    status_ = "MemProcFS ownership query started.";
    worker_ = std::jthread([this, bridge, pfn](std::stop_token token) {
        MemProcFsProvider provider(bridge);
        SetPhase("Waiting for isolated MemProcFS bridge");
        Publish(provider.Query(pfn, token));
    });
}

void ProcessUsagePanel::StartReverseMap(
    IMemoryBackend& backend,
    std::uint64_t pfn,
    std::uint32_t pid,
    std::string process_name) {
    if (Busy()) return;
    if (worker_.joinable()) worker_.join();
    const auto table_limit = static_cast<std::size_t>(std::max(table_limit_, 1));
    const bool la57 = backend.Info().supports_la57;
    {
        std::scoped_lock lock(worker_mutex_);
        pending_result_.reset();
        pending_error_.reset();
        phase_ = "Reading selected-process paging context";
    }
    job_pfn_ = pfn;
    job_started_ = std::chrono::steady_clock::now();
    running_.store(true, std::memory_order_release);
    status_ = "Selected-process reverse mapping started.";
    IMemoryBackend* const backend_ptr = &backend;
    worker_ = std::jthread(
        [this, backend_ptr, pfn, pid, process_name = std::move(process_name),
         table_limit, la57](std::stop_token token) {
            const auto context = backend_ptr->GetProcessContext(pid);
            if (!context) {
                Publish(Result<PfnUsageResult>::Failure(context.GetError()));
                return;
            }
            if (token.stop_requested()) {
                Publish(Result<PfnUsageResult>::Failure(MakeError(
                    ErrorCode::Cancelled,
                    "PFN reverse mapping was cancelled",
                    "ProcessUsagePanel::StartReverseMap")));
                return;
            }
            SetPhase("Scanning selected-process page tables");
            PageTableReverseMapper mapper(*backend_ptr);
            mapper.SetLimits(ReverseMapLimits{table_limit, 200000});
            mapper.SetTargets({ProcessScanTarget{
                pid,
                process_name,
                context.Value().directory_table_base,
                la57}});
            Publish(mapper.Query(pfn, token));
        });
}

void ProcessUsagePanel::ConsumeWorkerResult() {
    if (Busy() || !worker_.joinable()) return;
    worker_.join();
    std::optional<PfnUsageResult> result;
    std::optional<Error> error;
    {
        std::scoped_lock lock(worker_mutex_);
        result = std::move(pending_result_);
        error = std::move(pending_error_);
        pending_result_.reset();
        pending_error_.reset();
    }
    if (error.has_value()) {
        mappings_.clear();
        provider_.clear();
        status_ = error->message;
        return;
    }
    if (!result.has_value()) return;
    mappings_ = std::move(result->mappings);
    provider_ = std::move(result->provider);
    status_ = "PFN ownership query complete: " +
        std::to_string(mappings_.size()) + " mapping(s).";
}

void ProcessUsagePanel::Draw(
    IMemoryBackend& backend,
    const std::optional<PfnAddress>& page,
    std::uint32_t attached_pid,
    const std::string& attached_name) {
    ConsumeWorkerResult();
    ImGui::TextUnformatted("PFN -> Process / Virtual Address");
    if (!page.has_value()) {
        ImGui::TextDisabled("Load a PFN first.");
        if (Busy()) {
            ImGui::TextWrapped("A query for PFN 0x%llX is still running.",
                static_cast<unsigned long long>(job_pfn_));
            if (ImGui::Button("Cancel PFN Query")) worker_.request_stop();
        }
        return;
    }
    ImGui::Text("Target PFN: 0x%llX | PA: 0x%016llX",
        static_cast<unsigned long long>(page->pfn),
        static_cast<unsigned long long>(page->physical_address));

    ImGui::SetNextItemWidth(-1.0F);
    ImGui::InputText("MemProcFS bridge", bridge_path_.data(), bridge_path_.size());
    const bool busy = Busy();
    if (busy) ImGui::BeginDisabled();
    if (ImGui::Button("Query MemProcFS")) StartMemProcFs(page->pfn);
    ImGui::SameLine();
    if (attached_pid == 0 || !backend.Info().connected) ImGui::BeginDisabled();
    if (ImGui::Button("Reverse-map Attached Process")) {
        StartReverseMap(
            backend, page->pfn, attached_pid, attached_name);
    }
    if (attached_pid == 0 || !backend.Info().connected) ImGui::EndDisabled();
    if (busy) ImGui::EndDisabled();
    ImGui::SetNextItemWidth(150.0F);
    ImGui::InputInt("Table-page limit", &table_limit_);
    table_limit_ = std::clamp(table_limit_, 1, 2'000'000);
    if (busy) {
        std::string phase;
        {
            std::scoped_lock lock(worker_mutex_);
            phase = phase_;
        }
        const auto elapsed = std::chrono::duration<double>(
            std::chrono::steady_clock::now() - job_started_).count();
        ImGui::ProgressBar(0.0F, ImVec2(-1.0F, 0.0F), phase.c_str());
        ImGui::Text("Target PFN 0x%llX | elapsed %.1f s | cancellation is cooperative",
            static_cast<unsigned long long>(job_pfn_), elapsed);
        if (ImGui::Button("Cancel PFN Query")) {
            worker_.request_stop();
            status_ = "PFN query cancellation requested.";
        }
    }
    if (attached_pid == 0) ImGui::TextDisabled("Attach a process for the built-in page-table reverse mapper.");
    if (!status_.empty()) ImGui::TextWrapped("%s", status_.c_str());
    DrawResults();
}

void ProcessUsagePanel::DrawResults() {
    if (mappings_.empty()) return;
    ImGui::Text("Provider: %s", provider_.c_str());
    if (ImGui::BeginTable(
            "pfn-mappings", 10,
            ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
                ImGuiTableFlags_Resizable | ImGuiTableFlags_ScrollY,
            ImVec2(0.0F, 420.0F))) {
        ImGui::TableSetupColumn("PID");
        ImGui::TableSetupColumn("Process");
        ImGui::TableSetupColumn("Virtual Address");
        ImGui::TableSetupColumn("PTE Address");
        ImGui::TableSetupColumn("Type");
        ImGui::TableSetupColumn("Shared");
        ImGui::TableSetupColumn("Confidence");
        ImGui::TableSetupColumn("Source");
        ImGui::TableSetupColumn("Permissions");
        ImGui::TableSetupColumn("Open");
        ImGui::TableHeadersRow();
        ImGuiListClipper clipper;
        clipper.Begin(static_cast<int>(std::min<std::size_t>(
            mappings_.size(), static_cast<std::size_t>(INT_MAX))));
        while (clipper.Step()) {
            for (int index = clipper.DisplayStart;
                 index < clipper.DisplayEnd; ++index) {
                const auto& mapping = mappings_[static_cast<std::size_t>(index)];
                ImGui::PushID(index);
                ImGui::TableNextRow();
                ImGui::TableNextColumn(); ImGui::Text("%u", mapping.pid);
                ImGui::TableNextColumn(); ImGui::TextUnformatted(mapping.process_name.c_str());
                ImGui::TableNextColumn(); ImGui::Text("0x%016llX", static_cast<unsigned long long>(mapping.virtual_address));
                ImGui::TableNextColumn(); ImGui::Text("0x%016llX", static_cast<unsigned long long>(mapping.pte_address));
                ImGui::TableNextColumn(); ImGui::TextUnformatted(mapping.mapping_type.c_str());
                ImGui::TableNextColumn(); ImGui::TextUnformatted(mapping.shared ? "yes" : "no");
                ImGui::TableNextColumn(); ImGui::TextUnformatted(ConfidenceName(mapping.confidence));
                ImGui::TableNextColumn(); ImGui::TextUnformatted(mapping.source.c_str());
                ImGui::TableNextColumn();
                ImGui::Text("%s/%s/%s",
                    mapping.user_accessible ? "U" : "K",
                    mapping.writable ? "RW" : "R",
                    mapping.no_execute ? "NX" : "X");
                ImGui::TableNextColumn();
                if (ImGui::SmallButton("PT")) {
                    navigation_ = PfnUsageNavigation{
                        PfnUsageNavigationTarget::PageTables,
                        mapping.pid,
                        mapping.virtual_address};
                }
                ImGui::SameLine();
                if (ImGui::SmallButton("Hex")) {
                    navigation_ = PfnUsageNavigation{
                        PfnUsageNavigationTarget::ProcessMemory,
                        mapping.pid,
                        mapping.virtual_address};
                }
                ImGui::PopID();
            }
        }
        ImGui::EndTable();
    }
}

std::optional<PfnUsageNavigation> ProcessUsagePanel::ConsumeNavigation() {
    auto result = navigation_;
    navigation_.reset();
    return result;
}

}  // namespace kdbg
