#include "app/ui/ProcessUsagePanel.h"

#include "core/pfn/MemProcFsProvider.h"
#include "core/pfn/PageTableReverseMapper.h"

#include <imgui.h>

#include <algorithm>
#include <climits>
#include <cstdio>
#include <filesystem>
#include <iterator>
#include <utility>

namespace kdbg {
namespace {

std::string PathToUtf8(const std::filesystem::path& path) {
    const auto encoded = path.u8string();
    return std::string(
        reinterpret_cast<const char*>(encoded.data()), encoded.size());
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

ProcessUsagePanel::ProcessUsagePanel()
    : bridge_path_(MemProcFsProvider::PackagedBridgePath()) {}

ProcessUsagePanel::~ProcessUsagePanel() { CancelAndWait(); }

void ProcessUsagePanel::RequestCancel() noexcept {
    if (worker_.joinable()) worker_.request_stop();
}

void ProcessUsagePanel::CancelAndWait() {
    generation_.fetch_add(1, std::memory_order_acq_rel);
    if (worker_.joinable()) {
        RequestCancel();
        worker_.join();
    }
    running_.store(false, std::memory_order_release);
    std::scoped_lock lock(worker_mutex_);
    pending_result_.reset();
    pending_error_.reset();
    pending_generation_ = 0;
    pending_requested_pfn_ = 0;
}

bool ProcessUsagePanel::Busy() const noexcept {
    return running_.load(std::memory_order_acquire);
}

void ProcessUsagePanel::SetPhase(std::string phase) {
    std::scoped_lock lock(worker_mutex_);
    phase_ = std::move(phase);
}

void ProcessUsagePanel::Publish(
    std::uint64_t generation,
    std::uint64_t requested_pfn,
    Result<PfnUsageResult> result) {
    std::scoped_lock lock(worker_mutex_);
    if (generation_.load(std::memory_order_acquire) != generation) return;
    pending_generation_ = generation;
    pending_requested_pfn_ = requested_pfn;
    if (result) {
        auto value = result.TakeValue();
        if (value.pfn != requested_pfn) {
            pending_result_.reset();
            pending_error_ = MakeError(
                ErrorCode::VerificationMismatch,
                "PFN ownership provider returned a result for a different PFN",
                "ProcessUsagePanel::Publish",
                0,
                requested_pfn,
                value.pfn);
        } else {
            pending_result_ = std::move(value);
            pending_error_.reset();
        }
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
    const auto bridge = bridge_path_;
    {
        std::scoped_lock lock(worker_mutex_);
        pending_result_.reset();
        pending_error_.reset();
        phase_ = "Launching isolated MemProcFS bridge";
    }
    const auto generation =
        generation_.fetch_add(1, std::memory_order_acq_rel) + 1U;
    job_pfn_ = pfn;
    job_started_ = std::chrono::steady_clock::now();
    running_.store(true, std::memory_order_release);
    status_ = "MemProcFS ownership query started.";
    worker_ = std::jthread(
        [this, bridge, pfn, generation](std::stop_token token) {
        MemProcFsProvider provider(bridge);
        SetPhase("Waiting for isolated MemProcFS bridge");
        Publish(generation, pfn, provider.Query(pfn, token));
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
    const auto generation =
        generation_.fetch_add(1, std::memory_order_acq_rel) + 1U;
    job_pfn_ = pfn;
    job_started_ = std::chrono::steady_clock::now();
    running_.store(true, std::memory_order_release);
    status_ = "Selected-process reverse mapping started.";
    IMemoryBackend* const backend_ptr = &backend;
    worker_ = std::jthread(
        [this, backend_ptr, pfn, pid, process_name = std::move(process_name),
         table_limit, la57, generation](std::stop_token token) {
            const auto context = backend_ptr->GetProcessContext(pid);
            if (!context) {
                Publish(
                    generation,
                    pfn,
                    Result<PfnUsageResult>::Failure(context.GetError()));
                return;
            }
            if (token.stop_requested()) {
                Publish(
                    generation,
                    pfn,
                    Result<PfnUsageResult>::Failure(MakeError(
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
            Publish(generation, pfn, mapper.Query(pfn, token));
        });
}

void ProcessUsagePanel::ConsumeWorkerResult() {
    if (Busy() || !worker_.joinable()) return;
    worker_.join();
    std::optional<PfnUsageResult> result;
    std::optional<Error> error;
    std::uint64_t result_generation = 0;
    std::uint64_t requested_pfn = 0;
    {
        std::scoped_lock lock(worker_mutex_);
        result = std::move(pending_result_);
        error = std::move(pending_error_);
        result_generation = pending_generation_;
        requested_pfn = pending_requested_pfn_;
        pending_result_.reset();
        pending_error_.reset();
        pending_generation_ = 0;
        pending_requested_pfn_ = 0;
    }
    if (result_generation != generation_.load(std::memory_order_acquire)) {
        return;
    }
    if (error.has_value()) {
        mappings_.clear();
        published_pfn_.reset();
        published_generation_ = 0;
        provider_.clear();
        status_ = error->message + " (requested PFN 0x";
        char pfn_text[32]{};
        std::snprintf(
            pfn_text, sizeof(pfn_text), "%llX)",
            static_cast<unsigned long long>(requested_pfn));
        status_ += pfn_text;
        return;
    }
    if (!result.has_value()) return;
    published_pfn_ = result->pfn;
    published_generation_ = result_generation;
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

    const auto bridge_display = PathToUtf8(bridge_path_);
    ImGui::TextWrapped(
        "MemProcFS bridge (packaged): %s", bridge_display.c_str());
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
    DrawResults(page->pfn);
}

void ProcessUsagePanel::DrawResults(std::uint64_t current_pfn) {
    if (!published_pfn_.has_value()) return;
    const bool stale = *published_pfn_ != current_pfn;
    ImGui::Text(
        "Published PFN: 0x%llX | Provider: %s | Mappings: %llu",
        static_cast<unsigned long long>(*published_pfn_),
        provider_.c_str(),
        static_cast<unsigned long long>(mappings_.size()));
    if (stale) {
        ImGui::TextColored(
            ImVec4(1.0F, 0.35F, 0.30F, 1.0F),
            "STALE RESULT: the loaded PFN changed. Navigation is disabled until this PFN is queried.");
    }
    if (mappings_.empty()) return;
    if (ImGui::BeginTable(
            "pfn-mappings", 10,
            ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
                ImGuiTableFlags_Resizable | ImGuiTableFlags_ScrollX |
                ImGuiTableFlags_ScrollY | ImGuiTableFlags_SizingFixedFit,
            ImVec2(0.0F, 420.0F))) {
        ImGui::TableSetupColumn(
            "PID", ImGuiTableColumnFlags_WidthFixed, 64.0F);
        ImGui::TableSetupColumn(
            "Process", ImGuiTableColumnFlags_WidthFixed, 132.0F);
        ImGui::TableSetupColumn(
            "Virtual Address", ImGuiTableColumnFlags_WidthFixed, 152.0F);
        ImGui::TableSetupColumn(
            "PTE Address", ImGuiTableColumnFlags_WidthFixed, 152.0F);
        ImGui::TableSetupColumn(
            "Type", ImGuiTableColumnFlags_WidthFixed, 96.0F);
        ImGui::TableSetupColumn(
            "Shared", ImGuiTableColumnFlags_WidthFixed, 68.0F);
        ImGui::TableSetupColumn(
            "Confidence", ImGuiTableColumnFlags_WidthFixed, 96.0F);
        ImGui::TableSetupColumn(
            "Source", ImGuiTableColumnFlags_WidthFixed, 176.0F);
        ImGui::TableSetupColumn(
            "Permissions", ImGuiTableColumnFlags_WidthFixed, 104.0F);
        ImGui::TableSetupColumn(
            "Open", ImGuiTableColumnFlags_WidthFixed, 96.0F);
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
                if (stale) ImGui::BeginDisabled();
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
                if (stale) ImGui::EndDisabled();
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

std::optional<PfnOwnershipEvidenceSnapshot>
ProcessUsagePanel::CurrentEvidence(
    std::uint64_t pfn,
    std::uint32_t pid,
    std::uint64_t virtual_address) const {
    if (Busy() || !published_pfn_.has_value() || *published_pfn_ != pfn ||
        provider_.empty()) {
        return std::nullopt;
    }
    const auto matches = [&](const ProcessUsage& mapping) {
        return mapping.pid == pid &&
            mapping.virtual_address == virtual_address &&
            mapping.page_size == 0x1000U;
    };
    const auto first = std::find_if(
        mappings_.begin(), mappings_.end(), matches);
    if (first == mappings_.end() ||
        std::find_if(std::next(first), mappings_.end(), matches) !=
            mappings_.end()) {
        return std::nullopt;
    }
    if (published_generation_ == 0) return std::nullopt;
    return PfnOwnershipEvidenceSnapshot{
        pfn, published_generation_, provider_, *first};
}

}  // namespace kdbg
