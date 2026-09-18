#include "app/ui/DisassemblyPanel.h"

#include <imgui.h>

#include <algorithm>
#include <charconv>
#include <chrono>
#include <exception>
#include <iomanip>
#include <sstream>
#include <string_view>

namespace kdbg {
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

std::string HexBytes(const std::vector<std::uint8_t>& bytes) {
    std::ostringstream stream;
    for (std::size_t i = 0; i < bytes.size(); ++i) {
        if (i != 0) stream << ' ';
        stream << std::uppercase << std::hex << std::setw(2)
               << std::setfill('0') << static_cast<unsigned>(bytes[i]);
    }
    return stream.str();
}

}  // namespace

DisassemblyPanel::~DisassemblyPanel() {
    CancelAndWait();
}

bool DisassemblyPanel::Busy() const noexcept {
    return decode_future_.valid();
}

void DisassemblyPanel::Poll() {
    PollDecode();
}

void DisassemblyPanel::RequestCancel() noexcept {
    stop_source_.request_stop();
}

void DisassemblyPanel::CancelAndWait() noexcept {
    RequestCancel();
    try {
        if (decode_future_.valid()) {
            static_cast<void>(decode_future_.get());
        }
    } catch (...) {
        // Process detach/destruction must continue after worker failure.
    }
}

void DisassemblyPanel::Attach(IProcessMemory* memory) {
    CancelAndWait();
    ++generation_;
    memory_ = memory;
    instructions_.clear();
    result_address_.reset();
    result_report_ = {};
    status_.clear();
}

void DisassemblyPanel::StartDecode(
    std::uint64_t address,
    std::uint32_t byte_count) {
    if (Busy() || memory_ == nullptr || !memory_->IsOpen()) return;
    stop_source_ = std::stop_source{};
    const auto stop_token = stop_source_.get_token();
    progress_.store(0, std::memory_order_relaxed);
    progress_consumed_.store(0, std::memory_order_relaxed);
    progress_total_.store(byte_count, std::memory_order_relaxed);
    progress_instructions_.store(0, std::memory_order_relaxed);
    const auto generation = ++generation_;
    IProcessMemory* const memory = memory_;
    status_ = "Reading and decoding process memory asynchronously...";
    decode_future_ = std::async(
        std::launch::async,
        [this, memory, address, byte_count, generation, stop_token] {
            DecodeOutcome outcome;
            outcome.generation = generation;
            outcome.address = address;
            try {
                progress_.store(1, std::memory_order_relaxed);
                ZydisDisassembler disassembler;
                auto decoded = disassembler.DecodeDetailed(
                    *memory,
                    address,
                    byte_count,
                    10000,
                    stop_token,
                    [this](const DisassemblyProgress& update) {
                        progress_consumed_.store(
                            update.bytes_consumed,
                            std::memory_order_relaxed);
                        progress_total_.store(
                            update.bytes_total,
                            std::memory_order_relaxed);
                        progress_instructions_.store(
                            update.instructions,
                            std::memory_order_relaxed);
                    });
                progress_.store(2, std::memory_order_relaxed);
                if (!decoded) {
                    outcome.error = decoded.GetError();
                    return outcome;
                }
                outcome.report = decoded.TakeValue();
            } catch (const std::exception& exception) {
                outcome.error = MakeError(
                    ErrorCode::InternalInvariant,
                    "Disassembly worker failed: " +
                        std::string(exception.what()),
                    "DisassemblyPanel::StartDecode");
            } catch (...) {
                outcome.error = MakeError(
                    ErrorCode::InternalInvariant,
                    "Disassembly worker failed with an unknown exception",
                    "DisassemblyPanel::StartDecode");
            }
            return outcome;
        });
}

void DisassemblyPanel::PollDecode() {
    using namespace std::chrono_literals;
    if (!decode_future_.valid() ||
        decode_future_.wait_for(0ms) != std::future_status::ready) {
        return;
    }
    DecodeOutcome outcome;
    try {
        outcome = decode_future_.get();
    } catch (const std::exception& exception) {
        status_ = "Disassembly result publication failed: " +
            std::string(exception.what());
        return;
    } catch (...) {
        status_ =
            "Disassembly result publication failed with an unknown exception.";
        return;
    }
    if (outcome.generation != generation_) return;
    if (outcome.error.code != ErrorCode::None) {
        status_ = outcome.error.message;
        if (outcome.error.requested != 0 ||
            outcome.error.completed != 0) {
            status_ += " | requested=" +
                std::to_string(outcome.error.requested) +
                " completed=" +
                std::to_string(outcome.error.completed);
        }
        return;
    }
    result_report_ = std::move(outcome.report);
    instructions_ = std::move(result_report_.instructions);
    result_address_ = outcome.address;
    status_ = "Decoded " + std::to_string(instructions_.size()) +
        " instruction(s), consumed " +
        std::to_string(result_report_.consumed_bytes) + " of " +
        std::to_string(result_report_.read_bytes) + " byte(s).";
    if (result_report_.truncated) {
        status_ += " Result truncated at the 10,000 instruction cap.";
    }
    if (result_report_.fallback_bytes != 0) {
        status_ += " " + std::to_string(result_report_.fallback_bytes) +
            " undecodable byte(s) were rendered as db.";
    }
}

void DisassemblyPanel::Draw() {
    PollDecode();
    const bool decode_busy = Busy();
    if (memory_ == nullptr || (!decode_busy && !memory_->IsOpen())) {
        ImGui::TextDisabled("Attach to a process to disassemble memory.");
        return;
    }
    ImGui::TextWrapped(
        "The disassembly view uses Zydis and reads the target through the same "
        "Win32/KDBG fallback process backend as the scanner.");
    ImGui::SetNextItemWidth(260.0F);
    ImGui::InputText("Start Address", address_.data(), address_.size());
    ImGui::SetNextItemWidth(140.0F);
    ImGui::InputInt("Bytes", &byte_count_);
    byte_count_ = std::clamp(byte_count_, 16, 1024 * 1024);
    ImGui::SameLine();
    ImGui::BeginDisabled(decode_busy);
    if (ImGui::Button("Disassemble")) {
        std::uint64_t address = 0;
        if (!ParseAddress(address_.data(), address)) {
            status_ = "Invalid disassembly address.";
        } else {
            StartDecode(address, static_cast<std::uint32_t>(byte_count_));
        }
    }
    ImGui::EndDisabled();
    if (decode_busy) {
        ImGui::SameLine();
        if (ImGui::Button("Cancel Disassembly")) {
            stop_source_.request_stop();
            status_ = "Disassembly cancellation requested.";
        }
        const auto progress = progress_.load(std::memory_order_relaxed);
        const auto consumed =
            progress_consumed_.load(std::memory_order_relaxed);
        const auto total = progress_total_.load(std::memory_order_relaxed);
        const auto instructions =
            progress_instructions_.load(std::memory_order_relaxed);
        const float fraction = progress == 1 && total != 0
            ? std::clamp(
                static_cast<float>(consumed) /
                    static_cast<float>(total),
                0.0F,
                1.0F)
            : static_cast<float>(progress) / 2.0F;
        const std::string overlay = progress == 0
            ? "queued"
            : (progress == 1
                ? (consumed == 0
                    ? "reading"
                    : "decoding " + std::to_string(consumed) + " / " +
                        std::to_string(total) + " bytes, " +
                        std::to_string(instructions) + " instructions")
                : "publishing");
        ImGui::ProgressBar(
            fraction,
            ImVec2(-1.0F, 0.0F),
            overlay.c_str());
    }
    if (!status_.empty()) ImGui::TextWrapped("%s", status_.c_str());

    std::uint64_t input_address = 0;
    const bool input_valid = ParseAddress(address_.data(), input_address);
    if (result_address_.has_value()) {
        ImGui::Text(
            "Displayed result: 0x%016llX | requested %u | read %llu | consumed %llu | fallback %llu | %s",
            static_cast<unsigned long long>(*result_address_),
            result_report_.requested_bytes,
            static_cast<unsigned long long>(result_report_.read_bytes),
            static_cast<unsigned long long>(result_report_.consumed_bytes),
            static_cast<unsigned long long>(result_report_.fallback_bytes),
            result_report_.truncated ? "TRUNCATED" : "COMPLETE");
        if (!input_valid || input_address != *result_address_) {
            ImGui::TextColored(
                ImVec4(1.0F, 0.75F, 0.25F, 1.0F),
                "The input address changed; the table still shows the published result above.");
        }
    }

    if (instructions_.empty()) return;
    if (ImGui::BeginTable(
            "disassembly", 3,
            ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
                ImGuiTableFlags_Resizable | ImGuiTableFlags_ScrollY,
            ImVec2(0.0F, 650.0F))) {
        ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthFixed, 150.0F);
        ImGui::TableSetupColumn("Bytes", ImGuiTableColumnFlags_WidthFixed, 240.0F);
        ImGui::TableSetupColumn("Instruction");
        ImGui::TableHeadersRow();
        ImGuiListClipper clipper;
        clipper.Begin(static_cast<int>(instructions_.size()));
        while (clipper.Step()) {
            for (int index = clipper.DisplayStart; index < clipper.DisplayEnd; ++index) {
                const auto& instruction = instructions_[static_cast<std::size_t>(index)];
                const auto bytes = HexBytes(instruction.bytes);
                ImGui::TableNextRow();
                ImGui::TableNextColumn();
                ImGui::Text("0x%016llX", static_cast<unsigned long long>(instruction.address));
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
