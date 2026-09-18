#include "app/disasm/ZydisDisassembler.h"

#include <Zydis/Zydis.h>

#include <algorithm>
#include <array>
#include <cstdio>
#include <limits>
#include <utility>

namespace kdbg {

Result<std::vector<DisassembledInstruction>> ZydisDisassembler::Decode(
    IProcessMemory& memory,
    std::uint64_t address,
    std::uint32_t byte_count,
    std::size_t max_instructions) const {
    auto report = DecodeDetailed(
        memory, address, byte_count, max_instructions, {});
    if (!report) {
        return Result<std::vector<DisassembledInstruction>>::Failure(
            report.GetError());
    }
    return Result<std::vector<DisassembledInstruction>>::Success(
        std::move(report.Value().instructions));
}

Result<std::vector<DisassembledInstruction>> ZydisDisassembler::DecodeBytes(
    std::span<const std::uint8_t> data,
    std::uint64_t address,
    bool x64,
    std::size_t max_instructions) const {
    auto report = DecodeBytesDetailed(
        data, address, x64, max_instructions);
    if (!report) {
        return Result<std::vector<DisassembledInstruction>>::Failure(
            report.GetError());
    }
    return Result<std::vector<DisassembledInstruction>>::Success(
        std::move(report.Value().instructions));
}

Result<DisassemblyReport> ZydisDisassembler::DecodeDetailed(
    IProcessMemory& memory,
    std::uint64_t address,
    std::uint32_t byte_count,
    std::size_t max_instructions,
    std::stop_token stop_token,
    const DisassemblyProgressCallback& progress) const {
    if (address == 0 || byte_count == 0 || max_instructions == 0) {
        return Result<DisassemblyReport>::Failure(MakeError(
            ErrorCode::InvalidArgument,
            "Invalid disassembly range",
            "ZydisDisassembler::DecodeDetailed"));
    }
    if (stop_token.stop_requested()) {
        return Result<DisassemblyReport>::Failure(MakeError(
            ErrorCode::Cancelled,
            "Disassembly was cancelled before the memory read",
            "ZydisDisassembler::DecodeDetailed"));
    }
    const auto bytes_result = memory.Read(address, byte_count);
    if (!bytes_result) {
        return Result<DisassemblyReport>::Failure(bytes_result.GetError());
    }
    if (bytes_result.Value().size() != byte_count) {
        return Result<DisassemblyReport>::Failure(MakeError(
            ErrorCode::ShortRead,
            "Disassembly memory read returned fewer bytes than requested",
            "ZydisDisassembler::DecodeDetailed",
            0,
            byte_count,
            bytes_result.Value().size()));
    }
    if (stop_token.stop_requested()) {
        return Result<DisassemblyReport>::Failure(MakeError(
            ErrorCode::Cancelled,
            "Disassembly was cancelled after the memory read",
            "ZydisDisassembler::DecodeDetailed",
            0,
            byte_count,
            byte_count));
    }
    auto report = DecodeBytesDetailed(
        bytes_result.Value(), address, memory.PointerSize() != 4,
        max_instructions, stop_token, progress);
    if (report) report.Value().requested_bytes = byte_count;
    return report;
}

Result<DisassemblyReport> ZydisDisassembler::DecodeBytesDetailed(
    std::span<const std::uint8_t> data,
    std::uint64_t address,
    bool x64,
    std::size_t max_instructions,
    std::stop_token stop_token,
    const DisassemblyProgressCallback& progress) const {
    if (address == 0 || data.empty() || max_instructions == 0) {
        return Result<DisassemblyReport>::Failure(MakeError(
            ErrorCode::InvalidArgument,
            "Invalid disassembly byte range",
            "ZydisDisassembler::DecodeBytesDetailed"));
    }

    ZydisDecoder decoder{};
    const auto mode = !x64
        ? ZYDIS_MACHINE_MODE_LEGACY_32
        : ZYDIS_MACHINE_MODE_LONG_64;
    const auto stack_width = !x64
        ? ZYDIS_STACK_WIDTH_32
        : ZYDIS_STACK_WIDTH_64;
    if (!ZYAN_SUCCESS(ZydisDecoderInit(&decoder, mode, stack_width))) {
        return Result<DisassemblyReport>::Failure(MakeError(
            ErrorCode::InternalInvariant,
            "Zydis decoder initialization failed",
            "ZydisDisassembler::Decode"));
    }
    ZydisFormatter formatter{};
    if (!ZYAN_SUCCESS(ZydisFormatterInit(
            &formatter,
            ZYDIS_FORMATTER_STYLE_INTEL))) {
        return Result<DisassemblyReport>::Failure(MakeError(
            ErrorCode::InternalInvariant,
            "Zydis formatter initialization failed",
            "ZydisDisassembler::Decode"));
    }

    DisassemblyReport report{};
    report.requested_bytes = static_cast<std::uint32_t>(
        std::min<std::size_t>(
            data.size(),
            std::numeric_limits<std::uint32_t>::max()));
    report.read_bytes = data.size();
    report.instructions.reserve(
        std::min<std::size_t>(max_instructions, 256));
    std::size_t offset = 0;
    while (offset < data.size() &&
           report.instructions.size() < max_instructions) {
        if (stop_token.stop_requested()) {
            return Result<DisassemblyReport>::Failure(MakeError(
                ErrorCode::Cancelled,
                "Disassembly decode was cancelled",
                "ZydisDisassembler::DecodeBytesDetailed",
                0,
                data.size(),
                offset));
        }
        ZydisDecodedInstruction instruction{};
        std::array<ZydisDecodedOperand, ZYDIS_MAX_OPERAND_COUNT> operands{};
        const auto status = ZydisDecoderDecodeFull(
            &decoder,
            data.data() + offset,
            data.size() - offset,
            &instruction,
            operands.data());
        if (!ZYAN_SUCCESS(status) || instruction.length == 0) {
            DisassembledInstruction invalid{};
            invalid.address = address + offset;
            invalid.bytes.push_back(data[offset]);
            char buffer[32]{};
            std::snprintf(buffer, sizeof(buffer), "db 0x%02X", data[offset]);
            invalid.text = buffer;
            report.instructions.push_back(std::move(invalid));
            ++report.fallback_bytes;
            ++offset;
            if (progress &&
                (report.instructions.size() % 256U == 0U)) {
                progress(DisassemblyProgress{
                    offset, data.size(), report.instructions.size()});
            }
            continue;
        }

        std::array<char, 256> formatted{};
        const auto format_status = ZydisFormatterFormatInstruction(
            &formatter,
            &instruction,
            operands.data(),
            instruction.operand_count_visible,
            formatted.data(),
            formatted.size(),
            address + offset,
            nullptr);

        DisassembledInstruction decoded{};
        decoded.address = address + offset;
        decoded.bytes.assign(
            data.begin() + static_cast<std::ptrdiff_t>(offset),
            data.begin() + static_cast<std::ptrdiff_t>(offset + instruction.length));
        decoded.text = ZYAN_SUCCESS(format_status)
            ? formatted.data()
            : "<format-error>";
        decoded.call = instruction.meta.category == ZYDIS_CATEGORY_CALL;
        decoded.ret = instruction.meta.category == ZYDIS_CATEGORY_RET;
        decoded.branch = decoded.call || decoded.ret ||
            instruction.meta.category == ZYDIS_CATEGORY_COND_BR ||
            instruction.meta.category == ZYDIS_CATEGORY_UNCOND_BR;
        report.instructions.push_back(std::move(decoded));
        offset += instruction.length;
        if (progress &&
            (report.instructions.size() % 256U == 0U)) {
            progress(DisassemblyProgress{
                offset, data.size(), report.instructions.size()});
        }
    }
    report.consumed_bytes = offset;
    report.truncated = offset < data.size();
    if (progress) {
        progress(DisassemblyProgress{
            offset, data.size(), report.instructions.size()});
    }
    return Result<DisassemblyReport>::Success(std::move(report));
}

}  // namespace kdbg
