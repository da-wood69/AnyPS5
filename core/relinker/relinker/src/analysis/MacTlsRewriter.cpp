#include <relinker/analysis/MacTlsRewriter.hpp>
#include <relinker/analysis/CodeInstructionCollector.hpp>
#include <codegen/x86/X64InstructionDecoder.hpp>
#include <domain/Types.hpp>
#include <cstring>
#include <limits>

namespace Relinker {

namespace {

bool IsAluReadOpcode(std::uint8_t opcode) {
    return opcode == 0x03 || opcode == 0x0b || opcode == 0x13 || opcode == 0x1b ||
           opcode == 0x23 || opcode == 0x2b || opcode == 0x33 || opcode == 0x3b;
}

}

std::size_t MacTlsRewriter::Rewrite(std::vector<std::uint8_t>& bytes, const std::vector<Domain::ProgramHeader>& headers) const {
    bool mayContainTlsAccess = false;
    for (const auto& header : headers) {
        if (header.Type != 1 || (header.Flags & 1) == 0 || header.FileSize == 0) continue;
        if (header.Offset > bytes.size() || header.FileSize > bytes.size() - header.Offset)
            throw Domain::RelinkerException("macOS TLS code segment exceeds source image", header.Offset);
        const auto begin = static_cast<std::size_t>(header.Offset);
        const auto end = begin + static_cast<std::size_t>(header.FileSize);
        for (auto prefix = begin; prefix < end; ++prefix) {
            if (bytes[prefix] != 0x64) continue;
            auto opcode = prefix + 1;
            if (opcode < end && bytes[opcode] == 0x66) ++opcode;
            if (opcode < end && bytes[opcode] >= 0x40 && bytes[opcode] <= 0x4f) ++opcode;
            if (opcode + 2 >= end) continue;
            const auto value = bytes[opcode];
            if ((value == 0x8b || value == 0xc7 || IsAluReadOpcode(value)) &&
                (bytes[opcode + 1] & 0xc7) == 0x04 && bytes[opcode + 2] == 0x25) {
                mayContainTlsAccess = true;
                break;
            }
        }
        if (mayContainTlsAccess) break;
    }
    if (!mayContainTlsAccess) return 0;

    const auto instructions = CodeInstructionCollector().Collect(bytes, headers);
    const Codegen::X64InstructionDecoder decoder;
    std::size_t rewritten = 0;
    for (const auto address : instructions) {
        const Domain::ProgramHeader* segment = nullptr;
        for (const auto& header : headers) {
            if (header.Type == 1 && (header.Flags & 1) != 0 && address >= header.MappedAddress &&
                address - header.MappedAddress < header.FileSize) {
                segment = &header;
                break;
            }
        }
        if (!segment) continue;
        const auto delta = address - segment->MappedAddress;
        if (segment->Offset > std::numeric_limits<std::size_t>::max() - delta) throw Domain::RelinkerException("macOS TLS instruction offset overflows", address);
        const auto offset = static_cast<std::size_t>(segment->Offset + delta);
        const auto available = static_cast<std::size_t>(segment->FileSize - delta);
        const auto info = decoder.DecodeInstruction(bytes.data() + offset, available);
        if (info.SegmentPrefix != 0x64) continue;

        const auto opcode = info.OpcodeOffset;
        bool hasOperandSize = false;
        bool supportedPrefixes = true;
        std::size_t fsPrefix = info.Length;
        for (std::size_t prefix = 0; prefix < opcode; ++prefix) {
            const auto value = bytes[offset + prefix];
            if (value == 0x64) fsPrefix = prefix;
            else if (value == 0x66) hasOperandSize = true;
            else if (!(prefix + 1 == opcode && value >= 0x40 && value <= 0x4f)) supportedPrefixes = false;
        }
        const auto loadRegister = info.Length - opcode == 7 ? static_cast<std::uint8_t>(((bytes[offset + opcode + 1] >> 3) & 7) | ((info.RexPrefix & 4) << 1)) : std::uint8_t{4};
        const bool loadValue = supportedPrefixes && (info.RexPrefix == 0x48 || info.RexPrefix == 0x4c) && loadRegister != 4 &&
            bytes[offset + opcode] == 0x8b && (bytes[offset + opcode + 1] & 0xc7) == 0x04 && bytes[offset + opcode + 2] == 0x25;
        const bool storeImmediate = supportedPrefixes && !hasOperandSize && (info.RexPrefix == 0 || info.RexPrefix == 0x40) &&
            info.Length - opcode == 11 && bytes[offset + opcode] == 0xc7 && (bytes[offset + opcode + 1] & 0xc7) == 0x04 && bytes[offset + opcode + 2] == 0x25;
        const bool aluRead = supportedPrefixes && (info.RexPrefix == 0x48 || info.RexPrefix == 0x4c) && loadRegister != 4 &&
            info.Length - opcode == 7 && IsAluReadOpcode(bytes[offset + opcode]) &&
            (bytes[offset + opcode + 1] & 0xc7) == 0x04 && bytes[offset + opcode + 2] == 0x25;
        if (fsPrefix == info.Length || (!loadValue && !storeImmediate && !aluRead))
            throw Domain::RelinkerException("Unsupported macOS guest TLS instruction", offset);

        std::uint32_t displacement = 0;
        std::memcpy(&displacement, bytes.data() + offset + opcode + 3, sizeof(displacement));
        if (displacement == 0) displacement = 6 * sizeof(std::uintptr_t);
        else if (displacement == 0x28) displacement = 11 * sizeof(std::uintptr_t);
        else throw Domain::RelinkerException("macOS guest TLS access requires an unsupported direct FS displacement", offset);
        bytes[offset + fsPrefix] = 0x65;
        std::memcpy(bytes.data() + offset + opcode + 3, &displacement, sizeof(displacement));
        ++rewritten;
    }
    return rewritten;
}

}
