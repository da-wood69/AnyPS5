#ifndef ANYPS5_MACOS_ELFTYPES_HPP
#define ANYPS5_MACOS_ELFTYPES_HPP

#include <cstdint>

namespace MacRuntime {

struct ElfHeader {
    unsigned char ident[16];
    std::uint16_t type;
    std::uint16_t machine;
    std::uint32_t version;
    std::uint64_t entry;
    std::uint64_t programOffset;
    std::uint64_t sectionOffset;
    std::uint32_t flags;
    std::uint16_t headerSize;
    std::uint16_t programEntrySize;
    std::uint16_t programCount;
    std::uint16_t sectionEntrySize;
    std::uint16_t sectionCount;
    std::uint16_t sectionNames;
};

struct ProgramHeader {
    std::uint32_t type;
    std::uint32_t flags;
    std::uint64_t offset;
    std::uint64_t address;
    std::uint64_t physicalAddress;
    std::uint64_t fileSize;
    std::uint64_t memorySize;
    std::uint64_t alignment;
};

struct SectionHeader {
    std::uint32_t name;
    std::uint32_t type;
    std::uint64_t flags;
    std::uint64_t address;
    std::uint64_t offset;
    std::uint64_t size;
    std::uint32_t link;
    std::uint32_t info;
    std::uint64_t alignment;
    std::uint64_t entrySize;
};

struct DynamicEntry { std::int64_t tag; std::uint64_t value; };

struct Symbol {
    std::uint32_t name;
    std::uint8_t info;
    std::uint8_t other;
    std::uint16_t section;
    std::uint64_t value;
    std::uint64_t size;
};

struct Relocation { std::uint64_t offset; std::uint64_t info; std::int64_t addend; };

inline constexpr std::uint32_t ProgramLoad = 1;
inline constexpr std::uint32_t ProgramDynamic = 2;
inline constexpr std::uint32_t ProgramTls = 7;
inline constexpr std::uint32_t ProgramProcessParameters = 0x61000001;
inline constexpr std::uint32_t ProgramGnuEhFrame = 0x6474e550;
inline constexpr std::uint32_t SectionDynamicSymbols = 11;
inline constexpr std::int64_t DynamicNull = 0;
inline constexpr std::int64_t DynamicNeeded = 1;
inline constexpr std::int64_t DynamicPltRelocationSize = 2;
inline constexpr std::int64_t DynamicHash = 4;
inline constexpr std::int64_t DynamicStringTable = 5;
inline constexpr std::int64_t DynamicSymbolTable = 6;
inline constexpr std::int64_t DynamicRelocation = 7;
inline constexpr std::int64_t DynamicRelocationSize = 8;
inline constexpr std::int64_t DynamicRelocationEntrySize = 9;
inline constexpr std::int64_t DynamicStringTableSize = 10;
inline constexpr std::int64_t DynamicSymbolEntrySize = 11;
inline constexpr std::int64_t DynamicInit = 12;
inline constexpr std::int64_t DynamicFini = 13;
inline constexpr std::int64_t DynamicPltRelocations = 23;
inline constexpr std::int64_t DynamicInitArray = 25;
inline constexpr std::int64_t DynamicFiniArray = 26;
inline constexpr std::int64_t DynamicInitArraySize = 27;
inline constexpr std::int64_t DynamicFiniArraySize = 28;
inline constexpr std::uint32_t Relocation64 = 1;
inline constexpr std::uint32_t RelocationPc32 = 2;
inline constexpr std::uint32_t RelocationGlobDat = 6;
inline constexpr std::uint32_t RelocationJumpSlot = 7;
inline constexpr std::uint32_t RelocationRelative = 8;
inline constexpr std::uint32_t Relocation32 = 10;
inline constexpr std::uint32_t Relocation32Signed = 11;
inline constexpr std::uint32_t RelocationDtpModule = 16;
inline constexpr std::uint32_t RelocationDtpOffset = 17;
inline constexpr std::uint32_t RelocationTpOffset = 18;

}

#endif
