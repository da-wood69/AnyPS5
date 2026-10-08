#include "ElfLoader.hpp"
#include <algorithm>
#include <bit>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <dlfcn.h>
#include <fstream>
#include <iostream>
#include <limits>
#include <new>
#include <pthread.h>
#include <stdexcept>
#include <string_view>
#include <system_error>
#include <sys/mman.h>
#include <type_traits>
#include <unistd.h>

namespace MacRuntime {

namespace {

template<class T>
T Read(const std::vector<std::uint8_t>& bytes, std::size_t offset, const char* field) {
    if (offset > bytes.size() || sizeof(T) > bytes.size() - offset)
        throw std::runtime_error(std::string("ELF ") + field + " is outside the file");
    T result;
    std::memcpy(&result, bytes.data() + offset, sizeof(result));
    return result;
}

std::uint64_t AlignDown(std::uint64_t value, std::uint64_t alignment) { return value & ~(alignment - 1); }

std::uint64_t AlignUp(std::uint64_t value, std::uint64_t alignment) {
    if (value > std::numeric_limits<std::uint64_t>::max() - alignment + 1) throw std::runtime_error("ELF address range overflows");
    return AlignDown(value + alignment - 1, alignment);
}

int NativeProtection(std::uint32_t flags) {
    return ((flags & 4) ? PROT_READ : 0) | ((flags & 2) ? PROT_WRITE : 0) | ((flags & 1) ? PROT_EXEC : 0);
}

template<class T>
void Store(void* destination, T value) { std::memcpy(destination, &value, sizeof(value)); }

struct TlsIndex { std::uint64_t module; std::uint64_t offset; };
constexpr std::size_t StaticTlsCapacity = 64 * 1024 * 1024;
constexpr std::uintptr_t StackGuard = 0xDEADBEEFCAFEBABEull;

struct ThreadTlsState {
    void* reservation = nullptr;
    std::size_t reservationSize = 0;
    std::uintptr_t threadPointer = 0;
    void* previousBase = nullptr;
    void* previousGuard = nullptr;
    std::size_t depth = 0;
    std::vector<bool> initialized;

    ~ThreadTlsState() {
        if (reservation) munmap(reservation, reservationSize);
    }
};

thread_local std::map<Runtime*, std::unique_ptr<ThreadTlsState>> threadTls;
Runtime* activeRuntime = nullptr;

constexpr unsigned long GuestTlsBaseSlot = 6;
constexpr unsigned long GuestStackGuardSlot = 11;
extern "C" int _pthread_setspecific_static(unsigned long slot, void* value);

extern "C" void* AnyPs5TlsGetAddr(const TlsIndex* index) {
    if (!activeRuntime || !index) return nullptr;
    return activeRuntime->TlsAddress(index->module, index->offset);
}

extern "C" void AnyPs5GuestThreadEnter() {
    if (!activeRuntime) throw std::runtime_error("macOS guest thread entered without a runtime");
    activeRuntime->EnterThread();
}

extern "C" void AnyPs5GuestThreadLeave() {
    if (activeRuntime) activeRuntime->LeaveThread();
}

void CopyError(char* output, std::size_t capacity, const std::string& message) {
    if (!output || capacity == 0) return;
    const auto bytes = std::min(capacity - 1, message.size());
    std::memcpy(output, message.data(), bytes);
    output[bytes] = 0;
}

bool TraceLoader() { return std::getenv("ANYPS5_TRACE_LOADER") != nullptr; }

constexpr std::uint8_t EhPeOmit = 0xff;
constexpr std::uint8_t EhPePcrel = 0x10;
constexpr std::uint8_t EhPeTextrel = 0x20;
constexpr std::uint8_t EhPeDatarel = 0x30;
constexpr std::uint8_t EhPeAligned = 0x50;
constexpr std::uint8_t EhPeIndirect = 0x80;

template<class T>
std::optional<std::uint64_t> ReadEncodedScalar(const std::uint8_t*& cursor, const std::uint8_t* end) {
    if (cursor > end || sizeof(T) > static_cast<std::size_t>(end - cursor)) return std::nullopt;
    T value;
    std::memcpy(&value, cursor, sizeof(value));
    cursor += sizeof(value);
    if constexpr (std::is_signed_v<T>) return static_cast<std::uint64_t>(static_cast<std::int64_t>(value));
    return static_cast<std::uint64_t>(value);
}

std::optional<std::uint64_t> ReadUleb128(const std::uint8_t*& cursor, const std::uint8_t* end) {
    std::uint64_t result = 0;
    unsigned shift = 0;
    while (cursor < end && shift < 64) {
        const auto byte = *cursor++;
        result |= static_cast<std::uint64_t>(byte & 0x7f) << shift;
        if ((byte & 0x80) == 0) return result;
        shift += 7;
    }
    return std::nullopt;
}

std::optional<std::uint64_t> ReadSleb128(const std::uint8_t*& cursor, const std::uint8_t* end) {
    std::uint64_t result = 0;
    unsigned shift = 0;
    std::uint8_t byte = 0;
    do {
        if (cursor >= end || shift >= 64) return std::nullopt;
        byte = *cursor++;
        result |= static_cast<std::uint64_t>(byte & 0x7f) << shift;
        shift += 7;
    } while (byte & 0x80);
    if (shift < 64 && (byte & 0x40)) result |= ~std::uint64_t{0} << shift;
    return result;
}

std::optional<std::uintptr_t> DecodeEhPointer(const std::uint8_t*& cursor, const std::uint8_t* end,
                                              std::uint8_t encoding, std::uintptr_t textBase,
                                              std::uintptr_t dataBase) {
    if (encoding == EhPeOmit || (encoding & EhPeIndirect)) return std::nullopt;
    const auto application = encoding & 0x70;
    if (application == EhPeAligned) {
        const auto address = reinterpret_cast<std::uintptr_t>(cursor);
        const auto aligned = (address + sizeof(void*) - 1) & ~(sizeof(void*) - 1);
        if (aligned < address || aligned > reinterpret_cast<std::uintptr_t>(end)) return std::nullopt;
        cursor = reinterpret_cast<const std::uint8_t*>(aligned);
    }
    const auto fieldAddress = reinterpret_cast<std::uintptr_t>(cursor);
    std::optional<std::uint64_t> raw;
    switch (encoding & 0x0f) {
    case 0x00: raw = ReadEncodedScalar<std::uintptr_t>(cursor, end); break;
    case 0x01: raw = ReadUleb128(cursor, end); break;
    case 0x02: raw = ReadEncodedScalar<std::uint16_t>(cursor, end); break;
    case 0x03: raw = ReadEncodedScalar<std::uint32_t>(cursor, end); break;
    case 0x04: raw = ReadEncodedScalar<std::uint64_t>(cursor, end); break;
    case 0x09: raw = ReadSleb128(cursor, end); break;
    case 0x0a: raw = ReadEncodedScalar<std::int16_t>(cursor, end); break;
    case 0x0b: raw = ReadEncodedScalar<std::int32_t>(cursor, end); break;
    case 0x0c: raw = ReadEncodedScalar<std::int64_t>(cursor, end); break;
    default: return std::nullopt;
    }
    if (!raw) return std::nullopt;
    std::uintptr_t base = 0;
    switch (application) {
    case 0x00:
    case EhPeAligned: break;
    case EhPePcrel: base = fieldAddress; break;
    case EhPeTextrel: base = textBase; break;
    case EhPeDatarel: base = dataBase; break;
    default: return std::nullopt;
    }
    return base + static_cast<std::uintptr_t>(*raw);
}

}

extern "C" void* AnyPs5GuestDlopen(const char* path, int, char* error, std::size_t errorCapacity) {
    try {
        if (!activeRuntime || !path || !*path) throw std::runtime_error("macOS guest loader received an empty path");
        auto* result = activeRuntime->OpenGuest(path);
        if (TraceLoader()) std::cerr << "Guest dlopen: " << path << " -> " << result << '\n';
        return result;
    } catch (const std::exception& exception) {
        if (TraceLoader()) std::cerr << "Guest dlopen failed: " << exception.what() << '\n';
        CopyError(error, errorCapacity, exception.what());
        return nullptr;
    }
}

extern "C" void* AnyPs5GuestDlsym(void* handle, const char* name) {
    if (!activeRuntime || !handle || !name || !*name) return nullptr;
    auto* result = activeRuntime->GuestSymbol(handle, name);
    if (TraceLoader()) std::cerr << "Guest dlsym: " << name << " -> " << result << '\n';
    return result;
}

extern "C" int AnyPs5GuestDlclose(void* handle) {
    return activeRuntime ? activeRuntime->CloseGuest(handle) : -1;
}

extern "C" int AnyPs5GuestModuleInfo(std::uint64_t address, ModuleInfoEx* info) {
    if (!activeRuntime || !info || info->st_size != sizeof(*info)) return -1;
    try {
        if (!activeRuntime->ModuleInfo(static_cast<std::uintptr_t>(address), *info)) return -1;
        if (TraceLoader())
            std::cerr << "Guest module info: eh_frame=" << reinterpret_cast<const void*>(info->eh_frame_addr)
                      << "/" << info->eh_frame_size << ", eh_frame_hdr="
                      << reinterpret_cast<const void*>(info->eh_frame_hdr_addr) << "/" << info->eh_frame_hdr_size << '\n';
        return 0;
    } catch (const std::exception& exception) {
        if (TraceLoader()) std::cerr << "Guest module-info query failed: " << exception.what() << '\n';
        return -1;
    }
}

ElfImage::ElfImage(Runtime& runtime, std::filesystem::path path, bool mainImage)
    : runtime(runtime), path(std::filesystem::weakly_canonical(std::move(path))), mainImage(mainImage) {
    ReadFile();
    Map();
    ReadDynamic();
    ReadSymbols();
}

ElfImage::~ElfImage() {
    if (reservation) munmap(reservation, reservationSize);
}

void ElfImage::ReadFile() {
    std::ifstream stream(path, std::ios::binary | std::ios::ate);
    if (!stream) throw std::runtime_error("Cannot open guest ELF: " + path.string());
    const auto end = stream.tellg();
    if (end < 0) throw std::runtime_error("Cannot determine guest ELF size: " + path.string());
    file.resize(static_cast<std::size_t>(end));
    stream.seekg(0);
    if (!file.empty() && !stream.read(reinterpret_cast<char*>(file.data()), static_cast<std::streamsize>(file.size())))
        throw std::runtime_error("Cannot read guest ELF: " + path.string());
    header = Read<ElfHeader>(file, 0, "header");
    if (std::memcmp(header.ident, "\x7f" "ELF", 4) != 0 || header.ident[4] != 2 || header.ident[5] != 1 ||
        header.machine != 62 || header.programEntrySize != sizeof(ProgramHeader))
        throw std::runtime_error("Guest image is not a little-endian ELF64 x86-64 file: " + path.string());
    if (header.type != 3) throw std::runtime_error("Guest ELF is not position independent: " + path.string());
    for (std::size_t index = 0; index < header.programCount; ++index) {
        const auto offset = header.programOffset + index * sizeof(ProgramHeader);
        if (offset > std::numeric_limits<std::size_t>::max()) throw std::runtime_error("ELF program table overflows");
        programs.push_back(Read<ProgramHeader>(file, static_cast<std::size_t>(offset), "program header"));
    }
}

void ElfImage::Map() {
    const auto page = static_cast<std::uint64_t>(getpagesize());
    std::uint64_t first = std::numeric_limits<std::uint64_t>::max();
    std::uint64_t last = 0;
    for (const auto& program : programs) {
        if (program.type != ProgramLoad || program.memorySize == 0) continue;
        if (program.fileSize > program.memorySize || program.offset > file.size() || program.fileSize > file.size() - program.offset ||
            program.address > std::numeric_limits<std::uint64_t>::max() - program.memorySize)
            throw std::runtime_error("Invalid PT_LOAD range in " + path.string());
        first = std::min(first, AlignDown(program.address, page));
        last = std::max(last, AlignUp(program.address + program.memorySize, page));
    }
    if (first == std::numeric_limits<std::uint64_t>::max() || last <= first || last - first > std::numeric_limits<std::size_t>::max())
        throw std::runtime_error("Guest ELF has no usable PT_LOAD image: " + path.string());
    reservationSize = static_cast<std::size_t>(last - first);
    reservation = mmap(nullptr, reservationSize, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
    if (reservation == MAP_FAILED) {
        reservation = nullptr;
        throw std::system_error(errno, std::generic_category(), "reserve guest ELF address space");
    }
    mappedBegin = reinterpret_cast<std::uintptr_t>(reservation);
    mappedEnd = mappedBegin + reservationSize;
    slide = mappedBegin - first;
    for (const auto& program : programs) {
        if (program.type != ProgramLoad || program.memorySize == 0) continue;
        auto* destination = reinterpret_cast<void*>(slide + program.address);
        if (program.fileSize != 0) std::memcpy(destination, file.data() + program.offset, static_cast<std::size_t>(program.fileSize));
        if (program.memorySize > program.fileSize)
            std::memset(static_cast<std::uint8_t*>(destination) + program.fileSize, 0, static_cast<std::size_t>(program.memorySize - program.fileSize));
    }
    for (const auto& program : programs) {
        if (program.type != ProgramTls) continue;
        if (program.fileSize > program.memorySize || program.offset > file.size() || program.fileSize > file.size() - program.offset)
            throw std::runtime_error("Invalid PT_TLS range in " + path.string());
        tlsMemorySize = static_cast<std::size_t>(program.memorySize);
        tlsFileSize = static_cast<std::size_t>(program.fileSize);
        if (program.alignment > 1 && !std::has_single_bit(program.alignment))
            throw std::runtime_error("Invalid PT_TLS alignment in " + path.string());
        tlsAlignment = static_cast<std::size_t>(std::max<std::uint64_t>(16, program.alignment));
        tlsTemplate = reinterpret_cast<const void*>(slide + program.address);
        tlsModule = runtime.RegisterTls(*this);
    }
}

void ElfImage::ReadDynamic() {
    const auto found = std::find_if(programs.begin(), programs.end(), [](const auto& value) { return value.type == ProgramDynamic; });
    if (found == programs.end() || found->memorySize < sizeof(DynamicEntry)) throw std::runtime_error("Guest ELF has no dynamic table: " + path.string());
    if (!InImage(found->address, found->memorySize))
        throw std::runtime_error("Guest ELF dynamic table is outside the image: " + path.string());
    const auto* entries = reinterpret_cast<const DynamicEntry*>(slide + found->address);
    const auto count = static_cast<std::size_t>(found->memorySize / sizeof(DynamicEntry));
    bool terminated = false;
    for (std::size_t index = 0; index < count; ++index) {
        if (entries[index].tag == DynamicNull) { terminated = true; break; }
        dynamics.push_back(entries[index]);
    }
    if (!terminated) throw std::runtime_error("Unterminated guest ELF dynamic table: " + path.string());
    const auto stringAddress = DynamicValue(DynamicStringTable);
    stringsSize = static_cast<std::size_t>(DynamicValue(DynamicStringTableSize));
    if (!InImage(stringAddress, stringsSize))
        throw std::runtime_error("Guest ELF string table is outside the image: " + path.string());
    strings = reinterpret_cast<const char*>(slide + stringAddress);
    for (const auto offset : DynamicValues(DynamicNeeded)) neededNames.push_back(String(offset));
}

void ElfImage::ReadSymbols() {
    const auto symbolAddress = DynamicValue(DynamicSymbolTable);
    const auto entrySize = DynamicValue(DynamicSymbolEntrySize);
    if (entrySize != sizeof(Symbol) || !InImage(symbolAddress, sizeof(Symbol)))
        throw std::runtime_error("Invalid guest ELF symbol table: " + path.string());
    symbols = reinterpret_cast<const Symbol*>(slide + symbolAddress);
    const auto hashAddress = DynamicValue(DynamicHash);
    if (hashAddress != 0 && InImage(hashAddress, 8)) {
        const auto* words = reinterpret_cast<const std::uint32_t*>(slide + hashAddress);
        symbolCount = words[1];
    }
    if (symbolCount == 0 && header.sectionEntrySize == sizeof(SectionHeader)) {
        for (std::size_t index = 0; index < header.sectionCount; ++index) {
            const auto offset = header.sectionOffset + index * sizeof(SectionHeader);
            if (offset > std::numeric_limits<std::size_t>::max()) break;
            const auto section = Read<SectionHeader>(file, static_cast<std::size_t>(offset), "section header");
            if (section.type == SectionDynamicSymbols && section.entrySize == sizeof(Symbol)) {
                symbolCount = static_cast<std::size_t>(section.size / sizeof(Symbol));
                break;
            }
        }
    }
    if (symbolCount == 0) {
        const auto inspect = [&](std::uint64_t address, std::uint64_t bytes) {
            if (bytes % sizeof(Relocation) != 0 || !InImage(address, bytes)) return;
            const auto* values = reinterpret_cast<const Relocation*>(slide + address);
            for (std::size_t index = 0; index < bytes / sizeof(Relocation); ++index)
                symbolCount = std::max(symbolCount, static_cast<std::size_t>((values[index].info >> 32) + 1));
        };
        inspect(DynamicValue(DynamicRelocation), DynamicValue(DynamicRelocationSize));
        inspect(DynamicValue(DynamicPltRelocations), DynamicValue(DynamicPltRelocationSize));
    }
    if (symbolCount == 0 || symbolCount > (mappedEnd - reinterpret_cast<std::uintptr_t>(symbols)) / sizeof(Symbol))
        throw std::runtime_error("Cannot determine guest ELF symbol table size: " + path.string());
}

void ElfImage::LoadDependencies() {
    for (const auto& name : neededNames) {
        if (name == "ld-linux-x86-64.so.2") continue;
        if (name.find(".guest.prx") != std::string::npos || name.starts_with("$ORIGIN/")) {
            guestDependencies.push_back(&runtime.LoadGuest(runtime.ResolveGuestPath(*this, name)));
        } else {
            hostDependencies.push_back(runtime.LoadHost(name));
        }
    }
}

void ElfImage::Relocate() {
    if (relocated) return;
    for (auto* dependency : guestDependencies) dependency->Relocate();
    ApplyRelocations(DynamicValue(DynamicRelocation), DynamicValue(DynamicRelocationSize));
    ApplyRelocations(DynamicValue(DynamicPltRelocations), DynamicValue(DynamicPltRelocationSize));
    relocated = true;
    Protect();
}

void ElfImage::ApplyRelocations(std::uint64_t address, std::uint64_t bytes) {
    if (bytes == 0) return;
    const auto entrySize = DynamicValue(DynamicRelocationEntrySize);
    if (entrySize != 0 && entrySize != sizeof(Relocation)) throw std::runtime_error("Unsupported guest ELF relocation entry size");
    if (bytes % sizeof(Relocation) != 0 || !InImage(address, bytes))
        throw std::runtime_error("Guest ELF relocation table is outside the image: " + path.string());
    const auto* relocations = reinterpret_cast<const Relocation*>(slide + address);
    for (std::size_t index = 0; index < bytes / sizeof(Relocation); ++index) {
        const auto relocation = relocations[index];
        const auto type = static_cast<std::uint32_t>(relocation.info);
        const auto symbolIndex = static_cast<std::uint32_t>(relocation.info >> 32);
        const auto targetBytes = type == RelocationPc32 || type == Relocation32 || type == Relocation32Signed ? 4u : 8u;
        if (!InImage(relocation.offset, targetBytes))
            throw std::runtime_error("Guest ELF relocation target is outside the image: " + path.string());
        auto* target = reinterpret_cast<void*>(slide + relocation.offset);
        if (type == 0) continue;
        if (type == RelocationRelative) {
            Store(target, static_cast<std::uint64_t>(slide + relocation.addend));
            continue;
        }
        const auto& symbol = GetSymbol(symbolIndex);
        const bool weak = (symbol.info >> 4) == 2;
        if (type == RelocationDtpModule || type == RelocationDtpOffset || type == RelocationTpOffset) {
            std::optional<TlsSymbol> tls;
            if (symbolIndex == 0 || symbol.section != 0)
                tls = TlsSymbol{tlsModule, static_cast<std::int64_t>(tlsOffset), symbol.value};
            else
                tls = runtime.ResolveTls(*this, String(symbol.name), weak);
            if (!tls && !weak) throw std::runtime_error("Unresolved guest TLS symbol " + String(symbol.name));
            if (type == RelocationDtpModule) Store(target, tls ? tls->module : std::uint64_t{});
            else if (type == RelocationDtpOffset) Store(target, static_cast<std::uint64_t>((tls ? tls->value : 0) + relocation.addend));
            else Store(target, static_cast<std::uint64_t>((tls ? tls->tpOffset + static_cast<std::int64_t>(tls->value) : 0) + relocation.addend));
            continue;
        }
        const auto value = reinterpret_cast<std::uintptr_t>(Resolve(symbol, relocation.addend, weak));
        switch (type) {
        case Relocation64:
        case RelocationGlobDat:
        case RelocationJumpSlot:
            Store(target, static_cast<std::uint64_t>(value));
            break;
        case RelocationPc32: {
            const auto displacement = static_cast<std::int64_t>(value) - static_cast<std::int64_t>(reinterpret_cast<std::uintptr_t>(target));
            if (displacement < std::numeric_limits<std::int32_t>::min() || displacement > std::numeric_limits<std::int32_t>::max())
                throw std::runtime_error("Guest PC-relative relocation exceeds 32 bits: " + String(symbol.name));
            Store(target, static_cast<std::uint32_t>(displacement));
            break;
        }
        case Relocation32:
            if (value > std::numeric_limits<std::uint32_t>::max()) throw std::runtime_error("Guest relocation exceeds 32 bits: " + String(symbol.name));
            Store(target, static_cast<std::uint32_t>(value));
            break;
        case Relocation32Signed: {
            const auto signedValue = static_cast<std::int64_t>(value);
            if (signedValue < std::numeric_limits<std::int32_t>::min() || signedValue > std::numeric_limits<std::int32_t>::max())
                throw std::runtime_error("Guest signed relocation exceeds 32 bits: " + String(symbol.name));
            Store(target, static_cast<std::uint32_t>(signedValue));
            break;
        }
        default:
            throw std::runtime_error("Unsupported guest ELF relocation type " + std::to_string(type) + " in " + path.string());
        }
    }
}

void* ElfImage::Resolve(const Symbol& symbol, std::int64_t addend, bool allowUnresolved) const {
    const auto value = symbol.section != 0 ? slide + symbol.value :
        reinterpret_cast<std::uintptr_t>(runtime.Resolve(*this, String(symbol.name), allowUnresolved));
    if (value == 0 && allowUnresolved) return nullptr;
    return reinterpret_cast<void*>(value + addend);
}

void* ElfImage::FindExport(const std::string& name) const {
    for (std::size_t index = 1; index < symbolCount; ++index) {
        const auto& symbol = symbols[index];
        if (symbol.section == 0 || (symbol.info >> 4) == 0 || (symbol.info & 15) == 6 || (symbol.other & 3) != 0) continue;
        if (String(symbol.name) == name) return reinterpret_cast<void*>(slide + symbol.value);
    }
    return nullptr;
}

std::optional<TlsSymbol> ElfImage::FindTlsExport(const std::string& name) const {
    for (std::size_t index = 1; index < symbolCount; ++index) {
        const auto& symbol = symbols[index];
        if (symbol.section == 0 || (symbol.info >> 4) == 0 || (symbol.info & 15) != 6 || (symbol.other & 3) != 0) continue;
        if (String(symbol.name) == name) return TlsSymbol{tlsModule, static_cast<std::int64_t>(tlsOffset), symbol.value};
    }
    return std::nullopt;
}

bool ElfImage::Contains(std::uintptr_t address) const { return address >= mappedBegin && address < mappedEnd; }

bool ElfImage::InImage(std::uint64_t address, std::uint64_t bytes) const {
    if (address > std::numeric_limits<std::uintptr_t>::max() - slide) return false;
    const auto absolute = slide + static_cast<std::uintptr_t>(address);
    return absolute >= mappedBegin && absolute <= mappedEnd && bytes <= mappedEnd - absolute;
}

bool ElfImage::FillModuleInfo(std::uintptr_t address, KernelModule id, ModuleInfoEx& info) const {
    if (!Contains(address)) return false;
    ModuleInfoEx result{};
    result.st_size = sizeof(result);
    auto name = path.filename().string();
    static constexpr char guestSuffix[] = ".guest.prx";
    if (name.ends_with(guestSuffix)) name.resize(name.size() - (sizeof(guestSuffix) - 1));
    if (name.size() >= sizeof(result.name)) throw std::runtime_error("Guest module name exceeds the PS5 ABI field: " + name);
    std::memcpy(result.name, name.c_str(), name.size() + 1);
    result.id = id;
    if (tlsModule > std::numeric_limits<std::uint32_t>::max() || tlsFileSize > std::numeric_limits<std::uint32_t>::max() ||
        tlsMemorySize > std::numeric_limits<std::uint32_t>::max() || tlsAlignment > std::numeric_limits<std::uint32_t>::max())
        throw std::runtime_error("Guest module TLS metadata exceeds the PS5 ABI fields");
    result.tls_index = static_cast<std::uint32_t>(tlsModule);
    result.tls_init_addr = reinterpret_cast<std::uintptr_t>(tlsTemplate);
    result.tls_init_size = static_cast<std::uint32_t>(tlsFileSize);
    result.tls_size = static_cast<std::uint32_t>(tlsMemorySize);
    result.tls_offset = static_cast<std::uint32_t>(tlsOffset);
    result.tls_align = static_cast<std::uint32_t>(tlsAlignment);
    if (const auto init = DynamicValue(DynamicInit)) result.init_proc_addr = slide + init;
    if (const auto fini = DynamicValue(DynamicFini)) result.fini_proc_addr = slide + fini;
    for (const auto& program : programs) {
        if (program.type == ProgramGnuEhFrame) {
            if (program.memorySize > std::numeric_limits<std::uint32_t>::max()) throw std::runtime_error("Guest EH frame header exceeds the PS5 ABI size field");
            result.eh_frame_hdr_addr = slide + program.address;
            result.eh_frame_hdr_size = static_cast<std::uint32_t>(program.memorySize);
        }
        if (program.type != ProgramLoad || program.memorySize == 0) continue;
        if (result.segment_count == std::size(result.segments)) continue;
        if (program.memorySize > std::numeric_limits<std::uint32_t>::max()) throw std::runtime_error("Guest module segment exceeds the PS5 ABI size field");
        auto& segment = result.segments[result.segment_count++];
        segment.address = slide + program.address;
        segment.size = static_cast<std::uint32_t>(program.memorySize);
        segment.prot = ((program.flags & 4) ? 1 : 0) | ((program.flags & 2) ? 2 : 0) | ((program.flags & 1) ? 4 : 0);
    }
    if (header.sectionEntrySize == sizeof(SectionHeader) && header.sectionNames < header.sectionCount) {
        const auto namesOffset = header.sectionOffset + std::uint64_t{header.sectionNames} * sizeof(SectionHeader);
        if (namesOffset <= std::numeric_limits<std::size_t>::max()) {
            const auto names = Read<SectionHeader>(file, static_cast<std::size_t>(namesOffset), "section-name table");
            if (names.offset <= file.size() && names.size <= file.size() - names.offset) {
                for (std::size_t index = 0; index < header.sectionCount; ++index) {
                    const auto sectionOffset = header.sectionOffset + index * sizeof(SectionHeader);
                    if (sectionOffset > std::numeric_limits<std::size_t>::max()) break;
                    const auto section = Read<SectionHeader>(file, static_cast<std::size_t>(sectionOffset), "section header");
                    if (section.name >= names.size) continue;
                    const auto* sectionName = reinterpret_cast<const char*>(file.data() + names.offset + section.name);
                    const auto available = static_cast<std::size_t>(names.size - section.name);
                    const auto* end = static_cast<const char*>(std::memchr(sectionName, 0, available));
                    if (end && std::string_view(sectionName, static_cast<std::size_t>(end - sectionName)) == ".eh_frame") {
                        if (section.size > std::numeric_limits<std::uint32_t>::max()) throw std::runtime_error("Guest EH frame exceeds the PS5 ABI size field");
                        result.eh_frame_addr = slide + section.address;
                        result.eh_frame_size = static_cast<std::uint32_t>(section.size);
                        break;
                    }
                }
            }
        }
    }
    if (result.eh_frame_addr == 0 && result.eh_frame_hdr_addr != 0 && result.eh_frame_hdr_size >= 4) {
        const auto* ehHeader = reinterpret_cast<const std::uint8_t*>(result.eh_frame_hdr_addr);
        const auto* ehHeaderEnd = ehHeader + result.eh_frame_hdr_size;
        if (ehHeader[0] == 1) {
            std::uintptr_t textBase = 0;
            std::uintptr_t dataBase = 0;
            for (const auto& program : programs) {
                if (program.type != ProgramLoad || program.memorySize == 0) continue;
                if (!textBase && (program.flags & 1)) textBase = slide + program.address;
                if (!dataBase && (program.flags & 2)) dataBase = slide + program.address;
            }
            auto* cursor = ehHeader + 4;
            if (const auto ehFrame = DecodeEhPointer(cursor, ehHeaderEnd, ehHeader[1], textBase, dataBase);
                ehFrame && *ehFrame >= mappedBegin && *ehFrame < mappedEnd) {
                std::uintptr_t frameEnd = 0;
                for (const auto& program : programs) {
                    if (program.type != ProgramLoad || program.memorySize == 0 || program.address > std::numeric_limits<std::uintptr_t>::max() - slide)
                        continue;
                    const auto segmentBegin = slide + static_cast<std::uintptr_t>(program.address);
                    if (program.memorySize > std::numeric_limits<std::uintptr_t>::max() - segmentBegin) continue;
                    const auto segmentEnd = segmentBegin + static_cast<std::uintptr_t>(program.memorySize);
                    if (*ehFrame >= segmentBegin && *ehFrame < segmentEnd) {
                        frameEnd = segmentEnd;
                        break;
                    }
                }
                auto position = *ehFrame;
                while (frameEnd && position <= frameEnd && sizeof(std::uint32_t) <= frameEnd - position) {
                    std::uint32_t recordSize;
                    std::memcpy(&recordSize, reinterpret_cast<const void*>(position), sizeof(recordSize));
                    position += sizeof(recordSize);
                    if (recordSize == 0) {
                        const auto bytes = position - *ehFrame;
                        if (bytes <= std::numeric_limits<std::uint32_t>::max()) {
                            result.eh_frame_addr = *ehFrame;
                            result.eh_frame_size = static_cast<std::uint32_t>(bytes);
                        }
                        break;
                    }
                    std::uint64_t payloadSize = recordSize;
                    if (recordSize == std::numeric_limits<std::uint32_t>::max()) {
                        if (position > frameEnd || sizeof(std::uint64_t) > frameEnd - position) break;
                        std::memcpy(&payloadSize, reinterpret_cast<const void*>(position), sizeof(payloadSize));
                        position += sizeof(payloadSize);
                    }
                    if (position > frameEnd || payloadSize > frameEnd - position) break;
                    position += static_cast<std::uintptr_t>(payloadSize);
                }
            }
        }
    }
    result.ref_count = 1;
    info = result;
    return true;
}

void ElfImage::Protect() {
    const auto page = static_cast<std::size_t>(getpagesize());
    std::vector<int> protections(reservationSize / page);
    for (const auto& program : programs) {
        if (program.type != ProgramLoad || program.memorySize == 0) continue;
        const auto begin = AlignDown(slide + program.address, page);
        const auto end = AlignUp(slide + program.address + program.memorySize, page);
        for (auto current = begin; current < end; current += page) protections[(current - mappedBegin) / page] |= NativeProtection(program.flags);
    }
    for (std::size_t begin = 0; begin < protections.size();) {
        std::size_t end = begin + 1;
        while (end < protections.size() && protections[end] == protections[begin]) ++end;
        if (mprotect(reinterpret_cast<void*>(mappedBegin + begin * page), (end - begin) * page, protections[begin]) != 0)
            throw std::system_error(errno, std::generic_category(), "protect guest ELF pages");
        begin = end;
    }
    __builtin___clear_cache(reinterpret_cast<char*>(mappedBegin), reinterpret_cast<char*>(mappedEnd));
}

void ElfImage::Initialize() {
    if (initialized) return;
    for (auto* dependency : guestDependencies) dependency->Initialize();
    runtime.PrepareCurrentThread();
    initialized = true;
    using Initializer = void (*)();
    if (const auto value = DynamicValue(DynamicInit)) reinterpret_cast<Initializer>(slide + value)();
    const auto array = DynamicValue(DynamicInitArray);
    const auto arrayBytes = DynamicValue(DynamicInitArraySize);
    if (arrayBytes % sizeof(std::uintptr_t) != 0 || (arrayBytes && (array > std::numeric_limits<std::uintptr_t>::max() - slide || arrayBytes > mappedEnd - (slide + array))))
        throw std::runtime_error("Guest initializer array is outside the image: " + path.string());
    const auto* functions = reinterpret_cast<const std::uintptr_t*>(slide + array);
    for (std::size_t index = 0; index < arrayBytes / sizeof(std::uintptr_t); ++index)
        if (functions[index] != 0 && functions[index] != std::numeric_limits<std::uintptr_t>::max()) reinterpret_cast<Initializer>(functions[index])();
}

int ElfImage::Run(int argc, char** argv) {
    struct GuestThread {
        Runtime& runtime;
        explicit GuestThread(Runtime& runtime) : runtime(runtime) { runtime.EnterThread(); }
        ~GuestThread() { runtime.LeaveThread(); }
    } guestThread(runtime);
    Relocate();
    Initialize();
    auto entry = slide + header.entry;
    if (entry < mappedBegin || entry >= mappedEnd) throw std::runtime_error("Guest entry is outside the image: " + path.string());
    const auto* stub = reinterpret_cast<const std::uint8_t*>(entry);
    static constexpr std::uint8_t prefix[] = {0x48, 0x89, 0xe7, 0x48, 0x83, 0xe4, 0xf0, 0x48, 0x31, 0xf6, 0xe8};
    if (mappedEnd - entry >= sizeof(prefix) + 4 && std::memcmp(stub, prefix, sizeof(prefix)) == 0) {
        std::int32_t displacement;
        std::memcpy(&displacement, stub + sizeof(prefix), sizeof(displacement));
        entry += sizeof(prefix) + sizeof(displacement) + displacement;
    }
    std::vector<std::uintptr_t> stack;
    stack.reserve(static_cast<std::size_t>(argc) + 5);
    stack.push_back(static_cast<std::uintptr_t>(argc));
    for (int index = 0; index < argc; ++index) stack.push_back(reinterpret_cast<std::uintptr_t>(argv[index]));
    stack.insert(stack.end(), {0, 0, 0, 0});
    using Entry = void (*)(void*, void*);
    reinterpret_cast<Entry>(entry)(stack.data(), nullptr);
    return 0;
}

std::uint64_t ElfImage::DynamicValue(std::int64_t tag) const {
    const auto found = std::find_if(dynamics.begin(), dynamics.end(), [tag](const auto& value) { return value.tag == tag; });
    return found == dynamics.end() ? 0 : found->value;
}

std::vector<std::uint64_t> ElfImage::DynamicValues(std::int64_t tag) const {
    std::vector<std::uint64_t> result;
    for (const auto& value : dynamics) if (value.tag == tag) result.push_back(value.value);
    return result;
}

std::string ElfImage::String(std::uint64_t offset) const {
    if (offset >= stringsSize) throw std::runtime_error("Guest ELF string offset is out of range: " + path.string());
    const auto* end = static_cast<const char*>(std::memchr(strings + offset, 0, stringsSize - offset));
    if (!end) throw std::runtime_error("Guest ELF string is unterminated: " + path.string());
    return std::string(strings + offset, end);
}

const Symbol& ElfImage::GetSymbol(std::size_t index) const {
    if (index >= symbolCount) throw std::runtime_error("Guest ELF symbol index is out of range: " + path.string());
    return symbols[index];
}

Runtime::Runtime(std::filesystem::path executable) : executable(std::filesystem::weakly_canonical(std::move(executable))) {
    if (const char* configured = std::getenv("ANYPS5_LIBS")) libraries = configured;
    else libraries = this->executable.parent_path() / "libs";
    activeRuntime = this;
}

ElfImage& Runtime::LoadMain() { return LoadGuest(executable); }

ElfImage& Runtime::LoadGuest(const std::filesystem::path& path) {
    std::lock_guard lock(mutex);
    const auto canonical = std::filesystem::weakly_canonical(path);
    if (const auto found = guests.find(canonical); found != guests.end()) return *found->second;
    auto image = std::make_unique<ElfImage>(*this, canonical, canonical == executable);
    auto* result = image.get();
    guests.emplace(canonical, std::move(image));
    guestIds.emplace(result, nextGuestId++);
    result->LoadDependencies();
    return *result;
}

void Runtime::EnsureLibc() {
    if (hosts.contains("libc.prx")) return;
    if (std::filesystem::exists(libraries / "libc.prx")) LoadHost("libc.prx");
}

void* Runtime::LoadHost(const std::string& name) {
    if (const auto found = hosts.find(name); found != hosts.end()) return found->second;
    if (name != "libc.prx") EnsureLibc();
    auto candidate = std::filesystem::path(name);
    if (!candidate.is_absolute()) candidate = libraries / candidate;
    const auto absolute = std::filesystem::absolute(candidate).string();
    dlerror();
    void* handle = dlopen(absolute.c_str(), RTLD_NOW | RTLD_GLOBAL);
    if (!handle) {
        const char* error = dlerror();
        throw std::runtime_error("Cannot load host library " + absolute + ": " + (error ? error : "unknown dyld error"));
    }
    hosts.emplace(name, handle);
    std::cout << "Host module: " << absolute << '\n';
    return handle;
}

void* Runtime::Resolve(const ElfImage& requester, const std::string& name, bool weak) const {
    if (name == "__tls_get_addr") return reinterpret_cast<void*>(&AnyPs5TlsGetAddr);
    const auto key = std::make_pair(&requester, name);
    if (!resolving.insert(key).second) return nullptr;
    struct Erase {
        std::set<std::pair<const ElfImage*, std::string>>& values;
        std::pair<const ElfImage*, std::string> key;
        ~Erase() { values.erase(key); }
    } erase{resolving, key};
    const auto traced = [&](void* value, const char* source) {
        if (TraceLoader()) std::cerr << "Resolve " << name << " from " << source << " -> " << value << '\n';
        return value;
    };
    if (void* value = requester.FindExport(name)) return traced(value, "requester");
    for (const auto& [file, image] : guests) if (image.get() != &requester) if (void* value = image->FindExport(name)) return traced(value, "guest");
    for (const auto& [library, handle] : hosts) if (void* value = dlsym(handle, name.c_str())) return traced(value, library.c_str());
    if (void* value = dlsym(RTLD_DEFAULT, name.c_str())) return traced(value, "process");
    if (weak) return nullptr;
    throw std::runtime_error("Unresolved guest symbol " + name + " required by " + requester.Path().string());
}

std::optional<TlsSymbol> Runtime::ResolveTls(const ElfImage& requester, const std::string& name, bool weak) const {
    if (auto value = requester.FindTlsExport(name)) return value;
    for (const auto& [file, image] : guests)
        if (image.get() != &requester) if (auto value = image->FindTlsExport(name)) return value;
    if (weak) return std::nullopt;
    throw std::runtime_error("Unresolved guest TLS symbol " + name + " required by " + requester.Path().string());
}

std::filesystem::path Runtime::ResolveGuestPath(const ElfImage& requester, const std::string& name) const {
    static constexpr char origin[] = "$ORIGIN";
    if (name.starts_with(origin)) return requester.Path().parent_path() / name.substr(sizeof(origin));
    const auto candidate = std::filesystem::path(name);
    return candidate.is_absolute() ? candidate : requester.Path().parent_path() / candidate;
}

std::uint64_t Runtime::RegisterTls(ElfImage& image) {
    std::lock_guard lock(mutex);
    const auto alignment = std::max<std::size_t>(1, image.TlsAlignment());
    if (image.TlsMemorySize() > StaticTlsCapacity - tlsBytes) throw std::runtime_error("Guest static TLS exceeds the macOS runner capacity");
    tlsBytes = static_cast<std::size_t>(AlignUp(tlsBytes + image.TlsMemorySize(), alignment));
    if (tlsBytes > StaticTlsCapacity) throw std::runtime_error("Guest static TLS exceeds the macOS runner capacity");
    const auto offset = static_cast<std::uint64_t>(-static_cast<std::int64_t>(tlsBytes));
    const auto module = tlsImages.size();
    tlsImages.push_back(&image);
    image.AssignTls(module, offset);
    return module;
}

void* Runtime::TlsAddress(std::uint64_t module, std::uint64_t offset) {
    std::lock_guard lock(mutex);
    if (module == 0 || module >= tlsImages.size()) return nullptr;
    PrepareCurrentThread();
    const auto& state = *threadTls.at(this);
    const auto* image = tlsImages[module];
    if (offset > image->TlsMemorySize()) return nullptr;
    return reinterpret_cast<void*>(state.threadPointer + static_cast<std::int64_t>(image->TlsOffset()) + offset);
}

void Runtime::EnterThread() {
    std::lock_guard lock(mutex);
    auto& holder = threadTls[this];
    if (!holder) {
        holder = std::make_unique<ThreadTlsState>();
        auto& state = *holder;
        const auto page = static_cast<std::size_t>(getpagesize());
        state.reservationSize = StaticTlsCapacity + page;
        state.reservation = mmap(nullptr, state.reservationSize, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
        if (state.reservation == MAP_FAILED) {
            state.reservation = nullptr;
            throw std::system_error(errno, std::generic_category(), "reserve guest thread TLS");
        }
        state.threadPointer = reinterpret_cast<std::uintptr_t>(state.reservation) + StaticTlsCapacity;
        Store(reinterpret_cast<void*>(state.threadPointer), state.threadPointer);
        Store(reinterpret_cast<void*>(state.threadPointer + 0x28), StackGuard);
    }
    auto& state = *holder;
    if (state.depth++ == 0) {
        state.previousBase = pthread_getspecific(static_cast<pthread_key_t>(GuestTlsBaseSlot));
        state.previousGuard = pthread_getspecific(static_cast<pthread_key_t>(GuestStackGuardSlot));
        if (_pthread_setspecific_static(GuestTlsBaseSlot, reinterpret_cast<void*>(state.threadPointer)) != 0 ||
            _pthread_setspecific_static(GuestStackGuardSlot, reinterpret_cast<void*>(StackGuard)) != 0)
            throw std::runtime_error("Cannot install macOS guest TLS slots");
    }
    PrepareCurrentThread();
}

void Runtime::LeaveThread() {
    std::lock_guard lock(mutex);
    const auto found = threadTls.find(this);
    if (found == threadTls.end() || found->second->depth == 0) return;
    auto& state = *found->second;
    if (--state.depth == 0) {
        _pthread_setspecific_static(GuestTlsBaseSlot, state.previousBase);
        _pthread_setspecific_static(GuestStackGuardSlot, state.previousGuard);
    }
}

void Runtime::PrepareCurrentThread() {
    auto found = threadTls.find(this);
    if (found == threadTls.end() || !found->second || found->second->depth == 0) {
        EnterThread();
        found = threadTls.find(this);
    }
    auto& state = *found->second;
    if (state.initialized.size() < tlsImages.size()) state.initialized.resize(tlsImages.size());
    for (std::size_t module = 1; module < tlsImages.size(); ++module) {
        if (state.initialized[module]) continue;
        const auto* image = tlsImages[module];
        auto* destination = reinterpret_cast<void*>(state.threadPointer + static_cast<std::int64_t>(image->TlsOffset()));
        if (image->TlsFileSize() != 0) std::memcpy(destination, image->TlsTemplate(), image->TlsFileSize());
        state.initialized[module] = true;
    }
}

void* Runtime::OpenGuest(const std::filesystem::path& path) {
    auto& image = LoadGuest(path);
    image.Relocate();
    PrepareCurrentThread();
    image.Initialize();
    return &image;
}

void* Runtime::GuestSymbol(void* handle, const std::string& name) const {
    std::lock_guard lock(mutex);
    const auto* requested = static_cast<const ElfImage*>(handle);
    for (const auto& [path, image] : guests) {
        if (image.get() == requested) {
            if (auto* value = image->FindExport(name)) return value;
            if (auto tls = image->FindTlsExport(name)) return const_cast<Runtime*>(this)->TlsAddress(tls->module, tls->value);
            return nullptr;
        }
    }
    return nullptr;
}

int Runtime::CloseGuest(void* handle) const {
    std::lock_guard lock(mutex);
    const auto* requested = static_cast<const ElfImage*>(handle);
    return std::any_of(guests.begin(), guests.end(), [requested](const auto& entry) { return entry.second.get() == requested; }) ? 0 : -1;
}

bool Runtime::ModuleInfo(std::uintptr_t address, ModuleInfoEx& info) const {
    std::lock_guard lock(mutex);
    for (const auto& [path, image] : guests) {
        if (image->FillModuleInfo(address, guestIds.at(image.get()), info)) return true;
    }
    return false;
}

}
