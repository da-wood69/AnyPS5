#ifndef ANYPS5_MACOS_ELFLOADER_HPP
#define ANYPS5_MACOS_ELFLOADER_HPP

#include "ElfTypes.hpp"
#include "SceTypes.hpp"
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <string>
#include <vector>

namespace MacRuntime {

class Runtime;

struct TlsSymbol {
    std::uint64_t module;
    std::int64_t tpOffset;
    std::uint64_t value;
};

using GuestSegmentVisitor = bool (*)(std::uintptr_t address, std::size_t bytes, bool readable, bool writable, void* context);

class ElfImage {
public:
    ElfImage(Runtime& runtime, std::filesystem::path path, bool mainImage);
    ~ElfImage();
    ElfImage(const ElfImage&) = delete;
    ElfImage& operator=(const ElfImage&) = delete;
    void LoadDependencies();
    void Relocate();
    void Initialize();
    void* FindExport(const std::string& name) const;
    std::optional<TlsSymbol> FindTlsExport(const std::string& name) const;
    bool Contains(std::uintptr_t address) const;
    const void* ProcessParameters() const;
    const std::filesystem::path& Path() const { return path; }
    std::uint64_t TlsModule() const { return tlsModule; }
    std::uint64_t TlsOffset() const { return tlsOffset; }
    std::size_t TlsMemorySize() const { return tlsMemorySize; }
    std::size_t TlsFileSize() const { return tlsFileSize; }
    std::size_t TlsAlignment() const { return tlsAlignment; }
    const void* TlsTemplate() const { return tlsTemplate; }
    std::uintptr_t Slide() const { return slide; }
    const std::vector<ProgramHeader>& ProgramHeaders() const { return programs; }
    void AssignTls(std::uint64_t module, std::uint64_t offset) { tlsModule = module; tlsOffset = offset; }
    bool FillModuleInfo(std::uintptr_t address, KernelModule id, ModuleInfoEx& info) const;
    int Run(int argc, char** argv);

private:
    Runtime& runtime;
    std::filesystem::path path;
    bool mainImage;
    std::vector<std::uint8_t> file;
    ElfHeader header{};
    std::vector<ProgramHeader> programs;
    std::vector<DynamicEntry> dynamics;
    std::vector<std::string> neededNames;
    std::vector<ElfImage*> guestDependencies;
    std::vector<void*> hostDependencies;
    void* reservation = nullptr;
    std::size_t reservationSize = 0;
    std::uintptr_t mappedBegin = 0;
    std::uintptr_t mappedEnd = 0;
    std::uintptr_t slide = 0;
    const char* strings = nullptr;
    std::size_t stringsSize = 0;
    const Symbol* symbols = nullptr;
    std::size_t symbolCount = 0;
    std::uint64_t tlsModule = 0;
    std::uint64_t tlsOffset = 0;
    std::size_t tlsMemorySize = 0;
    std::size_t tlsFileSize = 0;
    std::size_t tlsAlignment = 1;
    const void* tlsTemplate = nullptr;
    bool relocated = false;
    bool initialized = false;
    void ReadFile();
    void Map();
    void ReadDynamic();
    void ReadSymbols();
    void ApplyRelocations(std::uint64_t address, std::uint64_t bytes);
    void* Resolve(const Symbol& symbol, std::int64_t addend, bool allowUnresolved) const;
    std::uint64_t DynamicValue(std::int64_t tag) const;
    std::vector<std::uint64_t> DynamicValues(std::int64_t tag) const;
    std::string String(std::uint64_t offset) const;
    const Symbol& GetSymbol(std::size_t index) const;
    void Protect();
    bool InImage(std::uint64_t address, std::uint64_t bytes) const;
};

class Runtime {
public:
    explicit Runtime(std::filesystem::path executable);
    ElfImage& LoadMain();
    ElfImage& LoadGuest(const std::filesystem::path& path);
    void* LoadHost(const std::string& name);
    void* Resolve(const ElfImage& requester, const std::string& name, bool weak) const;
    std::optional<TlsSymbol> ResolveTls(const ElfImage& requester, const std::string& name, bool weak) const;
    std::filesystem::path ResolveGuestPath(const ElfImage& requester, const std::string& name) const;
    std::uint64_t RegisterTls(ElfImage& image);
    void* TlsAddress(std::uint64_t module, std::uint64_t offset);
    void* OpenGuest(const std::filesystem::path& path);
    void* GuestSymbol(void* handle, const std::string& name) const;
    int CloseGuest(void* handle) const;
    bool ModuleInfo(std::uintptr_t address, ModuleInfoEx& info) const;
    const void* ProcessParameters() const;
    bool VisitMainImageSegments(GuestSegmentVisitor visitor, void* context) const;
    void EnterThread();
    void LeaveThread();
    void PrepareCurrentThread();

private:
    std::filesystem::path executable;
    std::filesystem::path libraries;
    std::map<std::filesystem::path, std::unique_ptr<ElfImage>> guests;
    std::map<std::string, void*> hosts;
    std::vector<ElfImage*> tlsImages{nullptr};
    std::size_t tlsBytes = 0;
    mutable std::recursive_mutex mutex;
    std::map<const ElfImage*, KernelModule> guestIds;
    KernelModule nextGuestId = 0x30000000;
    mutable std::set<std::pair<const ElfImage*, std::string>> resolving;
    void EnsureLibc();
};

}

#endif
