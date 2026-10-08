#include "prx/libc/include/exceptions/Unwind.hpp"
#include "prx/libc/include/specifics/linux/ElfTypes.hpp"
#include "prx/libc/src/specifics/x86_64/RegisterContext.cpp"
#include <limits>

#ifdef _WIN32
#include <windows.h>
#elif defined(__APPLE__)
#include "SceTypes.hpp"
#include <dlfcn.h>
#include <mach-o/compact_unwind_encoding.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <mach/vm_prot.h>
#endif

#if defined(__linux__) || defined(_WIN32) || defined(__APPLE__)

extern "C" _Unwind_Reason_Code __gxx_personality_v0(int, _Unwind_Action, std::uint64_t, _Unwind_Exception*, _Unwind_Context*);
extern "C" _Unwind_Reason_Code __gcc_personality_v0(int, _Unwind_Action, std::uint64_t, _Unwind_Exception*, _Unwind_Context*);
extern "C" _Unwind_Reason_Code LibcGccPersonality(int, _Unwind_Action, std::uint64_t, _Unwind_Exception*, _Unwind_Context*);

namespace LibcUnwind {
_Unwind_Reason_Code CallPersonality(Word personality, _Unwind_Action actions, _Unwind_Exception* exception, _Unwind_Context* context) {
#ifdef _WIN32
    const auto* code = reinterpret_cast<const Byte*>(personality);
    if (code[0] == 0xff && code[1] == 0x25) {
        std::int32_t displacement;
        std::memcpy(&displacement, code + 2, 4);
        std::memcpy(&personality, code + 6 + displacement, sizeof(personality));
    }
#endif

    if (personality == reinterpret_cast<Word>(__gxx_personality_v0_nid_postfix) || personality == reinterpret_cast<Word>(__gxx_personality_v0))
        return __gxx_personality_v0_nid_postfix(1, actions, exception->exception_class, exception, context);
    if (personality == reinterpret_cast<Word>(__gcc_personality_v0))
        return LibcGccPersonality(1, actions, exception->exception_class, exception, context);
    return (actions & _UA_SEARCH_PHASE) ? _URC_FATAL_PHASE1_ERROR : _URC_FATAL_PHASE2_ERROR;
}
struct Lookup { Word pc; const Byte* fde {}; Word text {}; Word data {}; };

#ifdef __APPLE__
struct AppleFrameRange {
    const Byte* ehBegin{};
    const Byte* ehEnd{};
    const Byte* compactBegin{};
    const Byte* compactEnd{};
    Word imageBase{};
    Word text{};
    Word data{};
};

bool FindAppleFrameRange(Word pc, AppleFrameRange& range) {
    using GuestModuleInfo = int (*)(std::uint64_t, ModuleInfoEx*);
    static const auto guestModuleInfo = reinterpret_cast<GuestModuleInfo>(dlsym(RTLD_DEFAULT, "AnyPs5GuestModuleInfo"));
    if (guestModuleInfo) {
        ModuleInfoEx info{};
        info.st_size = sizeof(info);
        if (guestModuleInfo(pc, &info) == 0 && info.eh_frame_addr != 0 && info.eh_frame_size != 0) {
            range.ehBegin = reinterpret_cast<const Byte*>(info.eh_frame_addr);
            range.ehEnd = range.ehBegin + info.eh_frame_size;
            for (std::size_t index = 0; index < info.segment_count; ++index) {
                if ((info.segments[index].prot & 4) != 0 && range.text == 0) range.text = info.segments[index].address;
                if ((info.segments[index].prot & 2) != 0 && range.data == 0) range.data = info.segments[index].address;
            }
            return true;
        }
    }
    for (std::uint32_t imageIndex = 0; imageIndex < _dyld_image_count(); ++imageIndex) {
        const auto* header = reinterpret_cast<const mach_header_64*>(_dyld_get_image_header(imageIndex));
        if (!header || header->magic != MH_MAGIC_64) continue;
        range.imageBase = reinterpret_cast<Word>(header);
        const auto slide = _dyld_get_image_vmaddr_slide(imageIndex);
        bool contains = false;
        auto* command = reinterpret_cast<const load_command*>(reinterpret_cast<const Byte*>(header) + sizeof(*header));
        for (std::uint32_t commandIndex = 0; commandIndex < header->ncmds; ++commandIndex) {
            if (command->cmd == LC_SEGMENT_64 && command->cmdsize >= sizeof(segment_command_64)) {
                const auto* segment = reinterpret_cast<const segment_command_64*>(command);
                const auto address = static_cast<Word>(static_cast<std::intptr_t>(segment->vmaddr) + slide);
                if (segment->vmsize != 0 && pc >= address && pc - address < segment->vmsize) contains = true;
            }
            command = reinterpret_cast<const load_command*>(reinterpret_cast<const Byte*>(command) + command->cmdsize);
        }
        if (!contains) continue;
        command = reinterpret_cast<const load_command*>(reinterpret_cast<const Byte*>(header) + sizeof(*header));
        for (std::uint32_t commandIndex = 0; commandIndex < header->ncmds; ++commandIndex) {
            if (command->cmd == LC_SEGMENT_64 && command->cmdsize >= sizeof(segment_command_64)) {
                const auto* segment = reinterpret_cast<const segment_command_64*>(command);
                const auto address = static_cast<Word>(static_cast<std::intptr_t>(segment->vmaddr) + slide);
                if ((segment->initprot & VM_PROT_EXECUTE) != 0 && range.text == 0) range.text = address;
                if ((segment->initprot & VM_PROT_WRITE) != 0 && range.data == 0) range.data = address;
                const auto sectionBytes = static_cast<std::uint64_t>(segment->nsects) * sizeof(section_64);
                if (sizeof(*segment) + sectionBytes <= command->cmdsize) {
                    const auto* sections = reinterpret_cast<const section_64*>(segment + 1);
                    for (std::uint32_t sectionIndex = 0; sectionIndex < segment->nsects; ++sectionIndex) {
                        const auto section = reinterpret_cast<const Byte*>(static_cast<std::intptr_t>(sections[sectionIndex].addr) + slide);
                        if (std::strncmp(sections[sectionIndex].sectname, "__eh_frame", sizeof(sections[sectionIndex].sectname)) == 0) {
                            range.ehBegin = section;
                            range.ehEnd = section + sections[sectionIndex].size;
                        } else if (std::strncmp(sections[sectionIndex].sectname, "__unwind_info", sizeof(sections[sectionIndex].sectname)) == 0) {
                            range.compactBegin = section;
                            range.compactEnd = section + sections[sectionIndex].size;
                        }
                    }
                }
            }
            command = reinterpret_cast<const load_command*>(reinterpret_cast<const Byte*>(command) + command->cmdsize);
        }
        return (range.ehBegin != nullptr && range.ehEnd > range.ehBegin) ||
            (range.compactBegin != nullptr && range.compactEnd > range.compactBegin);
    }
    return false;
}

struct AppleCompactInfo {
    std::uint32_t encoding{};
    Word functionStart{};
    Word personality{};
    Word lsda{};
};

template<class T>
const T* AppleTable(const AppleFrameRange& range, std::uint32_t offset, std::size_t count = 1) {
    if (!range.compactBegin || range.compactEnd < range.compactBegin ||
        offset > static_cast<std::size_t>(range.compactEnd - range.compactBegin) ||
        count > (static_cast<std::size_t>(range.compactEnd - range.compactBegin) - offset) / sizeof(T)) return nullptr;
    return reinterpret_cast<const T*>(range.compactBegin + offset);
}

bool FindAppleCompact(Word pc, const AppleFrameRange& range, AppleCompactInfo& result) {
    if (!range.compactBegin || range.imageBase == 0 || pc < range.imageBase || pc - range.imageBase > std::numeric_limits<std::uint32_t>::max()) return false;
    const auto* header = AppleTable<unwind_info_section_header>(range, 0);
    if (!header || header->version != UNWIND_SECTION_VERSION || header->indexCount < 2) return false;
    const auto* indexes = AppleTable<unwind_info_section_header_index_entry>(range, header->indexSectionOffset, header->indexCount);
    if (!indexes) return false;
    const auto target = static_cast<std::uint32_t>(pc - range.imageBase);
    std::uint32_t first = 0;
    std::uint32_t last = header->indexCount - 1;
    while (first + 1 < last) {
        const auto middle = first + (last - first) / 2;
        if (indexes[middle].functionOffset <= target) first = middle;
        else last = middle;
    }
    if (indexes[first].functionOffset > target || indexes[first].secondLevelPagesSectionOffset == 0) return false;
    const auto pageOffset = indexes[first].secondLevelPagesSectionOffset;
    const auto* kind = AppleTable<std::uint32_t>(range, pageOffset);
    if (!kind) return false;
    std::uint32_t encoding = 0;
    std::uint32_t functionOffset = 0;
    if (*kind == UNWIND_SECOND_LEVEL_REGULAR) {
        const auto* page = AppleTable<unwind_info_regular_second_level_page_header>(range, pageOffset);
        if (!page || page->entryCount == 0 || pageOffset > std::numeric_limits<std::uint32_t>::max() - page->entryPageOffset) return false;
        const auto* entries = AppleTable<unwind_info_regular_second_level_entry>(range, pageOffset + page->entryPageOffset, page->entryCount);
        if (!entries || entries[0].functionOffset > target) return false;
        std::uint32_t low = 0;
        std::uint32_t high = page->entryCount;
        while (low + 1 < high) {
            const auto middle = low + (high - low) / 2;
            if (entries[middle].functionOffset <= target) low = middle;
            else high = middle;
        }
        encoding = entries[low].encoding;
        functionOffset = entries[low].functionOffset;
        if ((encoding & UNWIND_IS_NOT_FUNCTION_START) != 0) {
            if (low == 0) return false;
            do --low; while (low != 0 && (entries[low].encoding & UNWIND_IS_NOT_FUNCTION_START) != 0);
            functionOffset = entries[low].functionOffset;
        }
    } else if (*kind == UNWIND_SECOND_LEVEL_COMPRESSED) {
        const auto* page = AppleTable<unwind_info_compressed_second_level_page_header>(range, pageOffset);
        if (!page || page->entryCount == 0 || pageOffset > std::numeric_limits<std::uint32_t>::max() - page->entryPageOffset) return false;
        const auto* entries = AppleTable<std::uint32_t>(range, pageOffset + page->entryPageOffset, page->entryCount);
        if (!entries || target < indexes[first].functionOffset) return false;
        const auto pageTarget = target - indexes[first].functionOffset;
        if (UNWIND_INFO_COMPRESSED_ENTRY_FUNC_OFFSET(entries[0]) > pageTarget) return false;
        std::uint32_t low = 0;
        std::uint32_t high = page->entryCount;
        while (low + 1 < high) {
            const auto middle = low + (high - low) / 2;
            if (UNWIND_INFO_COMPRESSED_ENTRY_FUNC_OFFSET(entries[middle]) <= pageTarget) low = middle;
            else high = middle;
        }
        const auto encodingAt = [&](std::uint32_t index, std::uint32_t& output) {
            const auto encodingIndex = UNWIND_INFO_COMPRESSED_ENTRY_ENCODING_INDEX(entries[index]);
            if (encodingIndex < header->commonEncodingsArrayCount) {
                const auto* common = AppleTable<std::uint32_t>(range, header->commonEncodingsArraySectionOffset, header->commonEncodingsArrayCount);
                if (!common) return false;
                output = common[encodingIndex];
                return true;
            }
            const auto localIndex = encodingIndex - header->commonEncodingsArrayCount;
            if (localIndex >= page->encodingsCount || pageOffset > std::numeric_limits<std::uint32_t>::max() - page->encodingsPageOffset) return false;
            const auto* local = AppleTable<std::uint32_t>(range, pageOffset + page->encodingsPageOffset, page->encodingsCount);
            if (!local) return false;
            output = local[localIndex];
            return true;
        };
        if (!encodingAt(low, encoding)) return false;
        functionOffset = indexes[first].functionOffset + UNWIND_INFO_COMPRESSED_ENTRY_FUNC_OFFSET(entries[low]);
        if ((encoding & UNWIND_IS_NOT_FUNCTION_START) != 0) {
            if (low == 0) return false;
            std::uint32_t previousEncoding = 0;
            do {
                --low;
                if (!encodingAt(low, previousEncoding)) return false;
            } while (low != 0 && (previousEncoding & UNWIND_IS_NOT_FUNCTION_START) != 0);
            functionOffset = indexes[first].functionOffset + UNWIND_INFO_COMPRESSED_ENTRY_FUNC_OFFSET(entries[low]);
        }
    } else return false;
    result.encoding = encoding;
    result.functionStart = range.imageBase + functionOffset;
    if ((encoding & UNWIND_HAS_LSDA) != 0) {
        const auto begin = indexes[first].lsdaIndexArraySectionOffset;
        const auto end = indexes[first + 1].lsdaIndexArraySectionOffset;
        if (end < begin || (end - begin) % sizeof(unwind_info_section_header_lsda_index_entry) != 0) return false;
        const auto count = (end - begin) / sizeof(unwind_info_section_header_lsda_index_entry);
        const auto* entries = AppleTable<unwind_info_section_header_lsda_index_entry>(range, begin, count);
        if (!entries) return false;
        std::uint32_t low = 0;
        std::uint32_t high = count;
        while (low < high) {
            const auto middle = low + (high - low) / 2;
            if (entries[middle].functionOffset < functionOffset) low = middle + 1;
            else high = middle;
        }
        if (low >= count || entries[low].functionOffset != functionOffset) return false;
        result.lsda = range.imageBase + entries[low].lsdaOffset;
    }
    auto personality = (encoding & UNWIND_PERSONALITY_MASK) >> 28;
    if (personality != 0) {
        --personality;
        if (personality >= header->personalityArrayCount) return false;
        const auto* deltas = AppleTable<std::int32_t>(range, header->personalityArraySectionOffset, header->personalityArrayCount);
        if (!deltas) return false;
        const auto pointer = static_cast<Word>(static_cast<std::intptr_t>(range.imageBase) + deltas[personality]);
        std::memcpy(&result.personality, reinterpret_cast<const void*>(pointer), sizeof(result.personality));
    }
    return true;
}
#endif

#ifdef __linux__
int FindFrame(dl_phdr_info* info, std::size_t, void* argument) {
    auto& query = *static_cast<Lookup*>(argument);
    const Byte* header = nullptr;
    bool contains = false;
    for (unsigned i = 0; i < info->dlpi_phnum; ++i) {
        const auto& ph = info->dlpi_phdr[i];
        Word start = info->dlpi_addr + ph.p_vaddr;
        if (ph.p_type == PT_LOAD && query.pc >= start && query.pc - start < ph.p_memsz) contains = true;
        if (ph.p_type == PT_GNU_EH_FRAME) header = reinterpret_cast<const Byte*>(start);
        if (ph.p_type == PT_LOAD && (ph.p_flags & PF_X)) query.text = start;
        if (ph.p_type == PT_LOAD && (ph.p_flags & PF_W)) query.data = start;
    }
    if (!contains || !header || header[0] != 1) return 0;
    const Byte* p = header + 4;
    Encoded(p, header[1], Word(header));
    Word count = Encoded(p, header[2]);
    if (header[3] == 255) return 1;
    unsigned width = EncodingSize(header[3]);
    const Byte* table = p;
    Word lo = 0, hi = count;
    while (lo < hi) {
        Word mid = lo + (hi - lo) / 2;
        p = table + mid * width * 2;
        Word begin = Encoded(p, header[3], Word(header));
        if (begin <= query.pc) lo = mid + 1; else hi = mid;
    }
    if (lo) {
        p = table + (lo - 1) * width * 2 + width;
        query.fde = reinterpret_cast<const Byte*>(Encoded(p, header[3], Word(header)));
    }
    return 1;
}

#endif

struct Frame {
    const Byte* cieBegin {};
    const Byte* cieEnd {};
    const Byte* begin {};
    const Byte* end {};
    Word start {}, length {}, personality {}, lsda {};
    Word codeAlign {};
    std::intptr_t dataAlign {};
    unsigned returnRegister {};
    bool signal {};
#ifdef __APPLE__
    std::uint32_t compactEncoding {};
    Word compactFunctionStart {};
#endif
};

bool DecodeCandidate(_Unwind_Context& context, Frame& frame, const Lookup& query) {
    if (!query.fde) return false;
    const Byte* p = query.fde;
    auto length = Read<std::uint32_t>(p);
    if (!length || length == 0xffffffff) return false;
    frame.end = p + length;
    const Byte* ciePointer = p;
    auto cieOffset = Read<std::uint32_t>(p);
    const Byte* cie = ciePointer - cieOffset;
    const Byte* c = cie;
    auto cieLength = Read<std::uint32_t>(c);
    frame.cieEnd = c + cieLength;
    if (Read<std::uint32_t>(c) != 0) return false;
    Byte version = *c++;
    if (version != 1 && version != 3 && version != 4) return false;
    const char* augmentation = reinterpret_cast<const char*>(c);
    while (*c++) {}
    if (version == 4 && (*c++ != sizeof(Word) || *c++ != 0)) return false;
    frame.codeAlign = Uleb(c);
    frame.dataAlign = Sleb(c);
    frame.returnRegister = version == 1 ? *c++ : Uleb(c);
#ifdef _WIN32
    if (frame.returnRegister >= 17 && frame.returnRegister != 32) return false;
#else
    if (frame.returnRegister >= 17) return false;
#endif
    Byte pointerEncoding = 0, lsdaEncoding = 255;
    if (*augmentation == 'z') {
        Word size = Uleb(c);
        const Byte* end = c + size;
        for (const char* a = augmentation + 1; *a; ++a) {
            switch (*a) {
            case 'R': pointerEncoding = *c++; break;
            case 'L': lsdaEncoding = *c++; break;
            case 'P': { Byte encoding = *c++; frame.personality = Encoded(c, encoding, query.data, 0, query.text); break; }
            case 'S': frame.signal = true; break;
            default: return false;
            }
        }
        c = end;
    } else if (*augmentation) return false;
    frame.cieBegin = c;
    frame.start = Encoded(p, pointerEncoding, query.data, 0, query.text);
    frame.length = Encoded(p, pointerEncoding & 15);
    if (query.pc < frame.start || query.pc - frame.start >= frame.length) return false;
    if (*augmentation == 'z') {
        Word size = Uleb(p);
        const Byte* end = p + size;
        if (lsdaEncoding != 255) frame.lsda = Encoded(p, lsdaEncoding, query.data, frame.start, query.text);
        p = end;
    }
    frame.begin = p;
    context.region = frame.start;
    context.lsda = frame.lsda;
    context.personality = frame.personality;
    context.textBase = query.text;
    context.dataBase = query.data;
    return true;
}

bool DecodeFrame(_Unwind_Context& context, Frame& frame) {
    Lookup query {context.registers[16] - !context.signalFrame};
#ifdef __linux__
    dl_iterate_phdr(FindFrame, &query);
    return DecodeCandidate(context, frame, query);
#elif defined(_WIN32)
    MEMORY_BASIC_INFORMATION memory{};
    if (!VirtualQuery(reinterpret_cast<void*>(query.pc), &memory, sizeof(memory)) || memory.Type != MEM_IMAGE)
        return false;
    const auto* base = static_cast<const Byte*>(memory.AllocationBase);
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;
    const auto* sections = IMAGE_FIRST_SECTION(nt);
    for (unsigned i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        const auto& section = sections[i];
        if (std::memcmp(section.Name, ".ehmeta", 8) == 0) {
            const Byte* metadata = base + section.VirtualAddress;
            const Byte* header = base + Read<std::uint32_t>(metadata);
            if (header[0] != 1 || header[3] == 255) return false;
            const Byte* p = header + 4;
            Encoded(p, header[1], Word(header));
            const Word count = Encoded(p, header[2]);
            const auto width = EncodingSize(header[3]);
            const Byte* table = p;
            Word lo = 0, hi = count;
            while (lo < hi) {
                const Word mid = lo + (hi - lo) / 2;
                p = table + mid * width * 2;
                if (Encoded(p, header[3], Word(header)) <= query.pc) lo = mid + 1;
                else hi = mid;
            }
            if (!lo) return false;
            p = table + (lo - 1) * width * 2 + width;
            query.fde = reinterpret_cast<const Byte*>(Encoded(p, header[3], Word(header)));
            return DecodeCandidate(context, frame, query);
        }
        if (std::memcmp(section.Name, ".ehfram", 8) != 0) continue;
        const Byte* p = base + section.VirtualAddress;
        const Byte* end = p + section.Misc.VirtualSize;
        while (end - p >= 8) {
            const Byte* record = p;
            const auto length = Read<std::uint32_t>(p);
            if (!length) continue;
            if (length == 0xffffffff || length < 4 || Word(end - p) < length) return false;
            const Byte* next = p + length;
            if (Read<std::uint32_t>(p)) {
                query.fde = record;
                frame = {};
                if (DecodeCandidate(context, frame, query)) return true;
            }
            p = next;
        }
    }
    return false;
#else
    AppleFrameRange range;
    if (!FindAppleFrameRange(query.pc, range)) return false;
    query.text = range.text;
    query.data = range.data;
    AppleCompactInfo compact;
    if (FindAppleCompact(query.pc, range, compact)) {
        if ((compact.encoding & UNWIND_X86_64_MODE_MASK) == UNWIND_X86_64_MODE_DWARF) {
            const auto offset = compact.encoding & UNWIND_X86_64_DWARF_SECTION_OFFSET;
            if (!range.ehBegin || offset >= static_cast<Word>(range.ehEnd - range.ehBegin)) return false;
            query.fde = range.ehBegin + offset;
            return DecodeCandidate(context, frame, query);
        }
        frame.compactEncoding = compact.encoding;
        frame.compactFunctionStart = compact.functionStart;
        frame.personality = compact.personality;
        frame.lsda = compact.lsda;
        frame.start = compact.functionStart;
        context.region = frame.start;
        context.lsda = frame.lsda;
        context.personality = frame.personality;
        context.textBase = query.text;
        context.dataBase = query.data;
        return true;
    }
    if (!range.ehBegin || !range.ehEnd) return false;
    const Byte* record = range.ehBegin;
    while (range.ehEnd - record >= 8) {
        const Byte* position = record;
        const auto length = Read<std::uint32_t>(position);
        if (length == 0) break;
        if (length == 0xffffffffu || length < sizeof(std::uint32_t) || static_cast<Word>(range.ehEnd - position) < length) return false;
        const Byte* next = position + length;
        const auto cie = Read<std::uint32_t>(position);
        if (cie != 0) {
            query.fde = record;
            Frame candidate{};
            if (DecodeCandidate(context, candidate, query)) {
                frame = candidate;
                return true;
            }
        }
        record = next;
    }
    return false;
#endif
}

struct Rule { unsigned kind {}; std::intptr_t value {}; const Byte* expression {}; };
#ifdef _WIN32
constexpr unsigned RuleCount = 33;
#else
constexpr unsigned RuleCount = 17;
#endif

struct Rules { Rule registers[RuleCount] {}; unsigned cfaRegister {7}; std::intptr_t cfaOffset {}; const Byte* cfaExpression {}; };

bool Instructions(const Byte* p, const Byte* end, const Frame& frame, Word target, Rules& state, const Rules& initial) {
    Word location = frame.start;
    Rules saved[16];
    unsigned depth = 0;
    while (p < end && location <= target) {
        Byte opcode = *p++;
        unsigned reg;
        if ((opcode & 192) == 64) { location += (opcode & 63) * frame.codeAlign; continue; }
        if ((opcode & 192) == 128) {
            reg = opcode & 63;
            auto offset = Uleb(p) * frame.dataAlign;
            if (reg < RuleCount) state.registers[reg] = {1, static_cast<std::intptr_t>(offset)};
            continue;
        }
        if ((opcode & 192) == 192) {
            reg = opcode & 63;
            if (reg < RuleCount) state.registers[reg] = initial.registers[reg];
            continue;
        }
        switch (opcode) {
        case 0: break;
        case 1: location = Read<Word>(p); break;
        case 2: location += Read<Byte>(p) * frame.codeAlign; break;
        case 3: location += Read<std::uint16_t>(p) * frame.codeAlign; break;
        case 4: location += Read<std::uint32_t>(p) * frame.codeAlign; break;
        case 5: case 17: case 20: case 21: {
            reg = Uleb(p);
            auto offset = (opcode == 17 || opcode == 21 ? Sleb(p) : std::intptr_t(Uleb(p))) * frame.dataAlign;
            if (reg < RuleCount) state.registers[reg] = {unsigned(opcode >= 20 ? 4 : 1), offset};
            break;
        }
        case 6: reg = Uleb(p); if (reg < RuleCount) state.registers[reg] = initial.registers[reg]; break;
        case 7: case 8: reg = Uleb(p); if (reg < RuleCount) state.registers[reg] = {unsigned(opcode == 7 ? 5 : 0)}; break;
        case 9: { reg = Uleb(p); auto other = Uleb(p); if (reg < RuleCount) state.registers[reg] = {2, std::intptr_t(other)}; break; }
        case 10: if (depth == 16) return false; saved[depth++] = state; break;
        case 11: if (!depth) return false; state = saved[--depth]; break;
        case 12: case 18:
            state.cfaExpression = nullptr; state.cfaRegister = Uleb(p);
            state.cfaOffset = opcode == 18 ? Sleb(p) * frame.dataAlign : Uleb(p); break;
        case 13: state.cfaRegister = Uleb(p); break;
        case 14: case 19: state.cfaOffset = opcode == 19 ? Sleb(p) * frame.dataAlign : Uleb(p); break;
        case 15: { state.cfaExpression = p; auto size = Uleb(p); p += size; break; }
        case 16: case 22: {
            reg = Uleb(p); const Byte* expr = p; auto size = Uleb(p); p += size;
            if (reg < RuleCount) state.registers[reg] = {unsigned(opcode == 16 ? 3 : 6), 0, expr};
            break;
        }
        case 46: Uleb(p); break;
        default: return false;
        }
    }
    return true;
}

bool Expression(const Byte* p, const _Unwind_Context& context, Word cfa, Word& result) {
    Word length = Uleb(p);
    const Byte* end = p + length;
    Word stack[64]; unsigned size = 0;
    unsigned steps = 0;
    while (p < end && ++steps < 4096) {
        Byte op = *p++;
        if (size >= 62) return false;
        if (op >= 48 && op <= 79) { stack[size++] = op - 48; continue; }
        if (op >= 80 && op <= 96) { stack[size++] = context.registers[op - 80]; continue; }
        if (op >= 112 && op <= 128) { stack[size++] = context.registers[op - 112] + Sleb(p); continue; }
        switch (op) {
        case 3: stack[size++] = Read<Word>(p); break;
        case 6: if (!size) return false; std::memcpy(&stack[size-1], reinterpret_cast<void*>(stack[size-1]), 8); break;
        case 8: stack[size++] = Read<Byte>(p); break;
        case 9: stack[size++] = Read<std::int8_t>(p); break;
        case 10: stack[size++] = Read<std::uint16_t>(p); break;
        case 11: stack[size++] = Read<std::int16_t>(p); break;
        case 12: stack[size++] = Read<std::uint32_t>(p); break;
        case 13: stack[size++] = Read<std::int32_t>(p); break;
        case 14: case 15: stack[size++] = Read<Word>(p); break;
        case 16: stack[size++] = Uleb(p); break;
        case 17: stack[size++] = Sleb(p); break;
        case 18: if (!size) return false; stack[size] = stack[size-1]; ++size; break;
        case 19: if (!size) return false; --size; break;
        case 20: if (size < 2) return false; stack[size] = stack[size-2]; ++size; break;
        case 22: if (size < 2) return false; { Word x=stack[size-1]; stack[size-1]=stack[size-2]; stack[size-2]=x; } break;
        case 26: case 28: case 30: case 33: case 34: case 36: case 37: case 39: case 41: case 42: case 43: case 44: case 45: case 46: {
            if (size < 2) return false;
            Word b = stack[--size], &a = stack[size-1];
            switch (op) {
            case 26: a &= b; break; case 28: a -= b; break; case 30: a *= b; break;
            case 33: a |= b; break; case 34: a += b; break; case 36: a = b < 64 ? a << b : 0; break;
            case 37: a = b < 64 ? a >> b : 0; break; case 39: a ^= b; break;
            case 41: a = a == b; break; case 42: a = std::intptr_t(a) >= std::intptr_t(b); break;
            case 43: a = std::intptr_t(a) > std::intptr_t(b); break; case 44: a = std::intptr_t(a) <= std::intptr_t(b); break;
            case 45: a = std::intptr_t(a) < std::intptr_t(b); break; case 46: a = a != b; break;
            }
            break;
        }
        case 35: if (!size) return false; stack[size-1] += Uleb(p); break;
        case 146: { auto reg = Uleb(p); if (reg >= 17) return false; stack[size++] = context.registers[reg] + Sleb(p); break; }
        case 150: break;
        case 156: stack[size++] = cfa; break;
        case 159: break;
        default: return false;
        }
    }
    if (p != end || size != 1) return false;
    result = stack[0]; return true;
}

#ifdef __APPLE__
unsigned AppleRegisterIndex(unsigned compactRegister) {
    switch (compactRegister) {
    case UNWIND_X86_64_REG_RBX: return 3;
    case UNWIND_X86_64_REG_R12: return 12;
    case UNWIND_X86_64_REG_R13: return 13;
    case UNWIND_X86_64_REG_R14: return 14;
    case UNWIND_X86_64_REG_R15: return 15;
    case UNWIND_X86_64_REG_RBP: return 6;
    default: return 17;
    }
}

bool AppleFramelessStackSize(const _Unwind_Context& context, const Frame& frame, Word& stackSize) {
    const auto encoded = (frame.compactEncoding & UNWIND_X86_64_FRAMELESS_STACK_SIZE) >> 16;
    stackSize = static_cast<Word>(encoded) * 8;
    if ((frame.compactEncoding & UNWIND_X86_64_MODE_MASK) == UNWIND_X86_64_MODE_STACK_IND) {
        std::uint32_t immediate = 0;
        std::memcpy(&immediate, reinterpret_cast<const void*>(frame.compactFunctionStart + encoded), sizeof(immediate));
        stackSize = immediate + static_cast<Word>((frame.compactEncoding & UNWIND_X86_64_FRAMELESS_STACK_ADJUST) >> 13) * 8;
    }
    return stackSize >= 8 && context.registers[7] <= std::numeric_limits<Word>::max() - stackSize;
}

bool AppleCompactCfa(const _Unwind_Context& context, const Frame& frame, Word& cfa) {
    const auto mode = frame.compactEncoding & UNWIND_X86_64_MODE_MASK;
    if (mode == UNWIND_X86_64_MODE_RBP_FRAME) {
        if (context.registers[6] > std::numeric_limits<Word>::max() - 16) return false;
        cfa = context.registers[6] + 16;
        return true;
    }
    if (mode == UNWIND_X86_64_MODE_STACK_IMMD || mode == UNWIND_X86_64_MODE_STACK_IND) {
        Word stackSize = 0;
        if (!AppleFramelessStackSize(context, frame, stackSize)) return false;
        cfa = context.registers[7] + stackSize;
        return true;
    }
    return false;
}

bool AppleCompactStep(_Unwind_Context& context, const Frame& frame) {
    _Unwind_Context next = context;
    const auto mode = frame.compactEncoding & UNWIND_X86_64_MODE_MASK;
    if (mode == UNWIND_X86_64_MODE_RBP_FRAME) {
        const auto rbp = context.registers[6];
        const auto offset = (frame.compactEncoding & UNWIND_X86_64_RBP_FRAME_OFFSET) >> 16;
        if (rbp < static_cast<Word>(offset) * 8 || rbp > std::numeric_limits<Word>::max() - 16) return false;
        auto saved = rbp - static_cast<Word>(offset) * 8;
        auto registers = frame.compactEncoding & UNWIND_X86_64_RBP_FRAME_REGISTERS;
        for (unsigned index = 0; index < 5; ++index) {
            const auto compactRegister = registers & 7;
            if (compactRegister != UNWIND_X86_64_REG_NONE) {
                const auto native = AppleRegisterIndex(compactRegister);
                if (native >= 17) return false;
                std::memcpy(&next.registers[native], reinterpret_cast<const void*>(saved), sizeof(Word));
            }
            saved += sizeof(Word);
            registers >>= 3;
        }
        std::memcpy(&next.registers[6], reinterpret_cast<const void*>(rbp), sizeof(Word));
        std::memcpy(&next.registers[16], reinterpret_cast<const void*>(rbp + 8), sizeof(Word));
        next.registers[7] = rbp + 16;
    } else if (mode == UNWIND_X86_64_MODE_STACK_IMMD || mode == UNWIND_X86_64_MODE_STACK_IND) {
        Word stackSize = 0;
        if (!AppleFramelessStackSize(context, frame, stackSize)) return false;
        const auto count = (frame.compactEncoding & UNWIND_X86_64_FRAMELESS_STACK_REG_COUNT) >> 10;
        if (count > 6 || stackSize < 8 + static_cast<Word>(count) * 8) return false;
        auto permutation = frame.compactEncoding & UNWIND_X86_64_FRAMELESS_STACK_REG_PERMUTATION;
        unsigned compressed[6]{};
        switch (count) {
        case 6:
        case 5:
            compressed[0] = permutation / 120; permutation -= compressed[0] * 120;
            compressed[1] = permutation / 24; permutation -= compressed[1] * 24;
            compressed[2] = permutation / 6; permutation -= compressed[2] * 6;
            compressed[3] = permutation / 2; permutation -= compressed[3] * 2;
            compressed[4] = permutation;
            break;
        case 4:
            compressed[0] = permutation / 60; permutation -= compressed[0] * 60;
            compressed[1] = permutation / 12; permutation -= compressed[1] * 12;
            compressed[2] = permutation / 3; permutation -= compressed[2] * 3;
            compressed[3] = permutation;
            break;
        case 3:
            compressed[0] = permutation / 20; permutation -= compressed[0] * 20;
            compressed[1] = permutation / 4; permutation -= compressed[1] * 4;
            compressed[2] = permutation;
            break;
        case 2:
            compressed[0] = permutation / 5; permutation -= compressed[0] * 5;
            compressed[1] = permutation;
            break;
        case 1: compressed[0] = permutation; break;
        }
        bool used[7]{};
        unsigned restored[6]{};
        for (unsigned index = 0; index < count; ++index) {
            unsigned available = 0;
            for (unsigned candidate = 1; candidate < 7; ++candidate) {
                if (used[candidate]) continue;
                if (available++ != compressed[index]) continue;
                restored[index] = candidate;
                used[candidate] = true;
                break;
            }
            if (restored[index] == 0) return false;
        }
        auto saved = context.registers[7] + stackSize - 8 - static_cast<Word>(count) * 8;
        for (unsigned index = 0; index < count; ++index) {
            const auto native = AppleRegisterIndex(restored[index]);
            if (native >= 17) return false;
            std::memcpy(&next.registers[native], reinterpret_cast<const void*>(saved), sizeof(Word));
            saved += sizeof(Word);
        }
        std::memcpy(&next.registers[16], reinterpret_cast<const void*>(saved), sizeof(Word));
        next.registers[7] = saved + 8;
    } else return false;
    if (next.registers[16] == 0 || (next.registers[7] == context.registers[7] && next.registers[16] == context.registers[16])) return false;
    context = next;
    return true;
}
#endif

bool GetRules(_Unwind_Context& context, Frame& frame, Rules& rules) {
    if (!DecodeFrame(context, frame)) return false;
#ifdef __APPLE__
    if (frame.compactEncoding != 0) return AppleCompactCfa(context, frame, context.cfa);
#endif
    Rules initial;
    if (!Instructions(frame.cieBegin, frame.cieEnd, frame, ~Word(0), initial, {})) return false;
#ifdef _WIN32
    if (frame.returnRegister == 32) {
        initial.registers[16] = initial.registers[32];
        initial.registers[32] = {};
        frame.returnRegister = 16;
    }
#endif
    rules = initial;
    if (!Instructions(frame.begin, frame.end, frame, context.registers[16] - !context.signalFrame, rules, initial)) return false;
    if (rules.cfaExpression) return Expression(rules.cfaExpression, context, 0, context.cfa);
    if (rules.cfaRegister >= 17) return false;
    context.cfa = context.registers[rules.cfaRegister] + rules.cfaOffset;
    return true;
}

bool Step(_Unwind_Context& context) {
    Frame frame; Rules rules;
    if (!GetRules(context, frame, rules)) return false;
#ifdef __APPLE__
    if (frame.compactEncoding != 0) return AppleCompactStep(context, frame);
#endif
    _Unwind_Context next = context;
    for (unsigned i = 0; i < 17; ++i) {
        const auto& rule = rules.registers[i];
        Word value;
        switch (rule.kind) {
        case 0: break;
        case 1: std::memcpy(&next.registers[i], reinterpret_cast<void*>(context.cfa + rule.value), 8); break;
        case 2: if (rule.value < 0 || rule.value >= 17) return false; next.registers[i] = context.registers[rule.value]; break;
        case 3: case 6:
            if (!Expression(rule.expression, context, context.cfa, value)) return false;
            if (rule.kind == 3) std::memcpy(&value, reinterpret_cast<void*>(value), 8);
            next.registers[i] = value; break;
        case 4: next.registers[i] = context.cfa + rule.value; break;
        case 5: next.registers[i] = 0; break;
        }
    }
#ifdef _WIN32
    for (unsigned i = 17; i < RuleCount; ++i) {
        const auto& rule = rules.registers[i];
        auto* destination = next.vectorRegisters[i - 17];
        if (rule.kind == 1) std::memcpy(destination, reinterpret_cast<void*>(context.cfa + rule.value), 16);
        else if (rule.kind == 2 && rule.value >= 17 && rule.value < RuleCount)
            std::memcpy(destination, context.vectorRegisters[rule.value - 17], 16);
        else if (rule.kind == 3) {
            Word address;
            if (!Expression(rule.expression, context, context.cfa, address)) return false;
            std::memcpy(destination, reinterpret_cast<const void*>(address), 16);
        }
        else if (rule.kind == 5) std::memset(destination, 0, 16);
        else if (rule.kind != 0) return false;
    }
#endif
    next.registers[7] = context.cfa;
    next.registers[16] = next.registers[frame.returnRegister];
    next.signalFrame = frame.signal;
    if (!next.registers[16] || (next.registers[7] == context.registers[7] && next.registers[16] == context.registers[16])) return false;
    context = next;
    return true;
}

_Unwind_Reason_Code PhaseTwo(_Unwind_Context context, _Unwind_Exception* exception) {
    for (unsigned depth = 0; depth < 65536; ++depth) {
        Frame frame; Rules rules;
        if (!GetRules(context, frame, rules)) {
            if (exception->private_1) {
                auto stop = reinterpret_cast<_Unwind_Stop_Fn>(exception->private_1);
                return stop(1, _Unwind_Action(_UA_FORCE_UNWIND | _UA_CLEANUP_PHASE | _UA_END_OF_STACK), exception->exception_class, exception, &context, reinterpret_cast<void*>(exception->private_2));
            }
            return _URC_END_OF_STACK;
        }
        {
            auto actions = _UA_CLEANUP_PHASE;
            if (exception->private_1) {
                actions = _Unwind_Action(actions | _UA_FORCE_UNWIND);
                auto stop = reinterpret_cast<_Unwind_Stop_Fn>(exception->private_1);
                auto result = stop(1, actions, exception->exception_class, exception, &context, reinterpret_cast<void*>(exception->private_2));
                if (result != _URC_NO_REASON) return result;
            } else if (context.cfa == exception->private_2) actions = _Unwind_Action(actions | _UA_HANDLER_FRAME);
            if (frame.personality) {
                auto result = CallPersonality(frame.personality, actions, exception, &context);
                if (result == _URC_INSTALL_CONTEXT) LibcRestoreRegisters(context.registers);
                if (result != _URC_CONTINUE_UNWIND) return _URC_FATAL_PHASE2_ERROR;
            }
        }
        if (!Step(context)) {
            if (exception->private_1) {
                auto stop = reinterpret_cast<_Unwind_Stop_Fn>(exception->private_1);
                return stop(1, _Unwind_Action(_UA_FORCE_UNWIND | _UA_CLEANUP_PHASE | _UA_END_OF_STACK), exception->exception_class, exception, &context, reinterpret_cast<void*>(exception->private_2));
            }
            return _URC_FATAL_PHASE2_ERROR;
        }
    }
    return _URC_FATAL_PHASE2_ERROR;
}
}

extern "C" {
_Unwind_Reason_Code APS5_VABI _Unwind_RaiseException_nid_postfix(_Unwind_Exception* exception) {
    _Unwind_Context start;
    LibcCaptureRegisters(start.registers);
    if (!LibcUnwind::Step(start)) return _URC_FATAL_PHASE1_ERROR;
    auto context = start;
    exception->private_1 = 0;
    for (unsigned depth = 0; depth < 65536; ++depth) {
        LibcUnwind::Frame frame; LibcUnwind::Rules rules;
        if (!LibcUnwind::GetRules(context, frame, rules)) return _URC_END_OF_STACK;
        if (frame.personality) {
            auto result = LibcUnwind::CallPersonality(frame.personality, _UA_SEARCH_PHASE, exception, &context);
            if (result == _URC_HANDLER_FOUND) {
                exception->private_2 = context.cfa;
                return LibcUnwind::PhaseTwo(start, exception);
            }
            if (result != _URC_CONTINUE_UNWIND) return _URC_FATAL_PHASE1_ERROR;
        }
        if (!LibcUnwind::Step(context)) return _URC_END_OF_STACK;
    }
    return _URC_FATAL_PHASE1_ERROR;
}

[[noreturn]] void APS5_VABI _Unwind_Resume_nid_postfix(_Unwind_Exception* exception) {
    _Unwind_Context context;
    LibcCaptureRegisters(context.registers);
    if (!LibcUnwind::Step(context)) std::abort();
    LibcUnwind::PhaseTwo(context, exception);
    std::abort();
}

_Unwind_Reason_Code APS5_VABI _Unwind_Resume_or_Rethrow_nid_postfix(_Unwind_Exception* exception) {
    if (exception->private_1) _Unwind_Resume_nid_postfix(exception);
    return _Unwind_RaiseException_nid_postfix(exception);
}

void APS5_VABI _Unwind_DeleteException_nid_postfix(_Unwind_Exception* exception) {
    if (exception && exception->exception_cleanup) exception->exception_cleanup(_URC_FOREIGN_EXCEPTION_CAUGHT, exception);
}

_Unwind_Word APS5_VABI _Unwind_GetGR_nid_postfix(_Unwind_Context* context, int index) {
    if (index < 0 || index >= 17) std::abort();
    return context->registers[index];
}
void APS5_VABI _Unwind_SetGR_nid_postfix(_Unwind_Context* context, int index, _Unwind_Word value) {
    if (index < 0 || index >= 17) std::abort();
    context->registers[index] = value;
}
_Unwind_Ptr APS5_VABI _Unwind_GetIP_nid_postfix(_Unwind_Context* context) { return context->registers[16]; }
void APS5_VABI _Unwind_SetIP_nid_postfix(_Unwind_Context* context, _Unwind_Ptr value) { context->registers[16] = value; }
_Unwind_Ptr APS5_VABI _Unwind_GetIPInfo_nid_postfix(_Unwind_Context* context, int* before) { if (before) *before = context->signalFrame; return context->registers[16]; }
_Unwind_Word APS5_VABI _Unwind_GetCFA_nid_postfix(_Unwind_Context* context) { return context->cfa; }
_Unwind_Ptr APS5_VABI _Unwind_GetLanguageSpecificData_nid_postfix(_Unwind_Context* context) { return context->lsda; }
_Unwind_Ptr APS5_VABI _Unwind_GetRegionStart_nid_postfix(_Unwind_Context* context) { return context->region; }
_Unwind_Ptr APS5_VABI _Unwind_GetDataRelBase_nid_postfix(_Unwind_Context* context) { return context->dataBase; }
_Unwind_Ptr APS5_VABI _Unwind_GetTextRelBase_nid_postfix(_Unwind_Context* context) { return context->textBase; }

_Unwind_Reason_Code APS5_VABI _Unwind_ForcedUnwind_nid_postfix(_Unwind_Exception* exception, _Unwind_Stop_Fn stop, void* argument) {
    if (!stop) return _URC_FATAL_PHASE2_ERROR;
    _Unwind_Context context;
    LibcCaptureRegisters(context.registers);
    if (!LibcUnwind::Step(context)) return _URC_FATAL_PHASE2_ERROR;
    exception->private_1 = reinterpret_cast<std::uintptr_t>(stop);
    exception->private_2 = reinterpret_cast<std::uintptr_t>(argument);
    return LibcUnwind::PhaseTwo(context, exception);
}

_Unwind_Reason_Code APS5_VABI _Unwind_Backtrace_nid_postfix(_Unwind_Trace_Fn trace, void* argument) {
    _Unwind_Context context;
    LibcCaptureRegisters(context.registers);
    if (!LibcUnwind::Step(context)) return _URC_END_OF_STACK;
    for (unsigned depth = 0; depth < 65536; ++depth) {
        LibcUnwind::Frame frame; LibcUnwind::Rules rules;
        if (!LibcUnwind::GetRules(context, frame, rules)) return _URC_END_OF_STACK;
        auto result = trace(&context, argument);
        if (result != _URC_NO_REASON) return result;
        if (!LibcUnwind::Step(context)) return _URC_END_OF_STACK;
    }
    return _URC_FATAL_PHASE1_ERROR;
}
}

#else

extern "C" {
_Unwind_Reason_Code APS5_VABI _Unwind_RaiseException_nid_postfix(_Unwind_Exception*) { std::abort(); }
[[noreturn]] void APS5_VABI _Unwind_Resume_nid_postfix(_Unwind_Exception*) { std::abort(); }
_Unwind_Reason_Code APS5_VABI _Unwind_Resume_or_Rethrow_nid_postfix(_Unwind_Exception*) { std::abort(); }
void APS5_VABI _Unwind_DeleteException_nid_postfix(_Unwind_Exception* e) { if (e && e->exception_cleanup) e->exception_cleanup(_URC_FOREIGN_EXCEPTION_CAUGHT, e); }
_Unwind_Word APS5_VABI _Unwind_GetGR_nid_postfix(_Unwind_Context*, int) { std::abort(); }
void APS5_VABI _Unwind_SetGR_nid_postfix(_Unwind_Context*, int, _Unwind_Word) { std::abort(); }
_Unwind_Ptr APS5_VABI _Unwind_GetIP_nid_postfix(_Unwind_Context*) { std::abort(); }
void APS5_VABI _Unwind_SetIP_nid_postfix(_Unwind_Context*, _Unwind_Ptr) { std::abort(); }
_Unwind_Ptr APS5_VABI _Unwind_GetIPInfo_nid_postfix(_Unwind_Context*, int*) { std::abort(); }
_Unwind_Word APS5_VABI _Unwind_GetCFA_nid_postfix(_Unwind_Context*) { std::abort(); }
_Unwind_Ptr APS5_VABI _Unwind_GetLanguageSpecificData_nid_postfix(_Unwind_Context*) { std::abort(); }
_Unwind_Ptr APS5_VABI _Unwind_GetRegionStart_nid_postfix(_Unwind_Context*) { std::abort(); }
_Unwind_Ptr APS5_VABI _Unwind_GetDataRelBase_nid_postfix(_Unwind_Context*) { std::abort(); }
_Unwind_Ptr APS5_VABI _Unwind_GetTextRelBase_nid_postfix(_Unwind_Context*) { std::abort(); }
_Unwind_Reason_Code APS5_VABI _Unwind_ForcedUnwind_nid_postfix(_Unwind_Exception*, _Unwind_Stop_Fn, void*) { std::abort(); }
_Unwind_Reason_Code APS5_VABI _Unwind_Backtrace_nid_postfix(_Unwind_Trace_Fn, void*) { std::abort(); }
}

#endif
