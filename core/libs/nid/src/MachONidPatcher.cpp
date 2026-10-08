#include <nid/MachONidPatcher.hpp>
#include <nid/NidPatcherUtils.hpp>
#include <nid/NidResolver.hpp>
#include <algorithm>
#include <cstring>
#include <map>
#include <memory>
#include <limits>
#include <stdexcept>
#include <unordered_map>

namespace Nid {
namespace {

constexpr std::uint32_t MachOMagic64 = 0xfeedfacfu;
constexpr std::uint32_t LoadSymtab = 0x2u;
constexpr std::uint32_t LoadSegment64 = 0x19u;
constexpr std::uint32_t LoadDyldInfoOnly = 0x80000022u;
constexpr std::uint32_t LoadExportsTrie = 0x80000033u;
constexpr std::uint8_t SymbolExternal = 0x1u;
constexpr std::uint8_t SymbolTypeMask = 0x0eu;
constexpr std::uint8_t SymbolUndefined = 0x0u;
constexpr std::uint8_t SymbolDebugMask = 0xe0u;

struct MachHeader64 {
    std::uint32_t Magic;
    std::int32_t CpuType;
    std::int32_t CpuSubtype;
    std::uint32_t FileType;
    std::uint32_t CommandCount;
    std::uint32_t CommandSize;
    std::uint32_t Flags;
    std::uint32_t Reserved;
};

struct LoadCommand {
    std::uint32_t Command;
    std::uint32_t Size;
};

struct SymtabCommand {
    std::uint32_t Command;
    std::uint32_t Size;
    std::uint32_t SymbolOffset;
    std::uint32_t SymbolCount;
    std::uint32_t StringOffset;
    std::uint32_t StringSize;
};

struct Nlist64 {
    std::uint32_t StringIndex;
    std::uint8_t Type;
    std::uint8_t Section;
    std::uint16_t Description;
    std::uint64_t Value;
};

struct ExportRange {
    std::uint32_t Offset = 0;
    std::uint32_t Size = 0;
    std::vector<std::size_t> OffsetFields;
    std::vector<std::size_t> SizeFields;
};

struct MachLayout {
    SymtabCommand Symtab{};
    ExportRange Exports;
    std::size_t LinkeditCommand = 0;
};

void RequireRange(const std::vector<std::uint8_t>& binary, std::uint64_t offset, std::uint64_t size) {
    if (offset > binary.size() || size > binary.size() - offset) throw std::runtime_error("Mach-O range out of bounds");
}

MachLayout ReadLayout(const std::vector<std::uint8_t>& binary) {
    using Internal::Read;
    if (binary.size() < sizeof(MachHeader64)) throw std::runtime_error("Mach-O file too small");
    const auto header = Read<MachHeader64>(binary, 0);
    if (header.Magic != MachOMagic64) throw std::runtime_error("unsupported Mach-O format");
    RequireRange(binary, sizeof(MachHeader64), header.CommandSize);
    MachLayout layout;
    bool hasSymtab = false;
    std::size_t offset = sizeof(MachHeader64);
    for (std::uint32_t index = 0; index < header.CommandCount; ++index) {
        const auto command = Read<LoadCommand>(binary, offset);
        if (command.Size < sizeof(LoadCommand)) throw std::runtime_error("invalid Mach-O load command");
        RequireRange(binary, offset, command.Size);
        if (command.Command == LoadSymtab) {
            if (command.Size < sizeof(SymtabCommand)) throw std::runtime_error("invalid Mach-O symbol table command");
            layout.Symtab = Read<SymtabCommand>(binary, offset);
            hasSymtab = true;
        } else if (command.Command == LoadSegment64) {
            if (command.Size < 72) throw std::runtime_error("invalid Mach-O segment command");
            if (std::memcmp(binary.data() + offset + 8, "__LINKEDIT", 10) == 0) layout.LinkeditCommand = offset;
        } else if (command.Command == LoadDyldInfoOnly) {
            if (command.Size < 48) throw std::runtime_error("invalid Mach-O dyld info command");
            const auto exportOffset = Read<std::uint32_t>(binary, offset + 40);
            const auto exportSize = Read<std::uint32_t>(binary, offset + 44);
            if (exportSize != 0) {
                if (layout.Exports.Size != 0 && (layout.Exports.Offset != exportOffset || layout.Exports.Size != exportSize)) throw std::runtime_error("conflicting Mach-O export tries");
                layout.Exports.Offset = exportOffset;
                layout.Exports.Size = exportSize;
                layout.Exports.OffsetFields.push_back(offset + 40);
                layout.Exports.SizeFields.push_back(offset + 44);
            }
        } else if (command.Command == LoadExportsTrie) {
            if (command.Size < 16) throw std::runtime_error("invalid Mach-O exports command");
            const auto exportOffset = Read<std::uint32_t>(binary, offset + 8);
            const auto exportSize = Read<std::uint32_t>(binary, offset + 12);
            if (exportSize != 0) {
                if (layout.Exports.Size != 0 && (layout.Exports.Offset != exportOffset || layout.Exports.Size != exportSize)) throw std::runtime_error("conflicting Mach-O export tries");
                layout.Exports.Offset = exportOffset;
                layout.Exports.Size = exportSize;
                layout.Exports.OffsetFields.push_back(offset + 8);
                layout.Exports.SizeFields.push_back(offset + 12);
            }
        }
        offset += command.Size;
    }
    if (!hasSymtab) throw std::runtime_error("Mach-O has no symbol table");
    if (layout.LinkeditCommand == 0) throw std::runtime_error("Mach-O has no __LINKEDIT segment");
    RequireRange(binary, layout.Symtab.SymbolOffset, std::uint64_t{layout.Symtab.SymbolCount} * sizeof(Nlist64));
    RequireRange(binary, layout.Symtab.StringOffset, layout.Symtab.StringSize);
    if (layout.Exports.Size != 0) RequireRange(binary, layout.Exports.Offset, layout.Exports.Size);
    return layout;
}

struct ExportSymbol {
    std::size_t EntryOffset;
    std::uint32_t StringIndex;
    std::uint64_t Value;
    std::string Name;
};

std::vector<ExportSymbol> ReadSymbols(const std::vector<std::uint8_t>& binary, const MachLayout& layout) {
    using Internal::Read;
    std::vector<ExportSymbol> result;
    for (std::uint32_t index = 0; index < layout.Symtab.SymbolCount; ++index) {
        const auto entryOffset = layout.Symtab.SymbolOffset + std::size_t{index} * sizeof(Nlist64);
        const auto symbol = Read<Nlist64>(binary, entryOffset);
        if ((symbol.Type & SymbolDebugMask) != 0 || (symbol.Type & SymbolExternal) == 0 || (symbol.Type & SymbolTypeMask) == SymbolUndefined || symbol.Section == 0 || symbol.StringIndex == 0) continue;
        if (symbol.StringIndex >= layout.Symtab.StringSize) throw std::runtime_error("Mach-O symbol name is outside the string table");
        auto name = Internal::ReadCStr(binary, layout.Symtab.StringOffset + symbol.StringIndex);
        if (name.empty() || name.front() != '_') continue;
        name.erase(name.begin());
        result.push_back({entryOffset, symbol.StringIndex, symbol.Value, std::move(name)});
    }
    if (result.empty()) throw std::runtime_error("Mach-O has no exports");
    return result;
}

std::uint64_t ReadUleb(const std::vector<std::uint8_t>& bytes, std::size_t& offset) {
    std::uint64_t value = 0;
    unsigned shift = 0;
    while (offset < bytes.size() && shift < 64) {
        const auto byte = bytes[offset++];
        value |= std::uint64_t{byte & 0x7fu} << shift;
        if ((byte & 0x80u) == 0) return value;
        shift += 7;
    }
    throw std::runtime_error("invalid Mach-O export trie ULEB128");
}

void AppendUleb(std::vector<std::uint8_t>& bytes, std::uint64_t value) {
    do {
        auto byte = static_cast<std::uint8_t>(value & 0x7fu);
        value >>= 7;
        if (value != 0) byte |= 0x80u;
        bytes.push_back(byte);
    } while (value != 0);
}

struct TrieExport {
    std::string Name;
    std::vector<std::uint8_t> Terminal;
};

void ReadTrieNode(const std::vector<std::uint8_t>& trie, std::size_t nodeOffset, const std::string& prefix, std::vector<TrieExport>& exports, std::unordered_set<std::size_t>& path) {
    if (!path.insert(nodeOffset).second) throw std::runtime_error("cyclic Mach-O export trie");
    std::size_t cursor = nodeOffset;
    const auto terminalSize = ReadUleb(trie, cursor);
    if (terminalSize > trie.size() - cursor) throw std::runtime_error("Mach-O export terminal is out of bounds");
    if (terminalSize != 0) exports.push_back({prefix, {trie.begin() + static_cast<std::ptrdiff_t>(cursor), trie.begin() + static_cast<std::ptrdiff_t>(cursor + terminalSize)}});
    cursor += terminalSize;
    if (cursor >= trie.size()) throw std::runtime_error("Mach-O export trie child count is out of bounds");
    const auto childCount = trie[cursor++];
    for (std::uint32_t index = 0; index < childCount; ++index) {
        const auto labelStart = cursor;
        while (cursor < trie.size() && trie[cursor] != 0) ++cursor;
        if (cursor == trie.size() || cursor == labelStart) throw std::runtime_error("invalid Mach-O export trie edge");
        const std::string label(reinterpret_cast<const char*>(trie.data() + labelStart), cursor - labelStart);
        ++cursor;
        const auto childOffset = ReadUleb(trie, cursor);
        if (childOffset >= trie.size()) throw std::runtime_error("Mach-O export trie child is out of bounds");
        ReadTrieNode(trie, childOffset, prefix + label, exports, path);
    }
    path.erase(nodeOffset);
}

struct TrieNode {
    std::map<char, std::unique_ptr<TrieNode>> Children;
    std::vector<std::uint8_t> Terminal;
};

struct TrieEdge {
    std::string Label;
    TrieNode* Target;
};

std::vector<TrieEdge> CompressedEdges(TrieNode& node) {
    std::vector<TrieEdge> result;
    for (auto& [character, childOwner] : node.Children) {
        std::string label(1, character);
        auto* child = childOwner.get();
        while (child->Terminal.empty() && child->Children.size() == 1) {
            const auto& next = *child->Children.begin();
            label.push_back(next.first);
            child = next.second.get();
        }
        result.push_back({std::move(label), child});
    }
    return result;
}

void CollectNodes(TrieNode& node, std::vector<TrieNode*>& nodes) {
    nodes.push_back(&node);
    for (const auto& edge : CompressedEdges(node)) CollectNodes(*edge.Target, nodes);
}

std::vector<std::uint8_t> BuildTrie(const std::vector<TrieExport>& exports) {
    TrieNode root;
    for (const auto& item : exports) {
        auto* node = &root;
        for (const char character : item.Name) {
            auto& child = node->Children[character];
            if (!child) child = std::make_unique<TrieNode>();
            node = child.get();
        }
        if (!node->Terminal.empty()) throw std::runtime_error("duplicate renamed Mach-O export: " + item.Name);
        node->Terminal = item.Terminal;
    }
    std::vector<TrieNode*> nodes;
    CollectNodes(root, nodes);
    std::unordered_map<TrieNode*, std::size_t> indices;
    for (std::size_t index = 0; index < nodes.size(); ++index) indices.emplace(nodes[index], index);
    std::vector<std::size_t> offsets(nodes.size());
    for (unsigned iteration = 0; iteration < 16; ++iteration) {
        std::vector<std::size_t> next(nodes.size());
        std::size_t cursor = 0;
        for (std::size_t index = 0; index < nodes.size(); ++index) {
            next[index] = cursor;
            std::vector<std::uint8_t> encoded;
            AppendUleb(encoded, nodes[index]->Terminal.size());
            encoded.insert(encoded.end(), nodes[index]->Terminal.begin(), nodes[index]->Terminal.end());
            const auto edges = CompressedEdges(*nodes[index]);
            if (edges.size() > 255) throw std::runtime_error("Mach-O export trie node has too many children");
            encoded.push_back(static_cast<std::uint8_t>(edges.size()));
            for (const auto& edge : edges) {
                encoded.insert(encoded.end(), edge.Label.begin(), edge.Label.end());
                encoded.push_back(0);
                AppendUleb(encoded, offsets[indices.at(edge.Target)]);
            }
            cursor += encoded.size();
        }
        if (next == offsets) break;
        offsets = std::move(next);
        if (iteration == 15) throw std::runtime_error("Mach-O export trie layout did not converge");
    }
    std::vector<std::uint8_t> result;
    for (std::size_t index = 0; index < nodes.size(); ++index) {
        if (result.size() != offsets[index]) throw std::runtime_error("Mach-O export trie layout mismatch");
        AppendUleb(result, nodes[index]->Terminal.size());
        result.insert(result.end(), nodes[index]->Terminal.begin(), nodes[index]->Terminal.end());
        const auto edges = CompressedEdges(*nodes[index]);
        result.push_back(static_cast<std::uint8_t>(edges.size()));
        for (const auto& edge : edges) {
            result.insert(result.end(), edge.Label.begin(), edge.Label.end());
            result.push_back(0);
            AppendUleb(result, offsets[indices.at(edge.Target)]);
        }
    }
    return result;
}

}

std::unordered_set<std::string> ReadMachOExports(const std::vector<std::uint8_t>& binary) {
    const auto layout = ReadLayout(binary);
    std::unordered_set<std::string> result;
    for (const auto& symbol : ReadSymbols(binary, layout)) result.insert(symbol.Name);
    return result;
}

void MachONidPatcher::PatchNids(std::vector<std::uint8_t>& binary, const std::string& libraryName, const std::unordered_set<std::string>& excludedExports) const {
    const auto layout = ReadLayout(binary);
    const auto symbols = ReadSymbols(binary, layout);
    std::vector<std::string> names;
    names.reserve(symbols.size());
    for (const auto& symbol : symbols) {
        const bool hasAlias = std::any_of(symbols.begin(), symbols.end(), [&](const auto& candidate) {
            return candidate.Value == symbol.Value && candidate.Name != symbol.Name && Internal::IsNidNoPatchCut(candidate.Name);
        });
        if (!hasAlias || Internal::IsNidNoPatchCut(symbol.Name)) names.push_back(symbol.Name);
    }
    const auto mapped = ResolveNids(names, libraryName, excludedExports);

    std::vector<std::string> replacements(layout.Symtab.SymbolCount);
    for (std::uint32_t index = 0; index < layout.Symtab.SymbolCount; ++index) {
        const auto entryOffset = layout.Symtab.SymbolOffset + std::size_t{index} * sizeof(Nlist64);
        const auto symbol = Internal::Read<Nlist64>(binary, entryOffset);
        if (symbol.StringIndex == 0) continue;
        if (symbol.StringIndex >= layout.Symtab.StringSize) throw std::runtime_error("Mach-O symbol name is outside the string table");
        const auto absolute = layout.Symtab.StringOffset + symbol.StringIndex;
        auto name = Internal::ReadCStr(binary, absolute);
        if (name.empty() || name.front() != '_') {
            replacements[index] = std::move(name);
            continue;
        }
        const auto logical = name.substr(1);
        if (const auto found = mapped.find(logical); found != mapped.end()) {
            replacements[index] = "_" + found->second;
            continue;
        }
        const bool undefined = (symbol.Type & SymbolDebugMask) == 0 && (symbol.Type & SymbolExternal) != 0 && (symbol.Type & SymbolTypeMask) == SymbolUndefined;
        const bool sceName = logical.size() >= 3 && std::tolower(static_cast<unsigned char>(logical[0])) == 's' && std::tolower(static_cast<unsigned char>(logical[1])) == 'c' && std::tolower(static_cast<unsigned char>(logical[2])) == 'e';
        if (undefined && (logical.ends_with(Internal::kNidPostfix) || sceName)) replacements[index] = "_" + ResolveOneName(logical);
        else replacements[index] = std::move(name);
    }
    std::vector<std::uint8_t> strings{0};
    std::unordered_map<std::string, std::uint32_t> stringOffsets;
    for (std::uint32_t index = 0; index < layout.Symtab.SymbolCount; ++index) {
        if (replacements[index].empty()) continue;
        auto [found, inserted] = stringOffsets.emplace(replacements[index], static_cast<std::uint32_t>(strings.size()));
        if (inserted) {
            strings.insert(strings.end(), replacements[index].begin(), replacements[index].end());
            strings.push_back(0);
        }
        const auto entryOffset = layout.Symtab.SymbolOffset + std::size_t{index} * sizeof(Nlist64);
        Internal::Write(binary, entryOffset, found->second);
    }
    if (strings.size() > layout.Symtab.StringSize) throw std::runtime_error("rebuilt Mach-O string table exceeds its original allocation");
    std::copy(strings.begin(), strings.end(), binary.begin() + layout.Symtab.StringOffset);
    std::fill(binary.begin() + layout.Symtab.StringOffset + strings.size(), binary.begin() + layout.Symtab.StringOffset + layout.Symtab.StringSize, 0);

    if (layout.Exports.Size == 0) return;
    std::vector<std::uint8_t> oldTrie(binary.begin() + layout.Exports.Offset, binary.begin() + layout.Exports.Offset + layout.Exports.Size);
    std::vector<TrieExport> exports;
    std::unordered_set<std::size_t> path;
    ReadTrieNode(oldTrie, 0, {}, exports, path);
    for (auto& item : exports) {
        if (item.Name.empty() || item.Name.front() != '_') continue;
        const auto found = mapped.find(item.Name.substr(1));
        if (found != mapped.end()) item.Name = "_" + found->second;
    }
    const auto newTrie = BuildTrie(exports);
    std::uint32_t trieOffset = layout.Exports.Offset;
    if (newTrie.size() <= layout.Exports.Size) {
        std::copy(newTrie.begin(), newTrie.end(), binary.begin() + layout.Exports.Offset);
        std::fill(binary.begin() + layout.Exports.Offset + newTrie.size(), binary.begin() + layout.Exports.Offset + layout.Exports.Size, 0);
    } else {
        while (binary.size() % 8 != 0) binary.push_back(0);
        if (binary.size() > std::numeric_limits<std::uint32_t>::max()) throw std::runtime_error("Mach-O export trie offset exceeds 32 bits");
        trieOffset = static_cast<std::uint32_t>(binary.size());
        binary.insert(binary.end(), newTrie.begin(), newTrie.end());
        const auto fileOffset = Internal::Read<std::uint64_t>(binary, layout.LinkeditCommand + 40);
        if (fileOffset > binary.size()) throw std::runtime_error("invalid Mach-O __LINKEDIT file offset");
        const auto fileSize = binary.size() - fileOffset;
        const auto virtualSize = (fileSize + 0xfffu) & ~std::uint64_t{0xfff};
        Internal::Write(binary, layout.LinkeditCommand + 32, virtualSize);
        Internal::Write(binary, layout.LinkeditCommand + 48, static_cast<std::uint64_t>(fileSize));
    }
    for (const auto offsetField : layout.Exports.OffsetFields) Internal::Write(binary, offsetField, trieOffset);
    for (const auto sizeField : layout.Exports.SizeFields) Internal::Write(binary, sizeField, static_cast<std::uint32_t>(newTrie.size()));
}

}
