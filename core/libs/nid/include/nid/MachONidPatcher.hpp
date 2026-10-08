#ifndef NID_MACHONIDPATCHER_HPP
#define NID_MACHONIDPATCHER_HPP

#include <nid/IBinaryPatcher.hpp>

namespace Nid {

class MachONidPatcher final : public IBinaryPatcher {
public:
    void PatchNids(std::vector<std::uint8_t>& binary, const std::string& libraryName, const std::unordered_set<std::string>& excludedExports) const override;
};

std::unordered_set<std::string> ReadMachOExports(const std::vector<std::uint8_t>& binary);

}

#endif
