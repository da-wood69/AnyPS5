#ifndef RELINKER_MACTLSREWRITER_HPP
#define RELINKER_MACTLSREWRITER_HPP

#include <domain/Types.hpp>
#include <cstddef>
#include <cstdint>
#include <vector>

namespace Relinker {

class MacTlsRewriter {
public:
    std::size_t Rewrite(std::vector<std::uint8_t>& bytes, const std::vector<Domain::ProgramHeader>& headers) const;
};

}

#endif
