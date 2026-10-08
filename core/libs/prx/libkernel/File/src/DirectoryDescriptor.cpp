#include "prx/libkernel/File/include/DirectoryDescriptor.hpp"
#include "prx/libkernel/KernelErrors.hpp"

#if defined(_WIN32) || defined(__APPLE__)

#include <cstdint>
#include <cstring>
#include <map>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#else
#include <cerrno>
#include <dirent.h>
#include <unistd.h>
#endif

namespace {

constexpr std::uint8_t GuestDirectoryType = 4;
constexpr std::uint8_t GuestRegularType = 8;

struct DirectoryState {
#ifdef _WIN32
    std::filesystem::path path;
#endif
    struct Entry {
        std::string name;
        std::uint8_t type;
        std::uint32_t fileNumber;
    };
    std::vector<Entry> entries;
    std::size_t cursor = 0;
    std::int64_t byteCursor = 0;
    bool loaded = false;
};

std::mutex g_mutex;
std::map<int, DirectoryState> g_directories;

}

namespace File {

int OpenDirectoryDescriptor(const std::filesystem::path& path) {
#ifdef _WIN32
    const int fd = ::_open("NUL", _O_RDONLY | _O_BINARY);
    if (fd < 0) return -1;
    std::lock_guard lock(g_mutex);
    g_directories[fd] = DirectoryState{path};
    return fd;
#else
    (void)path;
    return -1;
#endif
}

std::optional<std::filesystem::path> DirectoryDescriptorPath(int fd) {
#ifdef _WIN32
    std::lock_guard lock(g_mutex);
    const auto found = g_directories.find(fd);
    if (found == g_directories.end()) return std::nullopt;
    return found->second.path;
#else
    (void)fd;
    return std::nullopt;
#endif
}

void ForgetDirectoryDescriptor(int fd) {
    std::lock_guard lock(g_mutex);
    g_directories.erase(fd);
}

void ResetDirectoryDescriptor(int fd) {
    std::lock_guard lock(g_mutex);
    if (const auto found = g_directories.find(fd); found != g_directories.end()) {
        found->second.cursor = 0;
        found->second.byteCursor = 0;
#ifdef __APPLE__
        found->second.entries.clear();
        found->second.loaded = false;
#endif
    }
}

int ReadDirectoryDescriptor(int fd, char* buf, int nbytes, std::int64_t* basep) {
    std::lock_guard lock(g_mutex);
#ifdef _WIN32
    const auto found = g_directories.find(fd);
    if (found == g_directories.end()) return SCE_KERNEL_ERROR_ENOTDIR;
    auto& state = found->second;
#else
    auto& state = g_directories[fd];
#endif
    if (!state.loaded) {
        state.loaded = true;
#ifdef _WIN32
        state.entries.push_back({".", GuestDirectoryType, 1});
        state.entries.push_back({"..", GuestDirectoryType, 2});
        std::error_code error;
        for (const auto& entry : std::filesystem::directory_iterator(state.path, error)) {
            std::error_code typeError;
            state.entries.push_back({entry.path().filename().string(),
                entry.is_directory(typeError) ? GuestDirectoryType : GuestRegularType,
                static_cast<std::uint32_t>(state.entries.size() + 1)});
        }
#else
        const int duplicate = ::dup(fd);
        if (duplicate < 0) {
            g_directories.erase(fd);
            return errno == EBADF ? SCE_KERNEL_ERROR_EBADF : SCE_KERNEL_ERROR_EIO;
        }
        DIR* directory = ::fdopendir(duplicate);
        if (directory == nullptr) {
            const int error = errno;
            ::close(duplicate);
            g_directories.erase(fd);
            return error == ENOTDIR ? SCE_KERNEL_ERROR_ENOTDIR
                                    : error == EBADF ? SCE_KERNEL_ERROR_EBADF : SCE_KERNEL_ERROR_EIO;
        }
        errno = 0;
        while (const auto* entry = ::readdir(directory)) {
            state.entries.push_back({entry->d_name, entry->d_type,
                static_cast<std::uint32_t>(entry->d_ino)});
            errno = 0;
        }
        const int readError = errno;
        ::closedir(directory);
        if (readError != 0) {
            g_directories.erase(fd);
            return SCE_KERNEL_ERROR_EIO;
        }
#endif
    }
    if (basep != nullptr) *basep = state.byteCursor;
    std::size_t used = 0;
    while (state.cursor < state.entries.size()) {
        const auto& [name, type, fileNumber] = state.entries[state.cursor];
        if (name.size() > 255) return used == 0 ? SCE_KERNEL_ERROR_ENAMETOOLONG : static_cast<int>(used);
        const std::size_t record = (8 + name.size() + 1 + 3) & ~std::size_t{3};
        if (used + record > static_cast<std::size_t>(nbytes)) {
            if (used == 0) return SCE_KERNEL_ERROR_EINVAL;
            break;
        }
        char* out = buf + used;
        std::memset(out, 0, record);
        const auto recordLength = static_cast<std::uint16_t>(record);
        std::memcpy(out, &fileNumber, sizeof(fileNumber));
        std::memcpy(out + 4, &recordLength, sizeof(recordLength));
        out[6] = static_cast<char>(type);
        out[7] = static_cast<char>(name.size());
        std::memcpy(out + 8, name.c_str(), name.size() + 1);
        used += record;
        state.byteCursor += static_cast<std::int64_t>(record);
        ++state.cursor;
    }
    return static_cast<int>(used);
}

}

#endif
