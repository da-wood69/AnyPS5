#include "ElfLoader.hpp"
#include <atomic>
#include <CoreFoundation/CoreFoundation.h>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <dlfcn.h>
#include <mach-o/dyld.h>
#include <thread>
#include <vector>

namespace {

std::filesystem::path RunnerPath() {
    std::uint32_t size = 0;
    _NSGetExecutablePath(nullptr, &size);
    std::vector<char> path(size);
    if (_NSGetExecutablePath(path.data(), &size) != 0) throw std::runtime_error("Cannot resolve the AnyPS5 runner path");
    return std::filesystem::weakly_canonical(path.data());
}

void ConfigureVulkan() {
    const char* configured = std::getenv("ANYPS5_VULKAN_LIBRARY");
    if (!configured || !*configured) {
        const auto bundled = RunnerPath().parent_path() / "libMoltenVK.dylib";
        if (std::filesystem::is_regular_file(bundled)) {
            const auto value = bundled.string();
            setenv("ANYPS5_VULKAN_LIBRARY", value.c_str(), 0);
            configured = std::getenv("ANYPS5_VULKAN_LIBRARY");
        }
    }
    if (configured && *configured && std::getenv("SDL_VULKAN_LIBRARY") == nullptr)
        setenv("SDL_VULKAN_LIBRARY", configured, 0);
}

bool InitializeHostVideoOnMainThread() {
    using Initialize = int (*)(std::uint32_t);
    const auto initialize = reinterpret_cast<Initialize>(dlsym(RTLD_DEFAULT, "SDL_InitSubSystem"));
    if (initialize == nullptr) return false;
    if (initialize(0x20) != 0)
        throw std::runtime_error("Cannot initialize the macOS SDL video subsystem");
    return true;
}

int RunWithMainEventLoop(MacRuntime::ElfImage& image, int argc, char** argv) {
    std::atomic<bool> finished{false};
    std::exception_ptr failure;
    int result = 2;
    const auto mainLoop = CFRunLoopGetMain();
    std::thread guest([&] {
        try {
            result = image.Run(argc, argv);
        } catch (...) {
            failure = std::current_exception();
        }
        finished.store(true, std::memory_order_release);
        CFRunLoopStop(mainLoop);
        CFRunLoopWakeUp(mainLoop);
    });
    while (!finished.load(std::memory_order_acquire))
        CFRunLoopRunInMode(kCFRunLoopDefaultMode, 0.05, true);
    guest.join();
    if (failure) std::rethrow_exception(failure);
    return result;
}

}

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "Usage: anyps5-runner <relinked.elf> [game arguments...]\n";
        return 1;
    }
    try {
        ConfigureVulkan();
        const auto executable = std::filesystem::weakly_canonical(argv[1]);
        std::filesystem::current_path(executable.parent_path());
        MacRuntime::Runtime runtime(executable);
        auto& mainImage = runtime.LoadMain();
        if (InitializeHostVideoOnMainThread())
            return RunWithMainEventLoop(mainImage, argc - 1, argv + 1);
        return mainImage.Run(argc - 1, argv + 1);
    } catch (const std::exception& error) {
        std::cerr << "FAIL: " << error.what() << '\n';
        return 2;
    }
}
