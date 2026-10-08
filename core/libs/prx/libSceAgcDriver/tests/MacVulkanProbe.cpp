#define SDL_MAIN_HANDLED
#include "prx/libSceAgcDriver/Execution/include/VulkanDevice.hpp"
#include <SDL.h>
#include <SDL_vulkan.h>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <exception>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

constexpr std::uint32_t Width = 64;
constexpr std::uint32_t Height = 64;

void Require(bool condition, const std::string& reason) {
    if (!condition) throw std::runtime_error(reason);
}

}

int main() {
    const char* vulkanLibrary = std::getenv("ANYPS5_VULKAN_LIBRARY");
    if (vulkanLibrary == nullptr) {
        std::cerr << "ANYPS5_VULKAN_LIBRARY is not set; skipping macOS Vulkan probe\n";
        return 77;
    }
    try {
        SDL_SetMainReady();
        Require(SDL_setenv("SDL_VULKAN_LIBRARY", vulkanLibrary, 1) == 0, SDL_GetError());
        Require(SDL_Init(SDL_INIT_VIDEO) == 0, SDL_GetError());
        {
            const auto window = std::unique_ptr<SDL_Window, decltype(&SDL_DestroyWindow)>(
                SDL_CreateWindow("AnyPS5 macOS Vulkan probe", SDL_WINDOWPOS_UNDEFINED,
                    SDL_WINDOWPOS_UNDEFINED, Width, Height,
                    SDL_WINDOW_VULKAN | SDL_WINDOW_HIDDEN | SDL_WINDOW_ALLOW_HIGHDPI),
                SDL_DestroyWindow);
            Require(window != nullptr, SDL_GetError());
            unsigned extensionCount = 0;
            Require(SDL_Vulkan_GetInstanceExtensions(window.get(), &extensionCount, nullptr) == SDL_TRUE, SDL_GetError());
            std::vector<const char*> extensions(extensionCount);
            Require(SDL_Vulkan_GetInstanceExtensions(window.get(), &extensionCount, extensions.data()) == SDL_TRUE, SDL_GetError());
            extensions.resize(extensionCount);
            const AgcDriver::PresentationWindow presentation{window.get(), extensions,
                [](void* context, VkInstance instance) {
                    VkSurfaceKHR surface = VK_NULL_HANDLE;
                    Require(SDL_Vulkan_CreateSurface(static_cast<SDL_Window*>(context), instance, &surface) == SDL_TRUE, SDL_GetError());
                    return surface;
                },
                [](void* context, std::uint32_t* width, std::uint32_t* height) {
                    int drawableWidth = 0;
                    int drawableHeight = 0;
                    SDL_Vulkan_GetDrawableSize(static_cast<SDL_Window*>(context), &drawableWidth, &drawableHeight);
                    *width = drawableWidth > 0 ? static_cast<std::uint32_t>(drawableWidth) : 0;
                    *height = drawableHeight > 0 ? static_cast<std::uint32_t>(drawableHeight) : 0;
                }, Width, Height};
            AgcDriver::VulkanDevice device(&presentation);
            std::array<std::byte, Width * Height * 4> pixels{};
            for (std::size_t index = 0; index < pixels.size(); index += 4) {
                pixels[index] = std::byte{0x18};
                pixels[index + 1] = std::byte{0x40};
                pixels[index + 2] = std::byte{0x78};
                pixels[index + 3] = std::byte{0xff};
            }
            device.PresentPixels(Width, Height, pixels);
            device.WaitIdle();
            std::cout << "AnyPS5 Vulkan surface/present: " << device.DeviceName() << '\n';
        }
        SDL_Quit();
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "AnyPS5 Vulkan probe failed: " << error.what() << '\n';
        SDL_Quit();
        return 1;
    }
}
