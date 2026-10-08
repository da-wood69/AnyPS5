# Build

```sh
git submodule update --init --recursive
```

## Requirements

- x86-64, Git, CMake 3.22.1 or newer, Ninja, C++20.
- Linux: GCC, G++, binutils. SDL's X11 backend requires X11 and Xext development headers (`libx11-dev` and `libxext-dev` on Debian/Ubuntu).
- Windows: only MinGW-w64 GCC 15.2.0 (WinLibs `x86_64-ucrt-posix-seh`, release `15.2.0posix-14.0.0-ucrt-r7`) is currently supported. Add its `mingw64/bin` directory to `PATH` before configuring.
- macOS: Xcode command-line tools, Ninja, `curl`, and Rosetta 2 on Apple Silicon. The current guest ABI is x86-64, so both Intel and Apple Silicon Macs build x86-64 binaries.
- FFmpeg binaries are downloaded during configuration unless `FFMPEG_PREBUILT_DIR` is set. With the WinLibs CMake, the download fails with status 60 (`SSL peer certificate or SSH remote key was not OK`) unless `SSL_CERT_FILE` names a CA bundle, for example `C:\Program Files\Git\mingw64\etc\ssl\certs\ca-bundle.crt` from Git for Windows, as in CI.

## Commands

```sh
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_COMPILER=gcc -DCMAKE_CXX_COMPILER=g++
cmake --build build --parallel
cmake --build build --target libs --parallel
```

`libs` is a custom target: every library under [core/libs/prx](../../core/libs/prx) is built with
`EXCLUDE_FROM_ALL`, so the first command alone does not produce them. Titles load the patched `.prx`
files from `build/core/libs/libs`, which only that second step refreshes. Running a title after a
library change without it therefore tests the previous binaries and can show no effect at all.

[Relinker usage and runtime layout](../user/USAGE.md).

## macOS package

The packaging script builds the x86-64 relinker, runner, and system libraries; downloads the pinned official MoltenVK 1.4.2 package; verifies its SHA-256; and runs a real Cocoa/Metal swapchain presentation probe:

```sh
./scripts/macos/build-package.sh
```

The default output is `build-macos-x64/AnyPS5-macOS/`. Supply a build directory and package directory as the first two arguments to override both paths:

```sh
./scripts/macos/build-package.sh build-macos-x64 build-macos-x64/AnyPS5-macOS
```

On Apple Silicon, install Rosetta first if it is not already available:

```sh
softwareupdate --install-rosetta --agree-to-license
```

For an incremental developer build using an existing MoltenVK installation:

```sh
cmake -S . -B build-macos-x64 -G Ninja \
    -DCMAKE_BUILD_TYPE=RelWithDebInfo \
    -DCMAKE_OSX_ARCHITECTURES=x86_64 \
    -DBUILD_TESTING=ON
cmake --build build-macos-x64 --target relinker anyps5-runner libs --parallel
```

Set `ANYPS5_VULKAN_LIBRARY` to the x86-64 or universal `libMoltenVK.dylib` when it is not beside `anyps5-runner`. The packaged layout needs no environment variable because the runner discovers its adjacent copy automatically.

## CMake flags

Project switches accept `ON` or `OFF`:

| Flag                             | Default | Effect                                           |
|----------------------------------|---------|--------------------------------------------------|
| `-DBUILD_TESTING=ON`             | `OFF`   | Build and register tests.                        |
| `-DANYPS5_ENABLE_SPIRV_TOOLS=ON` | `OFF`   | Enable SPIR-V validation and optimization.       |
| `-DAPS5_ENABLE_TIMING_LOG=ON`    | `OFF`   | Compile frame timing logging.                    |
| `-DAPS5_AGC_CREATE_LOG=OFF`      | `ON`    | Disable successful `sceAgcCreateShader` logging. |
| `-DAGC_BUILD_VISUAL_TEST=ON`     | `OFF`   | Build the standalone AGC SPIR-V visual test.     |

Build configuration parameters:

| Flag                                   | Value                                                              |
|----------------------------------------|--------------------------------------------------------------------|
| `-DCMAKE_BUILD_TYPE=Release`           | `Debug`, `Release`, `RelWithDebInfo`, or `MinSizeRel`.             |
| `-DCMAKE_C_COMPILER=gcc`               | C compiler name or absolute path.                                  |
| `-DCMAKE_CXX_COMPILER=g++`             | C++ compiler name or absolute path.                                |
| `-DCMAKE_C_COMPILER_LAUNCHER=ccache`   | Optional C compiler cache; requires `ccache`.                      |
| `-DCMAKE_CXX_COMPILER_LAUNCHER=ccache` | Optional C++ compiler cache; requires `ccache`.                    |
| `-DFFMPEG_PREBUILT_DIR=<path>`         | Unpacked FFmpeg package for the target platform; empty by default. |

SDL and FreeType settings forced by the root `CMakeLists.txt` cannot be overridden with `-D`.

## Pipeline statistics

Set `APS5_PIPELINE_STATS=1` to capture and print driver statistics for each newly created graphics or compute pipeline. This requires `VK_KHR_pipeline_executable_properties` and `pipelineExecutableInfo`; an unsupported device fails with an error. Statistic names and units are driver-specific. Capturing statistics can increase pipeline compilation cost. The setting is disabled by default.

## Shader recompiler

The shader recompilation logic in [core/shader/recompiler](../../core/shader/recompiler) is isolated from the rest of the project and is a pure function of its input data, designed for integration into any other project. The current CMake target also includes cache support and links a supplied runtime target, glslang, and optionally SPIRV-Tools.
