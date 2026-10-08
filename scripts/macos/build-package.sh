#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "$0")" && pwd)"
repo_dir="$(cd "$script_dir/../.." && pwd)"
build_dir="${1:-$repo_dir/build-macos-x64}"
package_dir="${2:-$build_dir/AnyPS5-macOS}"
mkdir -p "$build_dir" "$package_dir"
build_dir="$(cd "$build_dir" && pwd)"
package_dir="$(cd "$package_dir" && pwd)"
moltenvk_version="1.4.2"
moltenvk_sha256="f95765a6229cb7b915990a2890ce12ebe36a730b021545d3d52ae69ce4c4024e"
dependency_dir="$build_dir/_deps/moltenvk-$moltenvk_version"
archive="$build_dir/_deps/MoltenVK-macos-$moltenvk_version.tar"
moltenvk="$dependency_dir/MoltenVK/dynamic/dylib/macOS/libMoltenVK.dylib"

if [[ "$(uname -m)" == "arm64" ]] && ! /usr/bin/arch -x86_64 /usr/bin/true >/dev/null 2>&1; then
    echo "Rosetta 2 is required to run AnyPS5's x86_64 guest runtime." >&2
    echo "Install it with: softwareupdate --install-rosetta --agree-to-license" >&2
    exit 1
fi

mkdir -p "$build_dir/_deps"
if [[ ! -f "$archive" ]]; then
    curl -fL --retry 3 -o "$archive" \
        "https://github.com/KhronosGroup/MoltenVK/releases/download/v$moltenvk_version/MoltenVK-macos.tar"
fi
printf '%s  %s\n' "$moltenvk_sha256" "$archive" | shasum -a 256 -c -
if [[ ! -f "$moltenvk" ]]; then
    mkdir -p "$dependency_dir"
    tar -xf "$archive" -C "$dependency_dir" --strip-components=1
fi
moltenvk_architectures="$(lipo -archs "$moltenvk")"
if [[ " $moltenvk_architectures " != *" x86_64 "* ]]; then
    echo "MoltenVK package does not contain the required x86_64 slice" >&2
    exit 1
fi

cmake -S "$repo_dir" -B "$build_dir" -G Ninja \
    -DCMAKE_BUILD_TYPE=RelWithDebInfo \
    -DCMAKE_OSX_ARCHITECTURES=x86_64 \
    -DBUILD_TESTING=ON
cmake --build "$build_dir" --target \
    relinker anyps5-runner libs \
    macos_vulkan_probe_tests macos_guest_exception_tests \
    guest_dynamic_loader_tests guest_module_info_tests guest_thread_self_tests \
    host_thread_local_tests guest_math_tests agc_shader_disk_cache_tests \
    guest_font_tests guest_nanosleep_tests guest_udp_tests guest_directory_entry_tests \
    -j "$(sysctl -n hw.logicalcpu)"

mkdir -p "$package_dir/libs" "$package_dir/app0"
cp "$build_dir/core/runtime/anyps5-runner" "$package_dir/"
cp "$build_dir/core/relinker/relinker" "$package_dir/"
cp "$build_dir/core/libs/libs/"*.prx "$package_dir/libs/"
cp "$moltenvk" "$package_dir/libMoltenVK.dylib"

ANYPS5_VULKAN_LIBRARY="$package_dir/libMoltenVK.dylib" \
    ctest --test-dir "$build_dir" \
        -R '^(macos_guest_exceptions|macos_vulkan_probe|guest_dynamic_loader|guest_module_info|guest_thread_self|macos_runner_entry|host_thread_local|guest_math|agc_shader_disk_cache|guest_font|guest_nanosleep|guest_udp|guest_directory_entries)$' \
        --output-on-failure

echo "AnyPS5 macOS package: $package_dir"
