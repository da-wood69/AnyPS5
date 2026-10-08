# Architecture

How a PS5 executable becomes a Linux or Windows program, or a macOS-hosted x86-64 process. Guest CPU instructions execute natively; AnyPS5 replaces system libraries instead of emulating a console. macOS uses an in-process ELF loader because Darwin does not execute ELF files directly.

## Overview

```mermaid
flowchart LR
    subgraph input["PS5 game"]
        elf["input.elf"]
        mods["sce_module/*"]
    end

    subgraph relinker["relinker (core/relinker)"]
        direction TB
        intel["--to-intel:<br/>lower AMD-only instructions<br/>(codegen)"]
        mactls["--macos:<br/>rewrite direct FS TLS<br/>accesses for Darwin GS"]
        pipeline["RelinkerPipeline:<br/>read imports by NID,<br/>check syscalls, filter unused NIDs,<br/>build SysV dynamic section"]
        guest["GuestModuleBuilder:<br/>convert bundled modules"]
        patcher["LinuxElfPatcher / WindowsPePatcher<br/>(macOS keeps runner-loadable ELF)"]
        intel -.-> mactls -.-> pipeline --> guest --> patcher
    end

    subgraph build["build (core/libs)"]
        direction TB
        prx["core/libs/prx/*<br/>shared libraries"]
        nid["nid_patcher:<br/>rename exports to their NIDs"]
        prx --> nid
    end

    subgraph out["Native program"]
        app["app.elf / app.exe"]
        runner["anyps5-runner<br/>(macOS)"]
        app0["app0/sce_module/*<br/>(*.guest.prx on macOS)"]
        libs["libs/*.prx"]
    end

    elf --> intel
    mods --> guest
    patcher --> app
    guest --> app0
    nid --> libs
    app -- "Linux/Windows OS loader binds imports by NID" --> libs
    app -- "macOS: map ELF segments and relocate" --> runner
    app0 -- "macOS: map guest ELF modules" --> runner
    runner -- "dyld loads Mach-O system PRXs" --> libs
    app0 -- "Linux/Windows OS loader binds imports by NID" --> libs
```

- [`core/relinker/main.cpp`](../../core/relinker/main.cpp) runs the steps in this order. `--to-intel` is optional, see [USAGE.md](../user/USAGE.md).
- Each library in [`core/libs/prx`](../../core/libs/prx) builds as a shared library. After the build, `nid_patcher` ([`core/libs/nid`](../../core/libs/nid)) renames every export to its NID, computed from the function name. `APS5_EXPORT("<nid>", func)` sets the NID directly when the name is unknown.
- On macOS, [`core/runtime/macos`](../../core/runtime/macos) reserves and maps the relinked ELF image, resolves guest and Mach-O dependencies, supplies PS5-style TLS on each guest thread, and exposes guest module metadata to the exception unwinder. The relinker preserves `PT_GNU_EH_FRAME`, allowing DWARF exceptions to cross mapped guest frames and native compact-unwind frames.

## Graphics

```mermaid
flowchart LR
    game["Game:<br/>command buffers"] --> submit["libSceAgcDriver/Submit<br/>DCB / ACB"]
    submit --> pm4["Execution/Pm4:<br/>state, draws,<br/>dispatches"]
    pm4 -- "shader + state" --> cache{"Compiled variant<br/>in memory or<br/>on disk?"}
    cache -- yes --> vk
    cache -- no --> dec

    subgraph recompiler["core/shader/recompiler"]
        dec["RdnaDecoder"] --> cf["ControlFlow:<br/>graph + structurize"]
        cf --> tr["Translation:<br/>RDNA to IR"]
        tr --> opt["Optimization:<br/>SSA, resources,<br/>bindings"]
        opt --> spv["SpirvBackend:<br/>emit SPIR-V"]
    end

    spv --> vk["libSceAgcDriver/Graphics:<br/>Vulkan pipeline"]
```

- [`Recompiler.cpp`](../../core/shader/recompiler/Recompiler.cpp) runs the stages in this order. With `ANYPS5_ENABLE_SPIRV_TOOLS`, the SPIR-V is also validated and optimized with SPIRV-Tools.
- `ShaderRecompiler::Recompile` keeps compiled variants in memory, and `ShaderDiskCache` stores them on disk so later runs reuse them.
