# Tested compatibility

| Game           | ID        | Windows           | Linux | macOS                | Verified performance                                                                                           |
|----------------|-----------|-------------------|-------|----------------------|----------------------------------------------------------------------------------------------------------------|
| Dreaming Sarah | PPSA02929 | In game, playable | ?     | In game, playable | macOS: stable 59.6 FPS at 3840x2160, Apple M1 Pro under Rosetta 2; Windows: 60 FPS, GTX 1050 Ti / i5-7500; 36 FPS, Intel HD 620 / i5-7200 |

The macOS result was measured during gameplay with the game's 60 FPS cap enabled. The tested build uses the host-libc relink path; bundled guest-libc relinking is still blocked by an unresolved `sce_needLibc` import.
