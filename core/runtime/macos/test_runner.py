"""Exercise the Mach-O host with a minimal relinked PS5-style ELF entry."""

from pathlib import Path
import hashlib
import os
import signal
import struct
import subprocess
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).parents[2] / "relinker" / "relinker" / "tests"))
from test_linux_entry_argv import argv_fixture
from test_optional_plt import fixture as dynamic_fixture

NID_SUFFIX = bytes.fromhex("518d64a635ded8c1e6b039b1c3e55230")
NID_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+-"


def compute_nid(name):
    digest = hashlib.sha1(name.encode() + NID_SUFFIX).digest()
    value = digest[:8][::-1]
    bits = int.from_bytes(value, "big") << 2
    return "".join(NID_ALPHABET[(bits >> (60 - index * 6)) & 63] for index in range(11))


def import_fixture():
    image = dynamic_fixture()
    struct.pack_into("<H", image, 56, 5)
    for index in range(2, 5):
        struct.pack_into("<IIQQQQQQ", image, 64 + index * 56,
                         0x6FFFFF01, 0, 0, 0, 0, 0, 0, 1)
    nid = b"BNowx2l588E"
    strings = b"\0libkernel.prx\0" + nid + b"\0"
    library_offset = 1
    symbol_offset = 1 + len(b"libkernel.prx") + 1
    image[0x600:0x600 + len(strings)] = strings
    struct.pack_into("<IBBHQQ", image, 0x620 + 24, symbol_offset, 0x12, 0, 0, 0, 0)
    struct.pack_into("<QQq", image, 0x700, 0x300, (1 << 32) | 6, 0)
    tags = [(1, library_offset), (5, 0x600), (10, len(strings)), (6, 0x620), (11, 24),
            (7, 0x700), (8, 24), (9, 24), (0, 0)]
    for index, tag in enumerate(tags):
        struct.pack_into("<qQ", image, 0x400 + index * 16, *tag)
    struct.pack_into("<QQ", image, 120 + 32, len(tags) * 16, len(tags) * 16)
    code = bytes.fromhex("ff15fa000000" "483d00ca9a3b" "7501" "cc" "0f0b")
    image[0x200:0x200 + len(code)] = code
    return image


def direct_tls_fixture():
    image = argv_fixture()
    struct.pack_into("<H", image, 56, 6)
    struct.pack_into("<IIQQQQQQ", image, 64 + 2 * 56,
                     7, 4, 0x4800, 0x800, 0x800, 8, 16, 16)
    struct.pack_into("<IIQQQQQQ", image, 64 + 5 * 56,
                     0x6FFFFF01, 0, 0, 0, 0, 0, 0, 1)
    struct.pack_into("<Q", image, 0x4800, 42)
    code = bytes.fromhex(
        "64488b042500000000"
        "8378f02a" "7519"
        "64488b0c2528000000"
        "48babebafecaefbeadde"
        "4839d1" "7501"
        "cc" "0f0b")
    image[0x4010:0x4010 + len(code)] = code
    return image


def dynamic_loader_fixture():
    image = dynamic_fixture()
    struct.pack_into("<H", image, 56, 5)
    for index in range(2, 5):
        struct.pack_into("<IIQQQQQQ", image, 64 + index * 56,
                         0x6FFFFF01, 0, 0, 0, 0, 0, 0, 1)
    load_nid = compute_nid("sceKernelLoadStartModule").encode()
    dlsym_nid = compute_nid("sceKernelDlsym").encode()
    strings = b"\0libkernel.prx\0" + load_nid + b"\0" + dlsym_nid + b"\0"
    library_offset = 1
    load_offset = 1 + len(b"libkernel.prx") + 1
    dlsym_offset = load_offset + len(load_nid) + 1
    image[0x600:0x600 + len(strings)] = strings
    struct.pack_into("<IBBHQQ", image, 0x620 + 24, load_offset, 0x12, 0, 0, 0, 0)
    struct.pack_into("<IBBHQQ", image, 0x620 + 48, dlsym_offset, 0x12, 0, 0, 0, 0)
    struct.pack_into("<QQq", image, 0x700, 0x300, (1 << 32) | 6, 0)
    struct.pack_into("<QQq", image, 0x718, 0x308, (2 << 32) | 6, 0)
    tags = [(1, library_offset), (5, 0x600), (10, len(strings)), (6, 0x620), (11, 24),
            (7, 0x700), (8, 48), (9, 24), (0, 0)]
    for index, tag in enumerate(tags):
        struct.pack_into("<qQ", image, 0x400 + index * 16, *tag)
    struct.pack_into("<QQ", image, 120 + 32, len(tags) * 16, len(tags) * 16)

    base = 0x200
    code = bytearray(bytes.fromhex("488b7f10" "31f6" "31d2" "31c9" "4531c0" "4531c9"))

    def rip_instruction(opcode, target):
        next_address = base + len(code) + len(opcode) + 4
        code.extend(opcode)
        code.extend(struct.pack("<i", target - next_address))

    rip_instruction(b"\xff\x15", 0x300)
    code.extend(bytes.fromhex("89c7"))
    rip_instruction(b"\x48\x8d\x35", 0x280)
    rip_instruction(b"\x48\x8d\x15", 0x318)
    rip_instruction(b"\xff\x15", 0x308)
    code.extend(bytes.fromhex("85c0"))
    first_branch = len(code)
    code.extend(b"\x75\x00")
    rip_instruction(b"\xff\x15", 0x318)
    code.extend(bytes.fromhex("83f82a"))
    second_branch = len(code)
    code.extend(b"\x75\x00\xcc")
    failure = len(code)
    code.extend(b"\x0f\x0b")
    code[first_branch + 1] = failure - (first_branch + 2)
    code[second_branch + 1] = failure - (second_branch + 2)
    image[base:base + len(code)] = code
    image[0x280:0x280 + len(b"GuestModuleValue\0")] = b"GuestModuleValue\0"
    return image


def guest_module_fixture():
    image = dynamic_fixture()
    struct.pack_into("<Q", image, 24, 0)
    image[0x200:0x206] = bytes.fromhex("b82a000000c3")
    strings = b"\0GuestModuleValue#guest\0"
    image[0x600:0x600 + len(strings)] = strings
    struct.pack_into("<IBBHQQ", image, 0x620 + 24, 1, 0x12, 0, 1, 0x200, 6)
    struct.pack_into("<IIII", image, 0x680, 1, 2, 1, 0)
    tags = [(4, 0x680), (5, 0x600), (10, len(strings)), (6, 0x620), (11, 24), (0, 0)]
    for index, tag in enumerate(tags):
        struct.pack_into("<qQ", image, 0x400 + index * 16, *tag)
    struct.pack_into("<QQ", image, 120 + 32, len(tags) * 16, len(tags) * 16)
    return image


def unwind_metadata_fixture():
    """Build a sectionless ELF whose unwind range is only in PT_GNU_EH_FRAME."""
    image = dynamic_fixture()
    struct.pack_into("<H", image, 56, 6)
    struct.pack_into("<IIQQQQQQ", image, 64 + 2 * 56,
                     0x6474E550, 4, 0x900, 0x900, 0x900, 8, 8, 4)
    for index in range(3, 6):
        struct.pack_into("<IIQQQQQQ", image, 64 + index * 56,
                         0x6FFFFF01, 0, 0, 0, 0, 0, 0, 1)
    strings = b"\0AnyPs5GuestModuleInfo\0"
    image[0x600:0x600 + len(strings)] = strings
    struct.pack_into("<IBBHQQ", image, 0x620 + 24, 1, 0x12, 0, 0, 0, 0)
    struct.pack_into("<QQq", image, 0x700, 0x300, (1 << 32) | 6, 0)
    tags = [(5, 0x600), (10, len(strings)), (6, 0x620), (11, 24),
            (7, 0x700), (8, 24), (9, 24), (0, 0)]
    for index, tag in enumerate(tags):
        struct.pack_into("<qQ", image, 0x400 + index * 16, *tag)
    struct.pack_into("<QQ", image, 120 + 32, len(tags) * 16, len(tags) * 16)

    struct.pack_into("<I4sI", image, 0x800, 4, b"CIE!", 0)
    image[0x900:0x904] = bytes((1, 0x1B, 0xFF, 0xFF))
    struct.pack_into("<i", image, 0x904, 0x800 - 0x904)

    base = 0x200
    info = 0xA00
    code = bytearray(b"\x48\xb8" + struct.pack("<Q", 0x1A8))

    def rip_instruction(opcode, target, suffix=b""):
        next_address = base + len(code) + len(opcode) + 4 + len(suffix)
        code.extend(opcode)
        code.extend(struct.pack("<i", target - next_address))
        code.extend(suffix)

    rip_instruction(b"\x48\x89\x05", info)
    rip_instruction(b"\x48\x8d\x3d", base)
    rip_instruction(b"\x48\x8d\x35", info)
    rip_instruction(b"\xff\x15", 0x300)
    code.extend(b"\x85\xc0")
    branches = []

    def fail_if_zero(opcode, target):
        rip_instruction(opcode, target, b"\x00")
        branches.append(len(code))
        code.extend(b"\x74\x00")

    branches.append(len(code))
    code.extend(b"\x75\x00")
    fail_if_zero(b"\x48\x83\x3d", info + 0x148)
    fail_if_zero(b"\x48\x83\x3d", info + 0x150)
    fail_if_zero(b"\x83\x3d", info + 0x158)
    fail_if_zero(b"\x83\x3d", info + 0x15C)
    code.extend(b"\xcc")
    failure = len(code)
    code.extend(b"\x0f\x0b")
    for branch in branches:
        code[branch + 1] = failure - (branch + 2)
    image[base:base + len(code)] = code
    return image


def main():
    relinker = Path(sys.argv[1]).resolve()
    runner = Path(sys.argv[2]).resolve()
    libraries = Path(sys.argv[3]).resolve()
    with tempfile.TemporaryDirectory(prefix="anyps5-macos-runner-") as directory:
        root = Path(directory)
        source = root / "input.elf"
        output = root / "output.elf"
        source.write_bytes(argv_fixture())
        converted = subprocess.run(
            [str(relinker), "--macos", "--skip-sce-module", str(source), str(output)],
            capture_output=True, text=True, timeout=30)
        assert converted.returncode == 0, (converted.stdout, converted.stderr)
        assert "System: macOS runner" in converted.stdout, converted.stdout
        valid = subprocess.run([str(runner), str(output), "Z"], capture_output=True, timeout=20)
        assert valid.returncode == -signal.SIGTRAP, (valid.returncode, valid.stdout, valid.stderr)
        invalid = subprocess.run([str(runner), str(output), "Z", "extra"], capture_output=True, timeout=20)
        assert invalid.returncode == -signal.SIGILL, (invalid.returncode, invalid.stdout, invalid.stderr)
        source.write_bytes(direct_tls_fixture())
        tls_output = root / "tls.elf"
        converted = subprocess.run(
            [str(relinker), "--macos", "--skip-sce-module", str(source), str(tls_output)],
            capture_output=True, text=True, timeout=30)
        assert converted.returncode == 0, (converted.stdout, converted.stderr)
        tls = subprocess.run([str(runner), str(tls_output)], capture_output=True, timeout=20)
        assert tls.returncode == -signal.SIGTRAP, (tls.returncode, tls.stdout, tls.stderr)
        source.write_bytes(import_fixture())
        imported_output = root / "imported.elf"
        converted = subprocess.run(
            [str(relinker), "--macos", "--skip-sce-module", str(source), str(imported_output)],
            capture_output=True, text=True, timeout=30)
        assert converted.returncode == 0, (converted.stdout, converted.stderr)
        environment = dict(os.environ)
        environment["ANYPS5_LIBS"] = str(libraries)
        imported = subprocess.run([str(runner), str(imported_output)], capture_output=True, timeout=20, env=environment)
        assert imported.returncode == -signal.SIGTRAP, (imported.returncode, imported.stdout, imported.stderr)
        source.write_bytes(dynamic_loader_fixture())
        dynamic_output = root / "dynamic.elf"
        converted = subprocess.run(
            [str(relinker), "--macos", "--skip-sce-module", str(source), str(dynamic_output)],
            capture_output=True, text=True, timeout=30)
        assert converted.returncode == 0, (converted.stdout, converted.stderr)
        app0 = root / "app0"
        app0.mkdir()
        module = app0 / "dynamic-module.prx"
        Path(str(module) + ".guest.prx").write_bytes(guest_module_fixture())
        dynamic = subprocess.run([str(runner), str(dynamic_output), "/app0/dynamic-module.prx"], capture_output=True, timeout=20, env=environment)
        assert dynamic.returncode == -signal.SIGTRAP, (dynamic.returncode, dynamic.stdout, dynamic.stderr)
        source.write_bytes(unwind_metadata_fixture())
        unwind_output = root / "unwind.elf"
        converted = subprocess.run(
            [str(relinker), "--macos", "--skip-sce-module", str(source), str(unwind_output)],
            capture_output=True, text=True, timeout=30)
        assert converted.returncode == 0, (converted.stdout, converted.stderr)
        unwind = subprocess.run([str(runner), str(unwind_output)], capture_output=True, timeout=20)
        assert unwind.returncode == -signal.SIGTRAP, (unwind.returncode, unwind.stdout, unwind.stderr)
    print("macOS runner entry test passed")


if __name__ == "__main__":
    main()
