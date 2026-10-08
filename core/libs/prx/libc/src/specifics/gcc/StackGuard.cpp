#include <cstdint>
#include <cstdlib>

std::uintptr_t __stack_chk_guard = 0xDEADBEEFCAFEBABEull;
std::uintptr_t __stack_chk_guard_nid_postfix = __stack_chk_guard;
