#undef NDEBUG
#include <cassert>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <unwind.h>

extern "C" [[noreturn]] void _ZSt14_Xout_of_rangePKc_nid_postfix(const char*);
extern "C" unsigned __cxa_uncaught_exceptions_nid_postfix();
extern "C" void* __cxa_begin_catch_nid_postfix(void*);
extern "C" void __cxa_end_catch_nid_postfix();
extern "C" [[noreturn]] void _Unwind_Resume_nid_postfix(_Unwind_Exception*);
extern "C" _Unwind_Reason_Code _Unwind_Backtrace_nid_postfix(_Unwind_Trace_Fn, void*);
extern "C" std::uintptr_t _Unwind_GetIP_nid_postfix(_Unwind_Context*);
extern "C" void CallWithCleanup(void (*function)(), int* count);

extern "C" void* __cxa_begin_catch(void* exception) { return __cxa_begin_catch_nid_postfix(exception); }
extern "C" void __cxa_end_catch() { __cxa_end_catch_nid_postfix(); }
extern "C" void _Unwind_Resume(_Unwind_Exception* exception) { _Unwind_Resume_nid_postfix(exception); }

namespace {

int destroyed = 0;

struct Guard {
    ~Guard() {
        assert(__cxa_uncaught_exceptions_nid_postfix() > 0);
        ++destroyed;
    }
};

[[gnu::noinline]] void ThrowGuest() {
    Guard guard;
    _ZSt14_Xout_of_rangePKc_nid_postfix("macOS guest unwind");
}

}

int main() {
    try {
        ThrowGuest();
        assert(false);
    } catch (const std::logic_error& error) {
        assert(std::strcmp(error.what(), "macOS guest unwind") == 0);
    }
    assert(destroyed == 1);
    try {
        CallWithCleanup(ThrowGuest, &destroyed);
        assert(false);
    } catch (const std::logic_error& error) {
        assert(std::strcmp(error.what(), "macOS guest unwind") == 0);
    }
    assert(destroyed == 3);
    int frames = 0;
    const auto result = _Unwind_Backtrace_nid_postfix([](_Unwind_Context* context, void* argument) {
        assert(_Unwind_GetIP_nid_postfix(context) != 0);
        ++*static_cast<int*>(argument);
        return _URC_NO_REASON;
    }, &frames);
    if (result != _URC_END_OF_STACK || frames < 1) {
        std::fprintf(stderr, "macOS guest backtrace result=%d frames=%d\n", result, frames);
        return 1;
    }
    return 0;
}
