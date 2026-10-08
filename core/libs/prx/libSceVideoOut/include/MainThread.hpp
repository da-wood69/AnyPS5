#ifndef CORE_LIBS_PRX_LIBSCEVIDEOOUT_INCLUDE_MAINTHREAD_HPP
#define CORE_LIBS_PRX_LIBSCEVIDEOOUT_INCLUDE_MAINTHREAD_HPP

#ifdef __APPLE__
#include <dlfcn.h>
#include <exception>
#include <pthread.h>
#include <stdexcept>
#include <type_traits>
#include <utility>
#endif

namespace VideoOutPlatform {

template<class Callback>
void RunOnMainThread(Callback&& callback) {
#ifdef __APPLE__
    if (pthread_main_np() != 0) {
        callback();
        return;
    }
    using Dispatcher = void (*)(void (*)(void*), void*);
    const auto dispatcher = reinterpret_cast<Dispatcher>(dlsym(RTLD_DEFAULT, "AnyPs5RunOnMainThread"));
    if (dispatcher == nullptr) {
        callback();
        return;
    }
    std::exception_ptr failure;
    using CallbackType = std::remove_reference_t<Callback>;
    auto state = std::pair<CallbackType*, std::exception_ptr*>{&callback, &failure};
    dispatcher([](void* context) {
        auto& invocation = *static_cast<decltype(state)*>(context);
        try {
            (*invocation.first)();
        } catch (...) {
            *invocation.second = std::current_exception();
        }
    }, &state);
    if (failure) std::rethrow_exception(failure);
#else
    callback();
#endif
}

}

#endif
