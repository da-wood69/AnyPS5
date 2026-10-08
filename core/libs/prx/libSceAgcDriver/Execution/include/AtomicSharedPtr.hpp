#ifndef CORE_LIBS_PRX_LIBSCEAGCDRIVER_EXECUTION_INCLUDE_ATOMICSHAREDPTR_HPP
#define CORE_LIBS_PRX_LIBSCEAGCDRIVER_EXECUTION_INCLUDE_ATOMICSHAREDPTR_HPP

#include <atomic>
#include <memory>
#include <utility>

namespace AgcDriver {

template <typename T>
class AtomicSharedPtr {
public:
    AtomicSharedPtr() noexcept = default;
    AtomicSharedPtr(std::nullptr_t) noexcept {}
    AtomicSharedPtr(const AtomicSharedPtr&) = delete;
    AtomicSharedPtr& operator=(const AtomicSharedPtr&) = delete;

    std::shared_ptr<T> load(std::memory_order order = std::memory_order_seq_cst) const noexcept { return std::atomic_load_explicit(&value, order); }

    void store(std::shared_ptr<T> desired, std::memory_order order = std::memory_order_seq_cst) noexcept { std::atomic_store_explicit(&value, std::move(desired), order); }

    std::shared_ptr<T> exchange(std::shared_ptr<T> desired, std::memory_order order = std::memory_order_seq_cst) noexcept { return std::atomic_exchange_explicit(&value, std::move(desired), order); }

private:
    std::shared_ptr<T> value;
};

}

#endif
