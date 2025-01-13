// Copyright (c) 2019-2020, The Loki Project
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#pragma once

#include <concepts>
#include <mutex>
#include <shared_mutex>
#include <tuple>

namespace tools {

template <typename T>
concept lockable = requires(T a) {
    a.lock();
    a.unlock();
    { a.try_lock() } -> std::convertible_to<bool>;
};

template <typename T>
concept shared_lockable = requires(T a) {
    a.lock_shared();
    a.unlock_shared();
    { a.try_lock_shared() } -> std::convertible_to<bool>;
};

/// Takes any number of lockable objects, locks them atomically, and returns a tuple of
/// std::unique_lock holding the individual locks.
template <lockable... T>
[[nodiscard]] std::tuple<std::unique_lock<T>...> unique_locks(T&... lockables) {
    std::lock(lockables...);
    auto locks = std::make_tuple(std::unique_lock<T>(lockables, std::adopt_lock)...);
    return locks;
}

template <typename T>
struct shared_or_unique_lock_t {
    using type = std::unique_lock<T>;
};
template <shared_lockable T>
struct shared_or_unique_lock_t<T> {
    using type = std::shared_lock<T>;
};
template <typename T>
using shared_or_unique_lock = typename shared_or_unique_lock_t<T>::type;

/// Takes any number of shared lockable or lockable objects, locks them all, and returns a tuple of
/// std::unique_lock or std::shared_locks holding the individual locks: std::shared_lock is used if
/// the lockable object supports shared locking, otherwise you get a std::unique_lock.
template <typename... T>
    requires((shared_lockable<T> || lockable<T>) && ...)
[[nodiscard]] std::tuple<shared_or_unique_lock<T>...> shared_locks(T&... lockables) {
    auto locks = std::make_tuple(shared_or_unique_lock<T>(lockables, std::defer_lock)...);
    std::apply(std::lock<shared_or_unique_lock<T>...>, locks);
    return locks;
}

/// Takes a std::shared_lock, unlocks it (if locked), then re-locks the mutex in a std::unique_lock
/// which gets returned.  If the shared_lock is *not* initially locked (or is empty) then the
/// returned unique_lock will also be unlocked (or empty).
template <lockable Mutex>
[[nodiscard]] std::unique_lock<Mutex> upgrade_lock(std::shared_lock<Mutex>& shared) {
    auto* mutex = shared.mutex();
    if (!mutex)
        return {};

    std::unique_lock unique{*mutex, std::defer_lock};
    if (shared) {
        shared.unlock();
        unique.lock();
    }
    return unique;
}

/// Takes a std::unique_lock, unlocks it (if locked), then re-locks the mutex in a std::shared_lock
/// which gets returned.  If the unique_lock is *not* initially locked (or is empty) then the
/// returned shared_lock will also be unlocked (or empty).
template <shared_lockable Mutex>
[[nodiscard]] std::shared_lock<Mutex> downgrade_lock(std::unique_lock<Mutex>& unique) {
    auto* mutex = unique.mutex();
    if (!mutex)
        return {};

    std::shared_lock shared{*mutex, std::defer_lock};
    if (unique) {
        unique.unlock();
        shared.lock();
    }
    return shared;
}

}  // namespace tools
