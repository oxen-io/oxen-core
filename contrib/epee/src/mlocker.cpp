// Copyright (c) 2018, The Monero Project
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

#if defined __GNUC__ && !defined _WIN32 && !defined __ANDROID__
#define HAVE_MLOCK 1
#endif

#include <unistd.h>
#if defined HAVE_MLOCK
#include <sys/mman.h>
#endif
#include <atomic>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <map>
#include <mutex>
#include <utility>

#include "epee/misc_log_ex.h"
#include "epee/mlocker.h"

// did an mlock operation previously fail? we only
// want to log an error once and be done with it
static std::atomic<bool> previously_failed{false};

static size_t query_page_size() {
#if defined HAVE_MLOCK
    long ret = sysconf(_SC_PAGESIZE);
    if (ret <= 0) {
        return 0;
    }
    return ret;
#else
#warning Missing query_page_size implementation
#endif
    return 0;
}

static void do_lock(void* ptr, size_t len) {
#if defined HAVE_MLOCK
    int ret = mlock(ptr, len);
#else
#warning Missing do_lock implementation
#endif
}

static void do_unlock(void* ptr, size_t len) {
#if defined HAVE_MLOCK
    int ret = munlock(ptr, len);
#else
#warning Missing implementation of page size detection
#endif
}

namespace epee {
size_t mlocker::page_size = 0;
size_t mlocker::num_locked_objects = 0;

std::mutex& mlocker::mutex() {
    static std::mutex* vmutex = new std::mutex();
    return *vmutex;
}
std::map<size_t, unsigned int>& mlocker::map() {
    static std::map<size_t, unsigned int>* vmap = new std::map<size_t, unsigned int>();
    return *vmap;
}

size_t mlocker::get_page_size() {
#if defined(HAVE_MLOCK)
    std::lock_guard lock{mutex()};
    if (page_size == 0)
        page_size = query_page_size();
    return page_size;
#else
    return 0;
#endif
}

mlocker::mlocker(void* ptr, size_t len) : ptr(ptr), len(len) {
#if defined(HAVE_MLOCK)
    lock(ptr, len);
#endif
}

mlocker::~mlocker() {
#if defined(HAVE_MLOCK)
    try {
        unlock(ptr, len);
    } catch (...) { /* ignore and do not propagate through the dtor */
    }
#endif
}

void mlocker::lock(void* ptr, size_t len) {
#if defined(HAVE_MLOCK)
    TRY_ENTRY();

    size_t page_size = get_page_size();
    if (page_size == 0)
        return;

    std::lock_guard lock{mutex()};
    const size_t first = ((uintptr_t)ptr) / page_size;
    const size_t last = (((uintptr_t)ptr) + len - 1) / page_size;
    for (size_t page = first; page <= last; ++page)
        lock_page(page);
    ++num_locked_objects;

    CATCH_ENTRY("mlocker::lock", void());
#endif
}

void mlocker::unlock(void* ptr, size_t len) {
#if defined(HAVE_MLOCK)
    TRY_ENTRY();

    size_t page_size = get_page_size();
    if (page_size == 0)
        return;
    std::lock_guard lock{mutex()};
    const size_t first = ((uintptr_t)ptr) / page_size;
    const size_t last = (((uintptr_t)ptr) + len - 1) / page_size;
    for (size_t page = first; page <= last; ++page)
        unlock_page(page);
    --num_locked_objects;

    CATCH_ENTRY("mlocker::lock", void());
#endif
}

size_t mlocker::get_num_locked_pages() {
#if defined(HAVE_MLOCK)
    std::lock_guard lock{mutex()};
    return map().size();
#else
    return 0;
#endif
}

size_t mlocker::get_num_locked_objects() {
#if defined(HAVE_MLOCK)
    std::lock_guard lock{mutex()};
    return num_locked_objects;
#else
    return 0;
#endif
}

void mlocker::lock_page(size_t page) {
#if defined(HAVE_MLOCK)
    std::pair<std::map<size_t, unsigned int>::iterator, bool> p =
            map().insert(std::make_pair(page, 1));
    if (p.second) {
        do_lock((void*)(page * page_size), page_size);
    } else {
        ++p.first->second;
    }
#endif
}

void mlocker::unlock_page(size_t page) {
#if defined(HAVE_MLOCK)
    std::map<size_t, unsigned int>::iterator i = map().find(page);
    if (i != map().end()) {
        if (!--i->second) {
            map().erase(i);
            do_unlock((void*)(page * page_size), page_size);
        }
    }
#endif
}
}  // namespace epee
