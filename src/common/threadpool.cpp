// Copyright (c) 2017-2019, The Monero Project
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
#include "common/threadpool.h"

#include "common/util.h"
#include "cryptonote_config.h"
#include "epee/misc_log_ex.h"
#include "logging/oxen_logger.h"

static thread_local int depth = 0;
static thread_local bool is_leaf = false;

namespace tools {

threadpool::threadpool(unsigned int max_threads) : running(true), active(0) {
    create(max_threads);
}

threadpool::~threadpool() {
    destroy();
}

void threadpool::destroy() {
    try {
        const std::unique_lock lock{mutex};
        running = false;
        has_work.notify_all();
    } catch (...) {
        // if the lock throws, we're just do it without a lock and hope,
        // since the alternative is terminate
        running = false;
        has_work.notify_all();
    }
    for (size_t i = 0; i < threads.size(); i++) {
        try {
            threads[i].join();
        } catch (...) { /* ignore */
        }
    }
    threads.clear();
}

void threadpool::recycle() {
    destroy();
    create(max);
}

void threadpool::create(unsigned int max_threads) {
    const std::unique_lock lock{mutex};
    max = max_threads ? max_threads : tools::get_max_concurrency();
    running = true;
    for (size_t i = max ? max : 1; i > 0; i--) {
        threads.emplace_back([this] { run(false); });
    }
}

void threadpool::submit(waiter* obj, std::function<void()> f, bool leaf) {
    if (is_leaf) {
        auto logcat = oxen::log::Cat("threadpool");
        ASSERT_MES_AND_THROW("A leaf routine is using a thread pool");
    }
    std::unique_lock lock{mutex};
    if (!leaf && ((active == max && !queue.empty()) || depth > 0)) {
        // if all available threads are already running
        // and there's work waiting, just run in current thread
        lock.unlock();
        ++depth;
        is_leaf = leaf;
        f();
        --depth;
        is_leaf = false;
    } else {
        if (obj)
            obj->inc();
        if (leaf)
            queue.push_front({obj, f, leaf});
        else
            queue.push_back({obj, f, leaf});
        has_work.notify_one();
    }
}

unsigned int threadpool::get_max_concurrency() const {
    return max;
}

threadpool::waiter::~waiter() {
    try {
        std::unique_lock lock{mt};
        if (num)
            log::error(
                    globallogcat, "wait should have been called before waiter dtor - waiting now");
    } catch (...) { /* ignore */
    }
    try {
        wait(NULL);
    } catch (const std::exception& e) {
        /* ignored */
    }
}

void threadpool::waiter::wait(threadpool* tpool) {
    if (tpool)
        tpool->run(true);
    std::unique_lock lock{mt};
    while (num)
        cv.wait(lock);
}

void threadpool::waiter::inc() {
    const std::unique_lock lock{mt};
    num++;
}

void threadpool::waiter::dec() {
    const std::unique_lock lock{mt};
    num--;
    if (!num)
        cv.notify_all();
}

void threadpool::run(bool flush) {
    std::unique_lock lock{mutex};
    while (running) {
        entry e;
        while (queue.empty() && running) {
            if (flush)
                return;
            has_work.wait(lock);
        }
        if (!running)
            break;

        active++;
        e = std::move(queue.front());
        queue.pop_front();
        lock.unlock();
        ++depth;
        is_leaf = e.leaf;
        e.f();
        --depth;
        is_leaf = false;

        if (e.wo)
            e.wo->dec();
        lock.lock();
        active--;
    }
}
}  // namespace tools
