#pragma once

#include <atomic>
#include <chrono>

#include "crypto/crypto.h"
#include "logging/oxen_logger.h"

using namespace std::literals;

namespace tools {
// Periodic timer that gatekeeps calling of a job to a minimum interval after the previous job
// finished.  Only the reset() call is thread-safe; everything else should be confined to the
// owning thread.
class periodic_task {
  public:
    explicit periodic_task(
            std::string description,
            std::chrono::microseconds interval,
            bool start_immediately = true,
            std::chrono::microseconds random_max_delay = 0s) :
            m_description{std::move(description)},
            m_interval{interval},
            m_last_worked_time{std::chrono::steady_clock::now()},
            m_trigger_now{start_immediately},
            m_random_max_delay{random_max_delay},
            m_next_delay{make_delay()} {}

    template <class functor_t>
    void do_call(functor_t functr) {
        if (m_trigger_now ||
            std::chrono::steady_clock::now() - m_last_worked_time > (m_interval + m_next_delay)) {
            try {
                functr();
            } catch (const std::exception& e) {
                log::error(log::Cat("task"), "{} failed: {}", m_description, e.what());
                return;
            }

            m_last_worked_time = std::chrono::steady_clock::now();
            m_trigger_now = false;
            m_next_delay = make_delay();
        }
    }

    std::chrono::microseconds make_delay() const {
        return m_random_max_delay > 0s ? crypto::rand_range(0us, m_random_max_delay) : 0us;
    }

    // Makes the next task attempt run the job, regardless of the time since the last job. Atomic.
    void reset() { m_trigger_now = true; }
    // Returns the current interval
    std::chrono::microseconds interval() const { return m_interval; }
    // Changes the current interval
    void interval(std::chrono::microseconds us) { m_interval = us; }

  private:
    std::string m_description;
    std::chrono::microseconds m_interval;
    std::chrono::steady_clock::time_point m_last_worked_time;
    std::atomic<bool> m_trigger_now;
    std::chrono::microseconds m_random_max_delay;  // Add Unif[0, this] to each interval
    std::chrono::microseconds m_next_delay;
};
};  // namespace tools
