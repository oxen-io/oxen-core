#pragma once

#include <chrono>
#include <atomic>
#include "crypto/crypto.h"

namespace tools
{
// Periodic timer that gatekeeps calling of a job to a minimum interval after the previous job
// finished.  Only the reset() call is thread-safe; everything else should be confined to the
// owning thread.
class periodic_task
{
  public:
      explicit periodic_task(std::chrono::microseconds interval,
                             bool start_immediately = true,
                             std::pair<int, int> random_delay_interval = {})
      : m_interval{interval}
      , m_last_worked_time{std::chrono::steady_clock::now()}
      , m_trigger_now{start_immediately}
      , m_random_delay_interval{random_delay_interval}
      , m_next_delay{std::chrono::microseconds(crypto::random_range(m_random_delay_interval.first, m_random_delay_interval.second))}
      {}

  template <class functor_t>
  void do_call(functor_t functr)
  {
    if (m_trigger_now || std::chrono::steady_clock::now() - m_last_worked_time > (m_interval + m_next_delay))
    {
      functr();
      m_last_worked_time = std::chrono::steady_clock::now();
      m_trigger_now = false;
      m_next_delay = std::chrono::microseconds(crypto::random_range(m_random_delay_interval.first, m_random_delay_interval.second));
    }
  }

  // Makes the next task attempt run the job, regardless of the time since the last job. Atomic.
  void reset() { m_trigger_now = true; }
  // Returns the current interval
  std::chrono::microseconds interval() const { return m_interval; }
  // Changes the current interval
  void interval(std::chrono::microseconds us) { m_interval = us; }

private:
  std::chrono::microseconds m_interval;
  std::chrono::steady_clock::time_point m_last_worked_time;
  std::atomic<bool> m_trigger_now;
  std::pair<int, int> m_random_delay_interval;
  std::chrono::microseconds m_next_delay;
};
};
