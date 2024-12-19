// Copyright (c) 2014-2018, The Monero Project
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
// 
// Parts of this file are originally copyright (c) 2012-2013 The Cryptonote developers

#pragma once

#include <iomanip>
#include <iostream>
#include <cstdint>
#include <regex>
#include <chrono>

#include "epee/stats.h"
#include "common/perf_timer.h"
#include "timings.h"

struct Params
{
  TimingsDatabase td;
  bool verbose;
  bool stats;
  unsigned loop_multiplier;
};

using namespace std::literals;

template <typename T>
class test_runner
{
public:
  test_runner(const Params &params)
    : m_elapsed(0s)
    , m_params(params)
    , m_per_call_timers(T::loop_count * params.loop_multiplier, {true})
  {
  }

  bool run()
  {
    static_assert(0 < T::loop_count, "T::loop_count must be greater than 0");

    T test;
    if (!test.init())
      return false;

    using clock = std::chrono::steady_clock;
    auto start = clock::now();
    warm_up();
    if (m_params.verbose)
      std::cout << "Warm up: " << std::chrono::duration<double>{clock::now() - start}.count() << " s" << std::endl;

    start = clock::now();
    for (size_t i = 0; i < T::loop_count * m_params.loop_multiplier; ++i)
    {
      if (m_params.stats)
        m_per_call_timers[i].resume();
      if (!test.test())
        return false;
      if (m_params.stats)
        m_per_call_timers[i].pause();
    }
    m_elapsed = clock::now() - start;
    m_stats.reset(new Stats<tools::PerformanceTimer, double>(m_per_call_timers));

    return true;
  }

  std::chrono::duration<double> elapsed_time() const { return m_elapsed; }
  size_t get_size() const { return m_stats->get_size(); }

  std::chrono::duration<double> time_per_call() const
  {
    static_assert(T::loop_count > 0);
    return m_elapsed / (T::loop_count * m_params.loop_multiplier);
  }

  double get_min() const { return m_stats->get_min(); }
  double get_max() const { return m_stats->get_max(); }
  double get_mean() const { return m_stats->get_mean(); }
  double get_median() const { return m_stats->get_median(); }
  double get_stddev() const { return m_stats->get_standard_deviation(); }
  double get_non_parametric_skew() const { return m_stats->get_non_parametric_skew(); }
  std::vector<double> get_quantiles(size_t n) const { return m_stats->get_quantiles(n); }

  bool is_same_distribution(size_t npoints, double mean, double stddev) const
  {
    return m_stats->is_same_distribution_99(npoints, mean, stddev);
  }

private:
  /**
   * Warm up processor core, enabling turbo boost, etc.
   */
  uint64_t warm_up()
  {
    const size_t warm_up_rounds = 1000 * 1000 * 1000;
    m_warm_up = 0;
    for (size_t i = 0; i < warm_up_rounds; ++i)
    {
      ++m_warm_up;
    }
    return m_warm_up;
  }

private:
  volatile uint64_t m_warm_up;  ///<! This field is intended for preclude compiler optimizations
  std::chrono::duration<double> m_elapsed;
  Params m_params;
  std::vector<tools::PerformanceTimer> m_per_call_timers;
  std::unique_ptr<Stats<tools::PerformanceTimer, double>> m_stats;
};

std::string elapsed_str(std::chrono::duration<double> seconds)
{
  std::pair<double, std::string> val;
  if (seconds >= 1s)
    val = {seconds.count(), "s"};
  else if (seconds >= 1ms)
    val = {seconds.count()*1e3, "ms"};
  else if (seconds >= 1us)
    val = {seconds.count()*1e6, u8"µs"};
  else
    val = {seconds.count()*1e9, u8"ns"};
  std::ostringstream s;
  s << std::fixed << std::setprecision(3) << val.first << val.second;
  return s.str();
}
std::string elapsed_str(double seconds) { return elapsed_str(std::chrono::duration<double>{seconds}); }

template <typename T>
void run_test(const std::string &filter, Params &params, const char* test_name)
{
  if (std::cmatch m; !filter.empty() && !std::regex_match(test_name, m, std::regex(filter)))
    return;

  test_runner<T> runner(params);
  if (runner.run())
  {
    if (params.verbose)
    {
      std::cout << test_name << " - OK:\n";
      std::cout << "  loop count:    " << T::loop_count * params.loop_multiplier << '\n';
      std::cout << "  elapsed:       " << elapsed_str(runner.elapsed_time()) << '\n';
      if (params.stats)
      {
        std::cout << "  min:       " << elapsed_str(runner.get_min()) << '\n';
        std::cout << "  max:       " << elapsed_str(runner.get_max()) << '\n';
        std::cout << "  median:    " << elapsed_str(runner.get_median()) << '\n';
        std::cout << "  std dev:   " << elapsed_str(runner.get_stddev()) << '\n';
      }
    }
    else
    {
      std::cout << test_name << " (" << T::loop_count * params.loop_multiplier << " calls) - OK:";
    }
    const auto quantiles = runner.get_quantiles(10);
    double min = runner.get_min();
    double max = runner.get_max();
    double med = runner.get_median();
    double mean = runner.get_mean();
    double stddev = runner.get_stddev();
    double npskew = runner.get_non_parametric_skew();

    std::vector<TimingsDatabase::instance> prev_instances = params.td.get(test_name);
    params.td.add(test_name, {time(NULL), runner.get_size(), min, max, mean, med, stddev, npskew, quantiles});

    std::cout << (params.verbose ? "  time per call: " : " ") << elapsed_str(runner.time_per_call()) << "/call" << (params.verbose ? "\n" : "");
    if (params.stats)
    {
      std::string cmp;
      if (!prev_instances.empty())
      {
        const TimingsDatabase::instance &prev_instance = prev_instances.back();
        if (!runner.is_same_distribution(prev_instance.npoints, prev_instance.mean, prev_instance.stddev))
        {
          double pc = fabs(100. * (prev_instance.mean - runner.get_mean()) / prev_instance.mean);
          cmp = ", " + std::to_string(pc) + "% " + (mean > prev_instance.mean ? "slower" : "faster");
        }
        cmp += "  -- " + std::to_string(prev_instance.mean);
      }
      std::cout << " (min " << elapsed_str(min) << ", 90th " << elapsed_str(quantiles[9]) <<
        ", median " << elapsed_str(med) << ", std dev " << elapsed_str(stddev) << ")" << cmp;
    }
    std::cout << std::endl;
  }
  else
  {
    std::cout << test_name << " - FAILED" << std::endl;
  }
}

#define QUOTEME(x) #x
#define TEST_PERFORMANCE0(filter, params, test_class)         run_test< test_class >(filter, params, QUOTEME(test_class))
#define TEST_PERFORMANCE1(filter, params, test_class, a0)     run_test< test_class<a0> >(filter, params, QUOTEME(test_class<a0>))
#define TEST_PERFORMANCE2(filter, params, test_class, a0, a1) run_test< test_class<a0, a1> >(filter, params, QUOTEME(test_class) "<" QUOTEME(a0) ", " QUOTEME(a1) ">")
#define TEST_PERFORMANCE3(filter, params, test_class, a0, a1, a2) run_test< test_class<a0, a1, a2> >(filter, params, QUOTEME(test_class) "<" QUOTEME(a0) ", " QUOTEME(a1) ", " QUOTEME(a2) ">")
#define TEST_PERFORMANCE4(filter, params, test_class, a0, a1, a2, a3) run_test< test_class<a0, a1, a2, a3> >(filter, params, QUOTEME(test_class) "<" QUOTEME(a0) ", " QUOTEME(a1) ", " QUOTEME(a2) ", " QUOTEME(a3) ">")
#define TEST_PERFORMANCE5(filter, params, test_class, a0, a1, a2, a3, a4) run_test< test_class<a0, a1, a2, a3, a4> >(filter, params, QUOTEME(test_class) "<" QUOTEME(a0) ", " QUOTEME(a1) ", " QUOTEME(a2) ", " QUOTEME(a3) ", " QUOTEME(a4) ">")
#define TEST_PERFORMANCE6(filter, params, test_class, a0, a1, a2, a3, a4, a5) run_test< test_class<a0, a1, a2, a3, a4, a5> >(filter, params, QUOTEME(test_class) "<" QUOTEME(a0) ", " QUOTEME(a1) ", " QUOTEME(a2) ", " QUOTEME(a3) ", " QUOTEME(a4) ", " QUOTEME(a5) ">")
