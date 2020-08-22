// Copyright (c) 2018, The Loki Project
// Copyright (c) 2014-2019, The Monero Project
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

#include <string>
#include <iomanip>
#include <thread>

#include <openssl/ssl.h>

#include "unbound.h"

#include "include_base_utils.h"
#include "string_tools.h"
#include "wipeable_string.h"
#include "crypto/crypto.h"
#include "util.h"
#include "stack_trace.h"
#include "misc_os_dependent.h"
#include "readline_buffer.h"
#include "string_util.h"
#include <boost/filesystem/path.hpp>

#include "i18n.h"

#ifdef __GLIBC__
#include <sys/resource.h>
#include <gnu/libc-version.h>
#endif

#undef LOKI_DEFAULT_LOG_CATEGORY
#define LOKI_DEFAULT_LOG_CATEGORY "util"

namespace tools
{

  static bool unbound_built_with_threads()
  {
    ub_ctx *ctx = ub_ctx_create();
    if (!ctx) return false; // cheat a bit, should not happen unless OOM
    char *loki = strdup("loki"), *unbound = strdup("unbound");
    ub_ctx_zone_add(ctx, loki, unbound); // this calls ub_ctx_finalize first, then errors out with UB_SYNTAX
    free(unbound);
    free(loki);
    // if no threads, bails out early with UB_NOERROR, otherwise fails with UB_AFTERFINAL id already finalized
    bool with_threads = ub_ctx_async(ctx, 1) != 0; // UB_AFTERFINAL is not defined in public headers, check any error
    ub_ctx_delete(ctx);
    MINFO("libunbound was built " << (with_threads ? "with" : "without") << " threads");
    return with_threads;
  }

  bool sanitize_locale()
  {
    // boost::filesystem throws for "invalid" locales, such as en_US.UTF-8, or kjsdkfs,
    // so reset it here before any calls to it
    try
    {
      boost::filesystem::path p {std::string("test")};
      p /= std::string("test");
    }
    catch (...)
    {
#if defined(__MINGW32__) || defined(__MINGW__)
      putenv("LC_ALL=C");
      putenv("LANG=C");
#else
      setenv("LC_ALL", "C", 1);
      setenv("LANG", "C", 1);
#endif
      return true;
    }
    return false;
  }

#ifdef STACK_TRACE
#ifdef _WIN32
  // https://stackoverflow.com/questions/1992816/how-to-handle-seg-faults-under-windows
  static LONG WINAPI windows_crash_handler(PEXCEPTION_POINTERS pExceptionInfo)
  {
    tools::log_stack_trace("crashing");
    exit(1);
    return EXCEPTION_CONTINUE_SEARCH;
  }
  static void setup_crash_dump()
  {
    SetUnhandledExceptionFilter(windows_crash_handler);
  }
#else
  static void posix_crash_handler(int signal)
  {
    tools::log_stack_trace(("crashing with fatal signal " + std::to_string(signal)).c_str());
#ifdef NDEBUG
    _exit(1);
#else
    abort();
#endif
  }
  static void setup_crash_dump()
  {
    signal(SIGSEGV, posix_crash_handler);
    signal(SIGBUS, posix_crash_handler);
    signal(SIGILL, posix_crash_handler);
    signal(SIGFPE, posix_crash_handler);
  }
#endif
#else
  static void setup_crash_dump() {}
#endif

  bool disable_core_dumps()
  {
#ifdef __GLIBC__
    // disable core dumps in release mode
    struct rlimit rlimit;
    rlimit.rlim_cur = rlimit.rlim_max = 0;
    if (setrlimit(RLIMIT_CORE, &rlimit))
    {
      MWARNING("Failed to disable core dumps");
      return false;
    }
#endif
    return true;
  }

  ssize_t get_lockable_memory()
  {
#ifdef __GLIBC__
    struct rlimit rlim;
    if (getrlimit(RLIMIT_MEMLOCK, &rlim) < 0)
    {
      MERROR("Failed to determine the lockable memory limit");
      return -1;
    }
    return rlim.rlim_cur;
#else
    return -1;
#endif
  }

  bool on_startup()
  {
    mlog_configure("", true);

    setup_crash_dump();

    sanitize_locale();

#ifdef __GLIBC__
    const char *ver = ::gnu_get_libc_version();
    if (!strcmp(ver, "2.25"))
      MCLOG_RED(el::Level::Warning, "global", "Running with glibc " << ver << ", hangs may occur - change glibc version if possible");
#endif

#if OPENSSL_VERSION_NUMBER < 0x10100000 || defined(LIBRESSL_VERSION_TEXT)
    SSL_library_init();
#else
    OPENSSL_init_ssl(0, NULL);
#endif

    if (!unbound_built_with_threads())
      MCLOG_RED(el::Level::Warning, "global", "libunbound was not built with threads enabled - crashes may occur");

    return true;
  }
  namespace
  {
    std::mutex max_concurrency_lock;
    unsigned max_concurrency = std::thread::hardware_concurrency();
  }

  void set_max_concurrency(unsigned n)
  {
    if (n < 1)
      n = std::thread::hardware_concurrency();
    unsigned hwc = std::thread::hardware_concurrency();
    if (n > hwc)
      n = hwc;
    std::lock_guard lock{max_concurrency_lock};
    max_concurrency = n;
  }

  unsigned get_max_concurrency()
  {
    std::lock_guard lock{max_concurrency_lock};
    return max_concurrency;
  }

  bool is_local_address(const std::string &address)
  {
    return address == "localhost"sv
        || (tools::starts_with(address, "127."sv) && address.find_first_not_of("0123456789."sv) == std::string::npos)
        || address == "::1"sv
        || address == "[::1]"sv; // There are other uncommon ways to specify localhost (e.g. 0::1, ::0001) but don't worry about them.
  }

  int vercmp(std::string_view v0, std::string_view v1)
  {
    auto f0 = tools::split_any(v0, ".-");
    auto f1 = tools::split_any(v1, ".-");
    const auto max = std::max(f0.size(), f1.size());
    for (size_t i = 0; i < max; ++i) {
      if (i >= f0.size())
        return -1;
      if (i >= f1.size())
        return 1;
      int f0i = 0, f1i = 0;
      tools::parse_int(f0[i], f0i);
      tools::parse_int(f1[i], f1i);
      int n = f0i - f1i;
      if (n)
        return n;
    }
    return 0;
  }

  std::optional<std::pair<uint32_t, uint32_t>> parse_subaddress_lookahead(const std::string& str)
  {
    auto pos = str.find(":");
    bool r = pos != std::string::npos;
    uint32_t major;
    r = r && epee::string_tools::get_xtype_from_string(major, str.substr(0, pos));
    uint32_t minor;
    r = r && epee::string_tools::get_xtype_from_string(minor, str.substr(pos + 1));
    if (r)
    {
      return std::make_pair(major, minor);
    }
    else
    {
      return {};
    }
  }

#ifdef _WIN32
  std::string input_line_win()
  {
    HANDLE hConIn = CreateFileW(L"CONIN$", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
    DWORD oldMode;

    FlushConsoleInputBuffer(hConIn);
    GetConsoleMode(hConIn, &oldMode);
    SetConsoleMode(hConIn, ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT | ENABLE_PROCESSED_INPUT);

    wchar_t buffer[1024];
    DWORD read;

    ReadConsoleW(hConIn, buffer, sizeof(buffer)/sizeof(wchar_t)-1, &read, nullptr);
    buffer[read] = 0;

    SetConsoleMode(hConIn, oldMode);
    CloseHandle(hConIn);
  
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, buffer, -1, NULL, 0, NULL, NULL);
    std::string buf(size_needed, '\0');
    WideCharToMultiByte(CP_UTF8, 0, buffer, -1, &buf[0], size_needed, NULL, NULL);
    buf.pop_back(); //size_needed includes null that we needed to have space for
    return buf;
  }
#endif

  std::string get_human_readable_timestamp(uint64_t ts)
  {
    char buffer[64];
    if (ts < 1234567890)
      return "<unknown>";
    time_t tt = ts;
    struct tm tm;
    epee::misc_utils::get_gmt_time(tt, tm);
    strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S UTC", &tm);
    return std::string(buffer);
  }

  std::string get_human_readable_timespan(std::chrono::seconds seconds)
  {
    uint64_t ts = seconds.count();
    if (ts < 60)
      return std::to_string(ts) + tr(" seconds");
    if (ts < 3600)
      return std::to_string((uint64_t)(ts / 60)) + tr(" minutes");
    if (ts < 3600 * 24)
      return std::to_string((uint64_t)(ts / 3600)) + tr(" hours");
    if (ts < 3600 * 24 * 30.5)
      return std::to_string((uint64_t)(ts / (3600 * 24))) + tr(" days");
    if (ts < 3600 * 24 * 365.25)
      return std::to_string((uint64_t)(ts / (3600 * 24 * 30.5))) + tr(" months");
    return tr("a long time");
  }

  std::string get_human_readable_bytes(uint64_t bytes)
  {
    if (bytes < 1000) return std::to_string(bytes) + " B";
    constexpr std::array units{" kB", " MB", " GB", " TB"};
    double b = bytes;
    for (const auto& suffix : units) {
      b /= 1000.;
      if (b < 1000.) {
        std::ostringstream o;
        o << std::fixed << std::setprecision(2) << b;
        return o.str() + suffix;
      }
    }
    return std::to_string(std::lround(b)) + units.back();
  }

  // Calculate a "sync weight" over ranges of blocks in the blockchain, suitable for
  // calculating sync time estimates
  uint64_t cumulative_block_sync_weight(cryptonote::network_type nettype, uint64_t start_block, uint64_t num_blocks)
  {
    // No detailed data available except for Mainnet: Give back the number of blocks
    // as a very simple and non-varying block sync weight for ranges of Testnet and
    // Devnet blocks
    return num_blocks;

    // TODO(loki):
#if 0
    // The following is a table of average blocks sizes in bytes over the Monero mainnet
    // blockchain, where the block size is averaged over ranges of 10,000 blocks
    // (about 2 weeks worth of blocks each).
    // The first array entry of 442 thus means "The average byte size of the blocks
    // 0 .. 9,999 is 442". The info "block_size" from the "get_block_header_by_height"
    // RPC call was used for calculating this. This table (and the whole mechanism
    // of calculating a "sync weight") is most important when estimating times for
    // syncing from scratch. Without it the fast progress through the (in comparison)
    // rather small blocks in the early blockchain) would lead to vastly underestimated
    // total sync times.
    // It's no big problem for estimates that this table will, over time, and if not
    // updated, miss larger and larger parts at the top of the blockchain, as long
    // as block size averages there do not differ wildly.
    // Without time-consuming tests it's hard to say how much the estimates would
    // improve if one would not only take block sizes into account, but also varying
    // verification times i.e. the different CPU effort needed for the different
    // transaction types (pre / post RingCT, pre / post Bulletproofs).
    // Testnet and Devnet are neglected here because of their much smaller
    // importance.
    static const uint32_t average_block_sizes[] =
    {
      442, 1211, 1445, 1763, 2272, 8217, 5603, 9999, 16358, 10805, 5290, 4362,
      4325, 5584, 4515, 5008, 4789, 5196, 7660, 3829, 6034, 2925, 3762, 2545,
      2437, 2553, 2167, 2761, 2015, 1969, 2350, 1731, 2367, 2078, 2026, 3518,
      2214, 1908, 1780, 1640, 1976, 1647, 1921, 1716, 1895, 2150, 2419, 2451,
      2147, 2327, 2251, 1644, 1750, 1481, 1570, 1524, 1562, 1668, 1386, 1494,
      1637, 1880, 1431, 1472, 1637, 1363, 1762, 1597, 1999, 1564, 1341, 1388,
      1530, 1476, 1617, 1488, 1368, 1906, 1403, 1695, 1535, 1598, 1318, 1234,
      1358, 1406, 1698, 1554, 1591, 1758, 1426, 2389, 1946, 1533, 1308, 2701,
      1525, 1653, 3580, 1889, 2913, 8164, 5154, 3762, 3356, 4360, 3589, 4844,
      4232, 3781, 3882, 5924, 10790, 7185, 7442, 8214, 8509, 7484, 6939, 7391,
      8210, 15572, 39680, 44810, 53873, 54639, 68227, 63428, 62386, 68504,
      83073, 103858, 117573, 98089, 96793, 102337, 94714, 129568, 251584,
      132026, 94579, 94516, 95722, 106495, 121824, 153983, 162338, 136608,
      137104, 109872, 91114, 84757, 96339, 74251, 94314, 143216, 155837,
      129968, 120201, 109913, 101588, 97332, 104611, 95310, 93419, 113345,
      100743, 92152, 57565, 22533, 37564, 21823, 19980, 18277, 18402, 14344,
      12142, 15842, 13677, 17631, 18294, 22270, 41422, 39296, 36688, 33512,
      33831, 27582, 22276, 27516, 27317, 25505, 24426, 20566, 23045, 26766,
      28185, 26169, 27011,
      28642    // Blocks 1,990,000 to 1,999,999 in December 2019
    };
    const uint64_t block_range_size = 10000;

    uint64_t num_block_sizes = sizeof(average_block_sizes) / sizeof(average_block_sizes[0]);
    uint64_t weight = 0;
    uint64_t table_index = start_block / block_range_size;
    for (;;) {
      if (num_blocks == 0)
      {
        break;
      }
      if (table_index >= num_block_sizes)
      {
        // Take all blocks beyond our table as having the size of the blocks
        // in the last table entry i.e. in the most recent known block range
        weight += num_blocks * average_block_sizes[num_block_sizes - 1];
        break;
      }
      uint64_t portion_size = std::min(num_blocks, block_range_size - start_block % block_range_size);
      weight += portion_size * average_block_sizes[table_index];
      table_index++;
      num_blocks -= portion_size;
      start_block += portion_size;
    }
    return weight;
#endif
  }
}
