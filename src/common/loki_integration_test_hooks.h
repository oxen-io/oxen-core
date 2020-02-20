#if defined(LOKI_ENABLE_INTEGRATION_TEST_HOOKS)

#if defined _WIN32
#error "Not implemented"
#endif

#ifndef LOKI_INTEGRATION_TEST_HOOKS_H
#define LOKI_INTEGRATION_TEST_HOOKS_H

//
// Header
//
#include <mutex>
#include <vector>
#include "command_line.h"

namespace integration_test
{
void                     init                 (std::string const &base_name);
void                     deinit               ();
std::string              read_from_pipe       ();
void                     write_buffered_stdout();
void                     use_standard_cout    ();
void                     use_redirected_cout  ();
std::vector<std::string> space_delimit_input  (std::string const &input);

extern const command_line::arg_descriptor<std::string, false> arg_hardforks_override;
extern const command_line::arg_descriptor<std::string, false> arg_pipe_name;

extern struct state_t
{
  std::mutex mutex;
  bool core_is_idle;
  bool disable_checkpoint_quorum;
  bool disable_obligation_quorum;
  bool disable_obligation_uptime_proof;
  bool disable_obligation_checkpointing;
} state;

}; // integration_test

#endif // LOKI_INTEGRATION_TEST_HOOKS_H

// -------------------------------------------------------------------------------------------------
//
// CPP Implementation
//
// -------------------------------------------------------------------------------------------------
#ifdef LOKI_INTEGRATION_TEST_HOOKS_IMPLEMENTATION
#include <string.h>
#include <assert.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <iostream>

namespace integration_test
{
const command_line::arg_descriptor<std::string, false> arg_hardforks_override = {
  "integration-test-hardforks-override"
, "Specify custom hardfork heights and launch in regtest mode"
, ""
, false
};

const command_line::arg_descriptor<std::string, false> arg_pipe_name = {
  "integration-test-pipe-name"
, "Specify the pipe name for stdin and stdout"
, "loki-default-pipe-name"
, false
};

state_t state;
}; // namespace integration_test

struct ipc_pipe
{
  int         fd;
  std::string file;
};
ipc_pipe read_pipe;
ipc_pipe write_pipe;

uint32_t const MSG_PACKET_MAGIC = 0x27befd93;
struct msg_packet
{
  uint32_t magic = MSG_PACKET_MAGIC;
  char buf[1024];
  int  len;
  bool has_more;
};

static std::ostringstream  global_redirected_cout;
static std::streambuf     *global_std_cout;
void integration_test::use_standard_cout()   { if (!global_std_cout) { global_std_cout = std::cout.rdbuf(); } std::cout.rdbuf(global_std_cout); }
void integration_test::use_redirected_cout() { if (!global_std_cout) { global_std_cout = std::cout.rdbuf(); } std::cout.rdbuf(global_redirected_cout.rdbuf()); }
void integration_test::init(const std::string &base_name)
{
  read_pipe.file  = base_name + "_stdin";
  write_pipe.file = base_name + "_stdout";
  read_pipe.fd    = open(read_pipe.file.c_str(), O_RDONLY);
  if (read_pipe.fd == -1)
  {
    perror("Failed to open read pipe");
    assert(false);
  }
  else
  {
    fprintf(stdout, "---------- Opened read pipe: %.*s\n", (int)read_pipe.file.size(), read_pipe.file.c_str());
    fprintf(stdout, "---------- Opened write pipe: %.*s\n", (int)write_pipe.file.size(), write_pipe.file.c_str());
  }
}

void integration_test::deinit()
{
  close(read_pipe.fd);
  close(write_pipe.fd);
}

std::vector<std::string> integration_test::space_delimit_input(std::string const &input)
{
  std::vector<std::string> args;
  std::string::const_iterator start = input.begin();
  for (auto it = input.begin(); it != input.end(); it++)
  {
    if (*it == ' ')
    {
      std::string result(start, it);
      start = (it + 1);
      args.push_back(result);
    }
  }

  if (start != input.end())
  {
    std::string last(start, input.end());
    args.push_back(last);
  }

  return args;
}

std::string integration_test::read_from_pipe()
{
  std::unique_lock<std::mutex> scoped_lock(integration_test::state.mutex);
  std::string result;

  for (;;)
  {
    msg_packet packet = {};
    int bytes_read    = read(read_pipe.fd, reinterpret_cast<void *>(&packet), sizeof(packet));
    if (bytes_read == -1)
    {
      perror("Error returned from read(...)");
      return result;
    }

    if (bytes_read < static_cast<int>(sizeof(packet)))
    {
      fprintf(stderr, "Error reading packet from pipe expected=%zu, read=%d, possible that the pipe was cut mid-transmission\n", sizeof(packet), bytes_read);
      return result;
    }

    if (packet.magic != MSG_PACKET_MAGIC)
    {
      fprintf(stderr, "Packet magic value=%x, does not match expected=%x\n", packet.magic, MSG_PACKET_MAGIC);
      exit(-1);
    }

    fprintf(stdout, "---------- Read packet, len=%d msg=\"%.*s\"\n", packet.len, packet.len, packet.buf);
    result.append(packet.buf, packet.len);
    if (!packet.has_more) break;
  }
  return result;
}

static char const *make_msg_packet(char const *src, int *len, msg_packet *dest)
{
  *dest                   = {};
  int const max_size      = static_cast<int>(sizeof(dest->buf));
  int const bytes_to_copy = (*len > max_size) ? max_size : *len;

  memcpy(dest->buf, src, bytes_to_copy);
  dest->len = bytes_to_copy;
  *len -= bytes_to_copy;

  char const *result = (*len == 0) ? nullptr : src + bytes_to_copy;
  dest->has_more     = result != nullptr;
  return result;
}

void integration_test::write_buffered_stdout()
{
  std::unique_lock<std::mutex> scoped_lock(integration_test::state.mutex);

  global_redirected_cout.flush();
  std::string output = global_redirected_cout.str();
  global_redirected_cout.str("");

  global_redirected_cout.clear();
  if (write_pipe.fd == 0)
  {
    write_pipe.fd = open(write_pipe.file.c_str(), O_WRONLY);
    if (write_pipe.fd == -1)
    {
      perror("Failed to open write pipe");
      assert(false);
    }
  }

  char const *src = output.c_str();
  int src_len     = static_cast<int>(output.size());
  while (src_len > 0)
  {
    msg_packet packet = {};
    src               = make_msg_packet(src, &src_len, &packet);

    int num_bytes_written = write(write_pipe.fd, static_cast<void *>(&packet), sizeof(packet));
    if (num_bytes_written == -1)
      perror("Error returned from write(...)");
  }

  use_standard_cout();
  std::cout << output << std::endl;
  use_redirected_cout();
}

#endif // LOKI_INTEGRATION_TEST_HOOKS_IMPLEMENTATION
#endif // LOKI_ENABLE_INTEGRATION_TEST_HOOKS

