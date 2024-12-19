
#include "lmq_server.h"
#include "cryptonote_config.h"
#include "oxenmq/oxenmq.h"
#include <fmt/core.h>

#undef OXEN_DEFAULT_LOG_CATEGORY
#define OXEN_DEFAULT_LOG_CATEGORY "daemon.rpc"

namespace cryptonote { namespace rpc {

using oxenmq::AuthLevel;

namespace {

// TODO: all of this --lmq-blah options really should be renamed to --omq-blah, but then we *also*
// need some sort of backwards compatibility shim, and that is a nuissance.

const command_line::arg_descriptor<std::vector<std::string>> arg_omq_public{
  "lmq-public",
  "Adds a public, unencrypted OxenMQ RPC listener (with restricted capabilities) at the given "
    "address; can be specified multiple times. Examples: tcp://0.0.0.0:5555 (listen on port 5555), "
    "tcp://198.51.100.42:5555 (port 5555 on specific IPv4 address), tcp://[::]:5555, "
    "tcp://[2001:db8::abc]:5555 (IPv6), or ipc:///path/to/socket to listen on a unix domain socket"};
const command_line::arg_descriptor<std::vector<std::string>> arg_omq_curve_public{
  "lmq-curve-public",
  "Adds a curve-encrypted OxenMQ RPC listener at the given address that accepts (restricted) rpc "
    "commands from any client. Clients must already know this server's public x25519 key to "
    "establish an encrypted connection."};
const command_line::arg_descriptor<std::vector<std::string>> arg_omq_curve{
  "lmq-curve",
  "Adds a curve-encrypted OxenMQ RPC listener at the given address that only accepts client connections from whitelisted client x25519 pubkeys. "
    "Clients must already know this server's public x25519 key to establish an encrypted connection. When running in service node mode "
    "the quorumnet port is already listening as if specified with --lmq-curve."};
const command_line::arg_descriptor<std::vector<std::string>> arg_omq_admin{
  "lmq-admin",
  "Adds an x25519 pubkey of a client permitted to connect to the --lmq-curve, --lmq-curve-public, or quorumnet address(es) with unrestricted (admin) capabilities."};
const command_line::arg_descriptor<std::vector<std::string>> arg_omq_user{
  "lmq-user",
  "Specifies an x25519 pubkey of a client permitted to connect to the --lmq-curve or quorumnet address(es) with restricted capabilities"};
const command_line::arg_descriptor<std::vector<std::string>> arg_omq_local_control{
  "lmq-local-control",
  "Adds an unencrypted OxenMQ RPC listener with full, unrestricted capabilities and no authentication at the given address. "
#ifndef _WIN32
    "Listens at ipc://<data-dir>/oxend.sock if not specified. Specify 'none' to disable the default. "
#endif
    "WARNING: Do not use this on a publicly accessible address!"};

#ifndef _WIN32
const command_line::arg_descriptor<std::string> arg_omq_umask{
  "lmq-umask",
  "Sets the umask to apply to any listening ipc:///path/to/sock LMQ sockets, in octal.",
  "0007"};
#endif


void check_omq_listen_addr(std::string_view addr) {
  // Crude check for basic validity; you can specify all sorts of invalid things, but at least
  // we can check the prefix for something that looks zmq-y.
  if (addr.size() < 7 || (addr.substr(0, 6) != "tcp://" && addr.substr(0, 6) != "ipc://"))
    throw std::runtime_error("Error: omq listen address '" + std::string(addr) + "' is invalid: expected tcp://IP:PORT, tcp://[IPv6]:PORT or ipc:///path/to/socket");
}


auto as_x_pubkeys(const std::vector<std::string>& pk_strings) {
  std::vector<crypto::x25519_public_key> pks;
  pks.reserve(pk_strings.size());
  for (const auto& pkstr : pk_strings) {
    if (pkstr.size() != 64 || !oxenc::is_hex(pkstr))
      throw std::runtime_error("Invalid LMQ login pubkey: '" + pkstr + "'; expected 64-char hex pubkey");
    pks.emplace_back();
    oxenc::to_hex(pkstr.begin(), pkstr.end(), reinterpret_cast<char *>(&pks.back()));
  }
  return pks;
}

// LMQ RPC responses consist of [CODE, DATA] for code we (partially) mimic HTTP error codes: 200
// means success, anything else means failure.  (We don't have codes for Forbidden or Not Found
// because those happen at the LMQ protocol layer).
constexpr std::string_view
  LMQ_OK{"200"sv},
  LMQ_BAD_REQUEST{"400"sv},
  LMQ_ERROR{"500"sv};

} // end anonymous namespace


void init_omq_options(boost::program_options::options_description& desc)
{
  command_line::add_arg(desc, arg_omq_public);
  command_line::add_arg(desc, arg_omq_curve_public);
  command_line::add_arg(desc, arg_omq_curve);
  command_line::add_arg(desc, arg_omq_admin);
  command_line::add_arg(desc, arg_omq_user);
  command_line::add_arg(desc, arg_omq_local_control);
#ifndef _WIN32
  command_line::add_arg(desc, arg_omq_umask);
#endif
}

omq_rpc::omq_rpc(cryptonote::core& core, core_rpc_server& rpc, const boost::program_options::variables_map& vm)
  : core_{core}, rpc_{rpc}
{
  auto& omq = core.get_omq();
  auto& auth = core._omq_auth_level_map();

  // Set up any requested listening sockets.  (Note: if we are a service node, we'll already have
  // the quorumnet listener set up in cryptonote_core).
  for (const auto &addr : command_line::get_arg(vm, arg_omq_public)) {
    check_omq_listen_addr(addr);
    MGINFO("LMQ listening on " << addr << " (public unencrypted)");
    omq.listen_plain(addr,
        [&core](std::string_view ip, std::string_view pk, bool /*sn*/) { return core.omq_allow(ip, pk, AuthLevel::basic); });
  }

  for (const auto &addr : command_line::get_arg(vm, arg_omq_curve_public)) {
    check_omq_listen_addr(addr);
    MGINFO("LMQ listening on " << addr << " (public curve)");
    omq.listen_curve(addr,
        [&core](std::string_view ip, std::string_view pk, bool /*sn*/) { return core.omq_allow(ip, pk, AuthLevel::basic); });
  }

  for (const auto &addr : command_line::get_arg(vm, arg_omq_curve)) {
    check_omq_listen_addr(addr);
    MGINFO("LMQ listening on " << addr << " (curve restricted)");
    omq.listen_curve(addr,
        [&core](std::string_view ip, std::string_view pk, bool /*sn*/) { return core.omq_allow(ip, pk, AuthLevel::denied); });
  }

  auto locals = command_line::get_arg(vm, arg_omq_local_control);
  if (locals.empty()) {
    // FIXME: this requires unix sockets and so probably won't work on older Windows 10 or pre-Win10
    // windows.  In theory we could do some runtime detection to see if the Windows version is new
    // enough to support unix domain sockets, but for now the Windows default is just "don't listen"
#ifndef _WIN32
    // Push default .oxen/oxend.sock
    locals.push_back("ipc://" + core.get_config_directory().u8string() + "/" + std::string{cryptonote::SOCKET_FILENAME});
    // Pushing old default lokid.sock onto the list. A symlink from .loki -> .oxen so the user should be able
    // to communicate via the old .loki/lokid.sock
    locals.push_back("ipc://" + core.get_config_directory().u8string() + "/" + std::string{cryptonote::old::SOCKET_FILENAME});
#endif
  } else if (locals.size() == 1 && locals[0] == "none") {
    locals.clear();
  }
  for (const auto &addr : locals) {
    check_omq_listen_addr(addr);
    MGINFO("LMQ listening on " << addr << " (unauthenticated local admin)");
    omq.listen_plain(addr,
        [&core](std::string_view ip, std::string_view pk, bool /*sn*/) { return core.omq_allow(ip, pk, AuthLevel::admin); });
  }

#ifndef _WIN32
  auto umask_str = command_line::get_arg(vm, arg_omq_umask);
  try {
    int umask = -1;
    size_t len = 0;
    umask = std::stoi(umask_str, &len, 8);
    if (len != umask_str.size())
      throw std::invalid_argument("not an octal value");
    if (umask < 0 || umask > 0777)
      throw std::invalid_argument("invalid umask value");
    omq.STARTUP_UMASK = umask;
  } catch (const std::exception& e) {
    throw std::invalid_argument("Invalid --lmq-umask value '" + umask_str + "': value must be an octal value between 0 and 0777");
  }
#endif


  // Insert our own pubkey so that, e.g., console commands from localhost automatically get full access
  {
    crypto::x25519_public_key my_pubkey;
    const std::string& pk = omq.get_pubkey();
    std::copy(pk.begin(), pk.end(), my_pubkey.data);
    auth.emplace(std::move(my_pubkey), AuthLevel::admin);
  }

  // User-specified admin/user pubkeys
  for (auto& pk : as_x_pubkeys(command_line::get_arg(vm, arg_omq_admin)))
    auth.emplace(std::move(pk), AuthLevel::admin);
  for (auto& pk : as_x_pubkeys(command_line::get_arg(vm, arg_omq_user)))
    auth.emplace(std::move(pk), AuthLevel::basic);

  // basic (non-admin) rpc commands go into the "rpc." category (e.g. 'rpc.get_info')
  omq.add_category("rpc", AuthLevel::basic, 0 /*no reserved threads*/, 1000 /*max queued requests*/);

  // Admin rpc commands go into "admin.".  We also always keep one (potential) thread reserved for
  // admin RPC commands; that way even if there are loads of basic commands being processed we'll
  // still have room to invoke an admin command without waiting for the basic ones to finish.
  constexpr unsigned int admin_reserved_threads = 1;
  omq.add_category("admin", AuthLevel::admin, admin_reserved_threads);
  for (auto& cmd : rpc_commands) {
    omq.add_request_command(cmd.second->is_public ? "rpc" : "admin", cmd.first,
        [name=std::string_view{cmd.first}, &call=*cmd.second, this](oxenmq::Message& m) {
      if (m.data.size() > 1)
        m.send_reply(LMQ_BAD_REQUEST, "Bad request: RPC commands must have at most one data part "
            "(received " + std::to_string(m.data.size()) + ")");

      rpc_request request{};
      request.context.admin = m.access.auth >= AuthLevel::admin;
      request.context.source = rpc_source::omq;
      request.context.remote = m.remote;
      request.body = m.data.empty() ? ""sv : m.data[0];

      try {
        m.send_reply(LMQ_OK, call.invoke(std::move(request), rpc_));
        return;
      } catch (const parse_error& e) {
        // This isn't really WARNable as it's the client fault; log at info level instead.
        //
        // TODO: for various parsing errors there are still some stupid forced ERROR-level
        // warnings that get generated deep inside epee, for example when passing a string or
        // number instead of a JSON object.  If you want to find some, `grep number2 epee` (for
        // real).
        MINFO("LMQ RPC request '" << (call.is_public ? "rpc." : "admin.") << name << "' called with invalid/unparseable data: " << e.what());
        m.send_reply(LMQ_BAD_REQUEST, "Unable to parse request: "s + e.what());
        return;
      } catch (const rpc_error& e) {
        MWARNING("LMQ RPC request '" << (call.is_public ? "rpc." : "admin.") << name << "' failed with: " << e.what());
        m.send_reply(LMQ_ERROR, e.what());
        return;
      } catch (const std::exception& e) {
        MWARNING("LMQ RPC request '" << (call.is_public ? "rpc." : "admin.") << name << "' "
            "raised an exception: " << e.what());
      } catch (...) {
        MWARNING("LMQ RPC request '" << (call.is_public ? "rpc." : "admin.") << name << "' "
            "raised an unknown exception");
      }
      // Don't include the exception message in case it contains something that we don't want go
      // back to the user.  If we want to support it eventually we could add some sort of
      // `rpc::user_visible_exception` that carries a message to send back to the user.
      m.send_reply(LMQ_ERROR, "An exception occured while processing your request");
    });
  }

  // Subscription commands

  // The "subscribe" category is for public subscriptions; i.e. anyone on a public RPC node, or
  // anyone on a private RPC node with public access level.
  omq.add_category("sub", AuthLevel::basic);

  // TX mempool subscriptions: [sub.mempool, blink] or [sub.mempool, all] to subscribe to new
  // approved mempool blink txes, or to all new mempool txes.  You get back a reply of "OK" or
  // "ALREADY" -- the former indicates that you are newly subscribed for tx updates (either because
  // you weren't subscribed before, or your subscription type changed); the latter indicates that
  // you were already subscribed for the request tx types.  Any other value should be considered an
  // error.
  //
  // Subscriptions expire after 30 minutes.  It is recommended that the client periodically
  // re-subscribe on a much shorter interval than this (perhaps once per minute) and use "OK"
  // replies as a indicator that there was some server-side interruption (such as a restart) that
  // might necessitate the client rechecking the mempool.
  //
  // When a tx arrives the node sends back [notify.mempool, txhash, txblob] every time a new
  // transaction is added to the mempool (minus some additions that aren't really new transactions
  // such as txes that came from an existing block during a rollback).  Note that both txhash and
  // txblob are binary: in particular, txhash is *not* hex-encoded.
  //
  omq.add_request_command("sub", "mempool", [this](oxenmq::Message& m) {

    if (m.data.size() != 1) {
      m.send_reply("Invalid subscription request: no subscription type given");
      return;
    }

    mempool_sub_type sub_type;
    if (m.data[0] == "blink"sv)
      sub_type = mempool_sub_type::blink;
    else if (m.data[0] == "all"sv)
      sub_type = mempool_sub_type::all;
    else {
      m.send_reply("Invalid mempool subscription type '" + std::string{m.data[0]} + "'");
      return;
    }

    {
      std::unique_lock lock{subs_mutex_};
      auto expiry = std::chrono::steady_clock::now() + 30min;
      auto result = mempool_subs_.emplace(m.conn, mempool_sub{expiry, sub_type});
      if (!result.second) {
        result.first->second.expiry = expiry;
        if (result.first->second.type == sub_type) {
          MTRACE("Renewed mempool subscription request from conn id " << m.conn << " @ " << m.remote);
          m.send_reply("ALREADY");
          return;
        }
        result.first->second.type = sub_type;
      }
      MDEBUG("New " << (sub_type == mempool_sub_type::blink ? "blink" : "all") << " mempool subscription request from conn " << m.conn << " @ " << m.remote);
      m.send_reply("OK");
    }
  });

  // New block subscriptions: [sub.block].  This sends a notification every time a new block is
  // added to the blockchain.
  //
  // TODO: make this support [sub.block, sn] so that we can receive notification only for blocks
  // that change the SN composition.
  //
  // The subscription request returns the current [height, blockhash] as a reply.
  //
  // The block notification for new blocks consists of a message [notify.block, height, blockhash]
  // containing the latest height/hash.  (Note that blockhash is the hash in bytes, *not* the hex
  // encoded block hash).
  omq.add_request_command("sub", "block", [this](oxenmq::Message& m) {
      std::unique_lock lock{subs_mutex_};
    auto expiry = std::chrono::steady_clock::now() + 30min;
    auto result = block_subs_.emplace(m.conn, block_sub{expiry});
    if (!result.second) {
      result.first->second.expiry = expiry;
      MTRACE("Renewed block subscription request from conn id " << m.conn << " @ " << m.remote);
      m.send_reply("ALREADY");
    } else {
      MDEBUG("New block subscription request from conn " << m.conn << " @ " << m.remote);
      m.send_reply("OK");
    }
  });

  core_.get_blockchain_storage().hook_block_post_add([this] (const auto& info) { send_block_notifications(info.block); return true; });
  core_.get_pool().add_notify([this](const crypto::hash& id, const transaction& tx, const std::string& blob, const tx_pool_options& opts) {
      send_mempool_notifications(id, tx, blob, opts);
  });
}

template <typename Mutex, typename Subs, typename Call>
static void send_notifies(Mutex& mutex, Subs& subs, const char* desc, Call call) {
  std::vector<oxenmq::ConnectionID> remove;
  {
    std::shared_lock lock{mutex};

    if (subs.empty())
      return;

    auto now = std::chrono::steady_clock::now();

    for (const auto& sub_pair : subs) {
      auto& conn = sub_pair.first;
      auto& sub = sub_pair.second;
      if (sub.expiry < now) {
        remove.push_back(conn);
        continue;
      } else {
        call(conn, sub);
      }
    }
  }

  if (remove.empty())
    return;
  std::unique_lock lock{mutex};
  auto now = std::chrono::steady_clock::now();
  for (auto& conn : remove) {
    auto it = subs.find(conn);
    if (it != subs.end() && it->second.expiry < now /* recheck: client might have resubscribed in between locks */) {
      MDEBUG("Removing " << conn << " from " << desc << " subscriptions: subscription timed out");
      subs.erase(it);
    }
  }
}

void omq_rpc::send_block_notifications(const block& block)
{
  auto& omq = core_.get_omq();
  std::string height = fmt::format("{}", get_block_height(block));
  send_notifies(subs_mutex_, block_subs_, "block", [&](auto& conn, auto& sub) {
    omq.send(conn, "notify.block", height, std::string_view{block.hash.data, sizeof(block.hash.data)});
  });
}

void omq_rpc::send_mempool_notifications(const crypto::hash& id, const transaction& tx, const std::string& blob, const tx_pool_options& opts)
{
  auto& omq = core_.get_omq();
  send_notifies(subs_mutex_, mempool_subs_, "mempool", [&](auto& conn, auto& sub) {
    if (sub.type == mempool_sub_type::all || opts.approved_blink)
      omq.send(conn, "notify.mempool", std::string_view{id.data, sizeof(id.data)}, blob);
  });
}


}} // namespace cryptonote::rpc
