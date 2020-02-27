#include "sn_network.h"
#include "bt_serialize.h"
#include "common/hex.h"
#include <ostream>
#include "common/string_view.h"
#include <sodium.h>
#include <atomic>
#include <queue>
#include <map>

namespace quorumnet {

using namespace std::string_literals;
using namespace std::chrono_literals;

using boost::get;



constexpr char SN_ADDR_COMMAND[] = "inproc://sn-command";
constexpr char SN_ADDR_WORKERS[] = "inproc://sn-workers";
constexpr char SN_ADDR_SELF[] = "inproc://sn-self";
constexpr char ZMQ_ADDR_ZAP[] = "inproc://zeromq.zap.01";

/** How long (in ms) to wait for handshaking to complete on external connections before timing out
 * and closing the connection */
constexpr int SN_HANDSHAKE_TIME = 10000;

/** Maximum incoming message size; if a remote tries sending a message larger than this they get disconnected */
constexpr int64_t SN_ZMQ_MAX_MSG_SIZE = 1 * 1024 * 1024;

/** How long (in ms) to linger sockets when closing them; this is the maximum time zmq spends trying
 * to sending pending messages before dropping them and closing the underlying socket after the
 * high-level zmq socket is closed. */
constexpr int CLOSE_LINGER = 5000;

// Inside some method:
//     SN_LOG(warn, "bad" << 42 << "stuff");
#define SN_LOG(level, stuff) do { if (want_logs(LogLevel::level)) { std::ostringstream o; o << stuff; logger(LogLevel::level, __FILE__, __LINE__, o.str()); } } while (0)

// This is the domain used for listening service nodes.
constexpr const char AUTH_DOMAIN_SN[] = "loki.sn";

void SNNetwork::add_pollitem(zmq::socket_t &sock) {
    pollitems.emplace_back();
    auto &p = pollitems.back();
    p.socket = static_cast<void *>(sock);
    p.fd = 0;
    p.events = ZMQ_POLLIN;
}

extern "C" void message_buffer_destroy(void *, void *hint) {
    delete reinterpret_cast<std::string *>(hint);
}

/// Creates a message without needing to reallocate the contained string data
zmq::message_t create_message(std::string &&data) {
    auto *buffer = new std::string(std::move(data));
    return zmq::message_t{&(*buffer)[0], buffer->size(), message_buffer_destroy, buffer};
};

/// Create a message from a copy of a string (or more generally a string_view, if under C++17)
zmq::message_t create_message(
#ifdef __cpp_lib_string_view
        std::string_view data
#else
        const std::string &data
#endif
) {
    return zmq::message_t{data.begin(), data.end()};
}

/// Creates a message by serializing a bt serialization dict
zmq::message_t create_bt_message(const bt_dict &data) { return create_message(bt_serialize(data)); }

namespace detail {
// Control messages between proxy and threads and between proxy and workers are command codes in the
// first frame followed by an optional bt-serialized dict in the second frame (if specified and
// non-empty).
void send_control(zmq::socket_t &sock, const std::string &cmd, const bt_dict &data) {
    zmq::message_t c{cmd.begin(), cmd.end()};
    if (data.empty()) {
        sock.send(c, zmq::send_flags::none);
    } else {
        zmq::message_t d{quorumnet::bt_serialize(data)};
        sock.send(c, zmq::send_flags::sndmore);
        sock.send(d, zmq::send_flags::none);
    }
}
}

/// Sends a control message to a specific destination by prefixing the worker name (or identity)
/// then appending the command and optional data.  (This is needed when sending the control message
/// to a router socket, i.e. inside the proxy thread).
static void route_control(zmq::socket_t &sock, const std::string &identity, const std::string &cmd, const bt_dict &data = {}) {
    sock.send(zmq::message_t{identity.begin(), identity.end()}, zmq::send_flags::sndmore);
    detail::send_control(sock, cmd, data);
}

/// Constructs a message sequence consisting of a recipient address (generally the pubkey) followed
/// by a bt-serialized value.
std::list<zmq::message_t> create_addressed_bt_message(const std::string &recipient, const bt_dict &data) {
    std::list<zmq::message_t> msgs;
    msgs.emplace_back(recipient.begin(), recipient.end());
    msgs.push_back(create_bt_message(data));
    return msgs;
}

// Receive all the parts of a single message from the given socket.  Returns true if a message was
// received, false if called with flags=zmq::recv_flags::dontwait and no message was available.
template <typename OutputIt>
bool recv_message_parts(zmq::socket_t &sock, OutputIt it, const zmq::recv_flags flags = zmq::recv_flags::none) {
    bool more = true;
    while (more) {
        zmq::message_t msg;
        if (!sock.recv(msg, flags))
            return false;
        more = msg.more();
        *it = std::move(msg);
    }
    return true;
}

template <typename It>
void send_message_parts(zmq::socket_t &sock, It begin, It end) {
    while (begin != end) {
        zmq::message_t &msg = *begin++;
        sock.send(msg, begin == end ? zmq::send_flags::none : zmq::send_flags::sndmore);
    }
}

template <typename Container>
void send_message_parts(zmq::socket_t &sock, Container &&c) {
    send_message_parts(sock, c.begin(), c.end());
}

template <typename It>
void forward_to_worker(zmq::socket_t &workers, std::string worker_id, It parts_begin, It parts_end) {
    assert(parts_begin != parts_end);

    // Forwarded message to worker: this just sends all the parts, but prefixed with the worker
    // name.
    // start with the worker name (so the worker router
    // knows where to send it), then the authenticated remote pubkey, then the message
    // parts.
    workers.send(create_message(std::move(worker_id)), zmq::send_flags::sndmore);
    send_message_parts(workers, parts_begin, parts_end);
}

std::string pop_string(std::list<zmq::message_t> &msgs) {
    if (msgs.empty())
        throw std::runtime_error("Expected message parts was empty!");
    std::string msg{msgs.front().data<char>(), msgs.front().size()};
    msgs.pop_front();
    return msg;
}

template <typename MessageContainer>
std::vector<std::string> as_strings(const MessageContainer &msgs) {
    std::vector<std::string> result;
    result.reserve(msgs.size());
    for (const auto &msg : msgs)
        result.emplace_back(msg.template data<char>(), msg.size());
    return result;
}

// Returns a string view of the given message data.  If real std::string_views are available,
// returns one, otherwise returns a simple partial implementation of string_view.  It's the caller's
// responsibility to keep the message alive.
common::string_view view(const zmq::message_t &m) {
    return {m.data<char>(), m.size()};
}

#ifndef __cpp_inline_variables
constexpr const std::chrono::milliseconds SNNetwork::default_send_keep_alive;
#endif

static std::string command_type_string(SNNetwork::command_type t) {
    return
            t == SNNetwork::command_type::quorum ? "quorum" :
            t == SNNetwork::command_type::public_ ? "public" :
            t == SNNetwork::command_type::response ? "response" :
            "unknown";
}
static std::ostream& operator<<(std::ostream& o, SNNetwork::command_type t) {
    return o << command_type_string(t);
}

std::unordered_map<std::string, std::pair<void(*)(SNNetwork::message &message, void *data), SNNetwork::command_type>> SNNetwork::commands;
bool SNNetwork::commands_mutable = true;
void SNNetwork::register_command(std::string command, command_type cmd_type,
        void(*callback)(SNNetwork::message &message, void *data)) {
    assert(cmd_type >= SNNetwork::command_type::quorum && cmd_type <= SNNetwork::command_type::response);

    if (!commands_mutable)
        throw std::logic_error("Failed to register " + command_type_string(cmd_type) + " command: command must be added before constructing a SNNetwork instance");

    commands.emplace(std::move(command), std::make_pair(callback, cmd_type));
}

std::atomic<int> next_id{1};

/// We have one mutex here that is generally used once per thread: to create a thread-local command
/// socket to talk to the proxy thread's control socket.  We need the proxy thread to also have a
/// copy of it so that it can close them when it is exiting.
std::mutex local_control_mutex;

/// Accesses a thread-local command socket connected to the proxy's command socket used to issue
/// commands in a thread-safe manner.  A mutex is only required here the first time a thread
/// accesses the control socket.
zmq::socket_t &SNNetwork::get_control_socket() {
    // Maps the SNNetwork unique ID to a local thread command socket.
    static thread_local std::map<int, std::shared_ptr<zmq::socket_t>> control_sockets;
    static thread_local std::pair<int, std::shared_ptr<zmq::socket_t>> last{-1, nullptr};

    // Optimize by caching the last value; SNNetwork is often a singleton and in that case we're
    // going to *always* hit this optimization.  Even if it isn't, we're probably likely to need the
    // same control socket from the same thread multiple times sequentially so this may still help.
    if (object_id == last.first)
        return *last.second;

    auto it = control_sockets.find(object_id);
    if (it != control_sockets.end()) {
        last = *it;
        return *last.second;
    }

    std::lock_guard<std::mutex> lock{local_control_mutex};
    zmq::socket_t foo{context, zmq::socket_type::dealer};
    auto control = std::make_shared<zmq::socket_t>(context, zmq::socket_type::dealer);
    control->setsockopt<int>(ZMQ_LINGER, 0);
    control->connect(SN_ADDR_COMMAND);
    thread_control_sockets.push_back(control);
    control_sockets.emplace(object_id, control);
    last.first = object_id;
    last.second = std::move(control);
    return *last.second;
}


SNNetwork::SNNetwork(
        std::string pubkey_, std::string privkey_,
        const std::vector<std::string> &bind,
        LookupFunc lookup,
        AllowFunc allow,
        WantLog want_log,
        WriteLog log,
        unsigned int max_workers)
    : object_id{next_id++}, pubkey{std::move(pubkey_)}, privkey{std::move(privkey_)}, peer_lookup{std::move(lookup)}, allow_connection{std::move(allow)},
    want_logs{want_log}, logger{log}, poll_remote_offset{poll_internal_size + 1}, max_workers{max_workers}
{
    SN_LOG(trace, "Constructing listening SNNetwork, id=" << object_id << ", this=" << this);

    if (bind.empty())
        throw std::invalid_argument{"Cannot create a service node listener with no address(es) to bind"};

    listener = std::make_unique<zmq::socket_t>(context, zmq::socket_type::router);

    launch_proxy_thread(bind);
}

SNNetwork::SNNetwork(
        LookupFunc lookup,
        AllowFunc allow,
        WantLog want_log,
        WriteLog log,
        unsigned int max_workers)
    : object_id{next_id++}, peer_lookup{std::move(lookup)}, allow_connection{std::move(allow)},
        want_logs{want_log}, logger{log}, poll_remote_offset{poll_internal_size}, max_workers{max_workers}
{
    SN_LOG(trace, "Constructing remote-only SNNetwork, id=" << object_id << ", this=" << this);

    SN_LOG(debug, "generating x25519 keypair for remote-only SNNetwork instance");
    pubkey.resize(crypto_box_PUBLICKEYBYTES);
    privkey.resize(crypto_box_SECRETKEYBYTES);
    crypto_box_keypair(reinterpret_cast<unsigned char *>(&pubkey[0]), reinterpret_cast<unsigned char *>(&privkey[0]));

    launch_proxy_thread({});
}

void SNNetwork::launch_proxy_thread(const std::vector<std::string> &bind) {

    commands_mutable = false;

    SN_LOG(info, "Initializing SNNetwork quorumnet " << (bind.empty() ? "remote-only" : "listener") << " with pubkey " << as_hex(pubkey));
    assert(pubkey.size() == 32 && privkey.size() == 32);

    if (max_workers == 0)
        max_workers = 1;

    {
        // We bind here so that the `get_control_socket()` below is always connecting to a bound
        // socket, but then proxy thread is responsible for the `command` socket.
        command.bind(SN_ADDR_COMMAND);
        proxy_thread = std::thread{&SNNetwork::proxy_loop, this, bind};

        SN_LOG(debug, "Waiting for proxy thread to get ready...");
        auto &control = get_control_socket();
        detail::send_control(control, "START");
        SN_LOG(trace, "Sent START command");

        zmq::message_t ready_msg;
        std::list<zmq::message_t> parts;
        try { recv_message_parts(control, std::back_inserter(parts)); }
        catch (const zmq::error_t &e) { throw std::runtime_error("Failure reading from SNNetwork::Proxy thread: "s + e.what()); }

        if (!(parts.size() == 1 && view(parts.front()) == "READY"))
            throw std::runtime_error("Invalid startup message from proxy thread (didn't get expected READY message)");
        SN_LOG(debug, "Proxy thread is ready");
    }
}


void SNNetwork::spawn_worker(std::string id) {
    worker_threads.emplace(std::piecewise_construct, std::make_tuple(id), std::make_tuple(&SNNetwork::worker_thread, this, id));
}

void SNNetwork::worker_thread(std::string worker_id) {
    zmq::socket_t sock{context, zmq::socket_type::dealer};
#if ZMQ_VERSION >= ZMQ_MAKE_VERSION (4, 3, 0)
    sock.setsockopt(ZMQ_ROUTING_ID, worker_id.data(), worker_id.size());
#else
    sock.setsockopt(ZMQ_IDENTITY, worker_id.data(), worker_id.size());
#endif
    SN_LOG(debug, "New worker thread " << worker_id << " started");
    sock.connect(SN_ADDR_WORKERS);

    while (true) {
        detail::send_control(sock, "READY");

        // When we get an incoming message it'll be in parts that look like one of:
        // [CONTROL] -- some control command, e.g. "QUIT"
        // [PUBKEY, "S", CMD, DATA...]
        //     some data-carrying command where DATA... is zero or more serialized bt_values, where
        //     the command originated from a known service node (i.e. that we can reconnect to, if
        //     needed, to relay a message).
        // [PUBKEY, "C", CMD, DATA...]
        //     same as above, but for a command originating from a non-SN source (e.g. a remote node
        //     submitting a blink TX).  We have a local route to send back to the source as long as
        //     it stays connecting but cannot reconnect to it.
        //
        // CMDs are registered *before* a SNNetwork is created and immutable afterwards and have
        // an associated callback that takes the pubkey and a vector<bt_value> of deserialized
        // DATA... values.
        SN_LOG(debug, "worker " << worker_id << " waiting for requests");
        std::list<zmq::message_t> parts;
        recv_message_parts(sock, std::back_inserter(parts));
        try {
            if (parts.size() == 1) {
                auto control = pop_string(parts);
                if (control == "QUIT") {
                    SN_LOG(debug, "worker " << worker_id << " shutting down");
                    detail::send_control(sock, "QUITTING");
                    sock.setsockopt<int>(ZMQ_LINGER, 1000);
                    sock.close();
                    return;
                } else {
                    // proxy shouldn't have let this through!
                    SN_LOG(error, "worker " << worker_id << " received invalid command: `" << control << "'");
                    continue;
                }
            }

            assert(parts.size() >= 3);

            auto pubkey = pop_string(parts);
            assert(pubkey.size() == 32);
            bool sn = pop_string(parts) == "S";

            message msg{*this, pop_string(parts), std::move(pubkey), sn};
            SN_LOG(trace, worker_id << " received " << msg.command << " message from " << (msg.sn ? "SN " : "non-SN ") << as_hex(msg.pubkey) <<
                    " with " << parts.size() << " data parts");
            for (const auto &part : parts) {
                msg.data.emplace_back();
                bt_deserialize(part.data<char>(), part.size(), msg.data.back());
            }

            if (msg.command == "BYE") {
                SN_LOG(info, "peer asked us to disconnect");
                detail::send_control(get_control_socket(), "DISCONNECT", {{"pubkey",msg.pubkey}});
                continue;
            }

            auto cmdit = commands.find(msg.command);
            if (cmdit == commands.end()) {
                SN_LOG(warn, worker_id << " received unknown command '" << msg.command << "' from " <<
                        (msg.sn ? "SN " : "non-SN ") << as_hex(msg.pubkey));
                continue;
            }

            auto cmd_type = cmdit->second.second;
            const bool command_accepted = (
                cmd_type == command_type::response ? msg.sn :
                cmd_type == command_type::quorum ? msg.sn && is_service_node() :
                cmd_type == command_type::public_ ? is_service_node() :
                false);
            if (!command_accepted) {
                // If they aren't valid, tell them so that they can disconnect (and attempt to reconnect later with appropriate authentication)
                SN_LOG(warn, worker_id << "/" << object_id << " received disallowed " << cmd_type << " command " << msg.command <<
                        " from " << (msg.sn ? "non-" : "") << "SN remote " << as_hex(msg.pubkey) << "; replying with a BYE");
                send(msg.pubkey, "BYE", send_option::incoming{});
                detail::send_control(get_control_socket(), "DISCONNECT", {{"pubkey",msg.pubkey}});
                continue;
            }

            SN_LOG(trace, "worker thread " << worker_id << " invoking " << msg.command << " callback");
            cmdit->second.first(msg, data);
        }
        catch (const bt_deserialize_invalid &e) {
            SN_LOG(warn, worker_id << " deserialization failed: " << e.what() << "; ignoring request");
        }
        catch (const boost::bad_get &e) {
            SN_LOG(warn, worker_id << " deserialization failed: found unexpected serialized type (" << e.what() << "); ignoring request");
        }
        catch (const std::out_of_range &e) {
            SN_LOG(warn, worker_id << " deserialization failed: invalid data - required field missing (" << e.what() << "); ignoring request");
        }
        catch (const std::exception &e) {
            SN_LOG(warn, worker_id << " caught exception when processing command: " << e.what());
        }
        catch (...) {
            SN_LOG(warn, worker_id << " caught unknown exception type when processing command");
        }
    }
}

void SNNetwork::proxy_quit() {
    SN_LOG(debug, "Received quit command, shutting down proxy thread");

    assert(worker_threads.empty());
    command.setsockopt<int>(ZMQ_LINGER, 0);
    command.close();
    {
        std::lock_guard<std::mutex> lock{local_control_mutex};
        for (auto &control : thread_control_sockets)
            control->close();
    }
    workers.close();
    if (listener) {
        listener->setsockopt(ZMQ_LINGER, CLOSE_LINGER);
        listener->close();
    }
    for (auto &r : remotes)
        r.second.setsockopt(ZMQ_LINGER, CLOSE_LINGER);
    remotes.clear();
    peers.clear(); 

    SN_LOG(debug, "Proxy thread teardown complete");
}

std::pair<zmq::socket_t *, std::string>
SNNetwork::proxy_connect(const std::string &remote, const std::string &connect_hint, bool optional, bool incoming_only, std::chrono::milliseconds keep_alive) {
    auto &peer = peers[remote]; // We may auto-vivify here, but that's okay; it'll get cleaned up in idle_expiry if no connection gets established

    std::pair<zmq::socket_t *, std::string> result = {nullptr, ""s};

    bool outgoing = false;
    if (peer.outgoing >= 0 && !incoming_only) {
        result.first = &remotes[peer.outgoing].second;
        outgoing = true;
    } else if (!peer.incoming.empty() && listener) {
        result.first = listener.get();
        result.second = peer.incoming;
    }

    if (result.first) {
        SN_LOG(trace, "proxy asked to connect to " << as_hex(remote) << "; reusing existing connection");
        if (outgoing) {
            if (peer.idle_expiry < keep_alive) {
                SN_LOG(debug, "updating existing outgoing peer connection idle expiry time from " <<
                        peer.idle_expiry.count() << "ms to " << keep_alive.count() << "ms");
                peer.idle_expiry = keep_alive;
            }
            peer.activity();
        }
        return result;
    } else if (optional || incoming_only) {
        SN_LOG(debug, "proxy asked for optional or incoming connection, but no appropriate connection exists so cancelling connection attempt");
        return result;
    }

    // No connection so establish a new one
    SN_LOG(debug, "proxy establishing new outbound connection to " << as_hex(remote));
    std::string addr;
    if (remote == pubkey) {
        // special inproc connection if self that doesn't need any external connection
        addr = SN_ADDR_SELF;
    } else {
        addr = connect_hint;
        if (addr.empty())
            addr = peer_lookup(remote);
        else
            SN_LOG(debug, "using connection hint " << connect_hint);

        if (addr.empty()) {
            SN_LOG(error, "quorumnet peer lookup failed for " << as_hex(remote));
            return result;
        }
    }

    SN_LOG(debug, as_hex(pubkey) << " connecting to " << addr << " to reach " << as_hex(remote));
    zmq::socket_t socket{context, zmq::socket_type::dealer};
    socket.setsockopt(ZMQ_CURVE_SERVERKEY, remote.data(), remote.size());
    socket.setsockopt(ZMQ_CURVE_PUBLICKEY, pubkey.data(), pubkey.size());
    socket.setsockopt(ZMQ_CURVE_SECRETKEY, privkey.data(), privkey.size());
    socket.setsockopt(ZMQ_HANDSHAKE_IVL, SN_HANDSHAKE_TIME);
    socket.setsockopt<int64_t>(ZMQ_MAXMSGSIZE, SN_ZMQ_MAX_MSG_SIZE);
#if ZMQ_VERSION >= ZMQ_MAKE_VERSION (4, 3, 0)
    socket.setsockopt(ZMQ_ROUTING_ID, pubkey.data(), pubkey.size());
#else
    socket.setsockopt(ZMQ_IDENTITY, pubkey.data(), pubkey.size());
#endif
    socket.connect(addr);
    peer.idle_expiry = keep_alive;

    add_pollitem(socket);
    peer.outgoing = remotes.size();
    remotes.emplace_back(remote, std::move(socket));
    peer.service_node = true;
    peer.activity();

    result.first = &remotes.back().second;
    return result;
}

std::pair<zmq::socket_t *, std::string> SNNetwork::proxy_connect(bt_dict &&data) {
    auto remote_pubkey = get<std::string>(data.at("pubkey"));
    std::chrono::milliseconds keep_alive{get_int<int>(data.at("keep-alive"))};
    std::string hint;
    auto hint_it = data.find("hint");
    if (hint_it != data.end())
        hint = get<std::string>(data.at("hint"));

    bool optional = data.count("optional"), incoming = data.count("incoming");

    return proxy_connect(remote_pubkey, hint, optional, incoming, keep_alive);
}

// Extracts and builds the "send" part of a message for proxy_send/proxy_reply
std::list<zmq::message_t> build_send_parts(bt_dict &data, const std::string &route) {
    std::list<zmq::message_t> parts;
    if (!route.empty())
        parts.push_back(create_message(route));
    for (auto &s : get<bt_list>(data.at("send")))
        parts.push_back(create_message(std::move(get<std::string>(s))));
    return parts;
}

void SNNetwork::proxy_send(bt_dict &&data) {
    const auto &remote_pubkey = get<std::string>(data.at("pubkey"));
    std::string hint;
    auto hint_it = data.find("hint");
    if (hint_it != data.end())
        hint = get<std::string>(hint_it->second);

    auto idle_it = data.find("keep-alive");
    std::chrono::milliseconds keep_alive = idle_it != data.end()
        ? std::chrono::milliseconds(get_int<uint64_t>(idle_it->second))
        : default_send_keep_alive;

    bool optional = data.count("optional"), incoming = data.count("incoming");

    auto sock_route = proxy_connect(remote_pubkey, hint, optional, incoming, keep_alive);
    if (!sock_route.first) {
        if (optional)
            SN_LOG(debug, "Not sending: send is optional and no connection to " << as_hex(remote_pubkey) << " is currently established");
        else
            SN_LOG(error, "Unable to send to " << as_hex(remote_pubkey) << ": no connection could be established");
        return;
    }
    try {
        send_message_parts(*sock_route.first, build_send_parts(data, sock_route.second));
    } catch (const zmq::error_t &e) {
        if (e.num() == EHOSTUNREACH && sock_route.first == listener.get() && !sock_route.second.empty()) {
            // We *tried* to route via the incoming connection but it is no longer valid.  Drop it,
            // establish a new connection, and try again.
            auto &peer = peers[remote_pubkey];
            peer.incoming.clear(); // Don't worry about cleaning the map entry if outgoing is also < 0: that will happen at the next idle cleanup
            SN_LOG(debug, "Could not route back to SN " << as_hex(remote_pubkey) << " via listening socket; trying via new outgoing connection");
            return proxy_send(std::move(data));
        }
        SN_LOG(warn, "Unable to send message to remote SN " << as_hex(remote_pubkey) << ": " << e.what());
    }
}

void SNNetwork::proxy_reply(bt_dict &&data) {
    const auto &route = get<std::string>(data.at("route"));
    assert(!route.empty());
    if (!listener) {
        SN_LOG(error, "Internal error: proxy_reply called but that shouldn't be possible as we have no listener!");
        return;
    }

    try {
        send_message_parts(*listener, build_send_parts(data, route));
    } catch (const zmq::error_t &err) {
        if (err.num() == EHOSTUNREACH) {
            SN_LOG(info, "Unable to send reply to incoming non-SN request: remote is no longer connected");
        } else {
            SN_LOG(warn, "Unable to send reply to incoming non-SN request: " << err.what());
        }
    }
}

void SNNetwork::proxy_control_message(std::list<zmq::message_t> parts) {
    auto route = pop_string(parts);
    auto cmd = pop_string(parts);
    bt_dict data;
    if (!parts.empty()) {
        bt_deserialize(parts.front().data<char>(), parts.front().size(), data);
        parts.pop_front();
    }
    assert(parts.empty());
    SN_LOG(trace, "control message: " << cmd);
    if (cmd == "START") {
        // Command send by the owning thread during startup; we send back a simple READY reply to
        // let it know we are running.
        route_control(command, route, "READY");
    } else if (cmd == "QUIT") {
        // Asked to quit: set max_workers to zero and tell any idle ones to quit.  We will
        // close workers as they come back to READY status, and then close external
        // connections once all workers are done.
        max_workers = 0;
        for (const auto &route : idle_workers)
            route_control(workers, route, "QUIT");
        idle_workers.clear();
    } else if (cmd == "CONNECT") {
        proxy_connect(std::move(data));
    } else if (cmd == "DISCONNECT") {
        proxy_disconnect(get<std::string>(data.at("pubkey")));
    } else if (cmd == "SEND") {
        SN_LOG(trace, "proxying message to " << as_hex(get<std::string>(data.at("pubkey"))));
        proxy_send(std::move(data));
    } else if (cmd == "REPLY") {
        SN_LOG(trace, "proxying reply to non-SN incoming message");
        proxy_reply(std::move(data));
    } else {
        throw std::runtime_error("Proxy received invalid control command: " + cmd +
                " (" + std::to_string(cmd.size()) + ")");
    }
}

auto SNNetwork::proxy_close_outgoing(decltype(peers)::iterator it) -> decltype(it) {
    auto &peer = *it;
    auto &info = peer.second;

    if (info.outgoing >= 0) {
        remotes[info.outgoing].second.setsockopt<int>(ZMQ_LINGER, CLOSE_LINGER);
        pollitems.erase(pollitems.begin() + poll_remote_offset + info.outgoing);
        remotes.erase(remotes.begin() + info.outgoing);
        assert(remotes.size() == pollitems.size() + poll_remote_offset);

        for (auto &p : peers)
            if (p.second.outgoing > info.outgoing)
                --p.second.outgoing;

        info.outgoing = -1;
    }

    if (info.incoming.empty())
        // Neither incoming nor outgoing connections left, so erase the peer info
        return peers.erase(it);

    return std::next(it);
}

void SNNetwork::proxy_disconnect(const std::string &remote) {
    auto it = peers.find(remote);
    if (it == peers.end())
        return;
    if (want_logs(LogLevel::debug)) {
        if (it->second.outgoing >= 0)
            SN_LOG(debug, "Closing outgoing connection to " << as_hex(it->first));
    }
    proxy_close_outgoing(it);
}

void SNNetwork::proxy_expire_idle_peers() {
    for (auto it = peers.begin(); it != peers.end(); ) {
        auto &info = it->second;
        if (info.outgoing >= 0) {
            auto idle = info.last_activity - std::chrono::steady_clock::now();
            if (idle <= info.idle_expiry) {
                ++it;
                continue;
            }
            SN_LOG(info, "Closing outgoing connection to " << as_hex(it->first) << ": idle timeout reached");
        }

        // Deliberately outside the above if: this *also* removes the peer from the map if if has
        // neither an incoming or outgoing connection
        it = proxy_close_outgoing(it);
    }
}

void SNNetwork::proxy_loop(const std::vector<std::string> &bind) {
    zmq::socket_t zap_auth{context, zmq::socket_type::rep};
    zap_auth.setsockopt<int>(ZMQ_LINGER, 0);
    zap_auth.bind(ZMQ_ADDR_ZAP);

    workers.setsockopt<int>(ZMQ_ROUTER_MANDATORY, 1);
    workers.bind(SN_ADDR_WORKERS);

    spawn_worker("w1");
    int next_worker_id = 2;

    add_pollitem(command);
    add_pollitem(workers);
    add_pollitem(zap_auth);
    assert(pollitems.size() == poll_internal_size);

    if (listener) {
        auto &l = *listener;
        // Set up the public tcp listener(s):
        l.setsockopt(ZMQ_ZAP_DOMAIN, AUTH_DOMAIN_SN, sizeof(AUTH_DOMAIN_SN)-1);
        l.setsockopt<int>(ZMQ_CURVE_SERVER, 1);
        l.setsockopt(ZMQ_CURVE_PUBLICKEY, pubkey.data(), pubkey.size());
        l.setsockopt(ZMQ_CURVE_SECRETKEY, privkey.data(), privkey.size());
        l.setsockopt<int64_t>(ZMQ_MAXMSGSIZE, SN_ZMQ_MAX_MSG_SIZE);
        l.setsockopt<int>(ZMQ_ROUTER_HANDOVER, 1);
        l.setsockopt<int>(ZMQ_ROUTER_MANDATORY, 1);

        for (const auto &b : bind) {
            SN_LOG(info, "Quorumnet listening on " << b);
            l.bind(b);
        }

        // Also add an internal connection to self so that calling code can avoid needing to
        // special-case rare situations where we are supposed to talk to a quorum member that happens to
        // be ourselves (which can happen, for example, with cross-quoum Blink communication)
        l.bind(SN_ADDR_SELF);

        add_pollitem(l);
    }

    assert(pollitems.size() == poll_remote_offset);

    constexpr auto poll_timeout = 5000ms; // Maximum time we spend in each poll
    constexpr auto timeout_check_interval = 10000ms; // Minimum time before for checking for connections to close since the last check
    auto last_conn_timeout = std::chrono::steady_clock::now();

    std::string waiting_for_worker; // If set contains the identify of a worker we just spawned but haven't received a READY signal from yet
    size_t last_conn_index = 0; // Index of the connection we last received a message from; see below

    while (true) {
        if (max_workers == 0) { // Will be 0 only if we are quitting
            if (worker_threads.empty()) {
                // All the workers have finished, so we can finish shutting down
                return proxy_quit();
            }
        }

        // We poll the control socket and worker socket for any incoming messages.  If we have
        // available workers (either actually waiting, or that we are allowed to start up) then also
        // poll incoming connections and outgoing connections for messages to forward to a worker.
        // Otherwise, we just look for a control message or a worker coming back with a ready message.
        bool have_workers = idle_workers.size() > 0 || (worker_threads.size() < max_workers && waiting_for_worker.empty());
        zmq::poll(pollitems.data(), have_workers ? pollitems.size() : poll_internal_size, poll_timeout);

        SN_LOG(trace, "processing control messages");
        // Retrieve any waiting incoming control messages
        for (std::list<zmq::message_t> parts; recv_message_parts(command, std::back_inserter(parts), zmq::recv_flags::dontwait); parts.clear()) {
            proxy_control_message(std::move(parts));
        }

        SN_LOG(trace, "processing worker messages");
        // Process messages sent by workers
        for (std::list<zmq::message_t> parts; recv_message_parts(workers, std::back_inserter(parts), zmq::recv_flags::dontwait); parts.clear()) {
            std::string route = pop_string(parts);
            if (want_logs(LogLevel::trace)) {
                std::ostringstream o;
                o << "Proxy received a " << (1+parts.size()) << "-part worker message from " << route;
                int i = 0;
                for (auto &m : parts)
                    o << '[' << i++ << "]: " << m.str() << "\n";
                logger(LogLevel::trace, __FILE__, __LINE__, o.str());
            }
            // If it's only a single part then it's a control message rather than a message to be
            // proxied
            if (parts.size() == 1) {
                auto cmd = pop_string(parts);
                if (cmd == "READY") {
                    if (route == waiting_for_worker)
                        waiting_for_worker.clear();
                    SN_LOG(debug, "Worker " << route << " is ready");
                    if (worker_threads.size() > max_workers) {
                        // We have too many worker threads (possibly because we're shutting down) so
                        // tell this worker to quit, and keep it non-idle.
                        SN_LOG(trace, "Telling worker " << route << " to quit");
                        route_control(workers, route, "QUIT");
                    } else {
                        idle_workers.push_back(std::move(route));
                    }
                } else if (cmd == "QUITTING") {
                    auto it = worker_threads.find(route);
                    assert(it != worker_threads.end());
                    it->second.join();
                    worker_threads.erase(it);
                    SN_LOG(debug, "Worker " << route << " exited normally");
                } else {
                    SN_LOG(error, "Worker " << route << " sent unknown control message: `" << cmd << "'");
                }
            } else {
                SN_LOG(error, "Received send invalid " << parts.size() << "-part message");
            }
        }

        SN_LOG(trace, "processing zap requests");
        // Handle any zap authentication
        process_zap_requests(zap_auth);

        if (max_workers > 0 && have_workers) {
            // If we have no idle workers but we end up here then we have room to create one: if
            // there is any actual demand (i.e. there is an incoming message) then we spawn a new
            // thread.  However that new one won't be ready right away, so we spawn it and then go
            // back to polling just the control and workers; when it is ready it'll send a READY
            // message, at which point we can resume polling on listening sockets and will end up
            // back here again with (at least) one idle worker.
            if (idle_workers.empty()) {
                bool peer_message = std::any_of(pollitems.begin() + poll_internal_size, pollitems.end(),
                        [](const zmq::pollitem_t &p) -> bool { return p.revents & ZMQ_POLLIN; });
                if (!peer_message)
                    continue; // No incoming messages, so nothing to do

                SN_LOG(debug, "no idle workers, so starting up a new one");
                waiting_for_worker = "w" + std::to_string(next_worker_id++);
                spawn_worker(waiting_for_worker);
                continue;
            }

            SN_LOG(trace, "processing incoming messages");

            // We round-robin connection queues for any pending messages (as long as we have enough
            // waiting workers), but we don't want a lot of earlier connection requests to starve
            // later request so each time through we continue from wherever we left off in the
            // previous queue.

            const size_t num_sockets = remotes.size() + (listener ? 1 : 0);
            if (last_conn_index >= num_sockets)
                last_conn_index = 0;
            std::queue<size_t> queue_index;
            for (size_t i = 1; i <= num_sockets; i++)
                queue_index.push((last_conn_index + i) % num_sockets);

            while (!idle_workers.empty() && !queue_index.empty()) {
                size_t i = queue_index.front();
                queue_index.pop();
                auto &sock = listener ? (i == 0 ? *listener : remotes[i - 1].second) : remotes[i].second;

                std::list<zmq::message_t> parts;
                if (recv_message_parts(sock, std::back_inserter(parts), zmq::recv_flags::dontwait)) {
                    last_conn_index = i;
                    queue_index.push(i); // We just read one, but there might be more messages waiting so requeue it at the end
                    proxy_to_worker(i, std::move(parts));
                }
            }
        }

        // Drop idle connections (if we haven't done it in a while) but *only* if we have some idle
        // workers: if we don't have any idle workers then we may still have incoming messages which
        // we haven't processed yet and those messages might end up reset the last activity time.
        if (!idle_workers.empty()) {
            auto now = std::chrono::steady_clock::now();
            if (now - last_conn_timeout >= timeout_check_interval) {
                SN_LOG(trace, "closing idle connections");
                proxy_expire_idle_peers();
                last_conn_timeout = now;
            }
        }

        SN_LOG(trace, "done proxy loop");
    }
}

void SNNetwork::proxy_to_worker(size_t conn_index, std::list<zmq::message_t> &&parts) {
    // A message to a worker takes one of the following forms:
    //
    // ["CONTROL"] -- for an internal proxy instruction such as "QUIT"
    // ["PUBKEY", "S", "CMD", ...] -- for a message relayed from an authenticated SN (... are optional bt_values).
    // ["PUBKEY", "C", "CMD", ...] -- for an incoming message from a non-SN node (i.e. not a SN quorum message)
    //
    // The latter two may be optionally followed (the ...) by one or more frames containing serialized bt_values.
    //
    // Both forms support replying back to the given PUBKEY, but only the first form
    // allows relaying back if the original connection is closed -- a new connection
    // to that SN will be established if required.  The "C" form only supports
    // replying on the existing incoming connection (any attempted reply will be
    // dropped if the connection no longer exists).

    std::string pubkey;

    bool is_outgoing_conn = !listener || conn_index > 0;

    bool remote_is_sn;
    if (is_outgoing_conn) { // Talking to a remote, we know the pubkey already, and is a SN.
        pubkey = remotes[conn_index - (listener ? 1 : 0)].first;
        remote_is_sn = 1;
    } else { // Incoming; extract the pubkey from the message properties
        try {
            const char *pubkey_hex = parts.back().gets("User-Id");
            auto len = std::strlen(pubkey_hex);
            assert(len == 66 && (pubkey_hex[0] == 'S' || pubkey_hex[0] == 'C') && pubkey_hex[1] == ':');
            pubkey = hex::from_hex(pubkey_hex + 2, pubkey_hex + 66);
            remote_is_sn = pubkey_hex[0] == 'S';
        } catch (...) {
            SN_LOG(error, "Internal error: socket User-Id not set or invalid; dropping message");
            return;
        }
    }
    assert(pubkey.size() == 32);

    auto &peer_info = peers[pubkey];
    peer_info.service_node |= remote_is_sn;

    if (is_outgoing_conn) {
        peer_info.activity(); // outgoing connection activity, pump the activity timer
    } else { // incoming connection; pop off the route and update it if needed
        auto route = pop_string(parts);
        if (peer_info.incoming != route)
            peer_info.incoming = route;
    }

    // We need at least a command:
    if (parts.empty()) {
        SN_LOG(warn, "Invalid empty incoming message; require at least a command. Dropping message.");
        return;
    }

    if (want_logs(LogLevel::trace)) {
        const char *remote_addr = "(unknown)";
        try { remote_addr = parts.back().gets("Peer-Address"); } catch (...) {}
        logger(LogLevel::trace, __FILE__, __LINE__, "Forwarding incoming message from " +
                (pubkey.empty() ? "anonymous"s : as_hex(pubkey)) + " @ " + remote_addr + " to worker " + idle_workers.front());
    }

    // Prepend the [pubkey, [S|C]] for the worker
    parts.emplace_front(peer_info.service_node ? "S" : "C", 1);
    parts.push_front(create_message(std::move(pubkey)));

    // Prepend the worker name for the worker router to send it to the right worker
    parts.emplace_front(idle_workers.front().data(), idle_workers.front().size());
    idle_workers.pop_front();

    send_message_parts(workers, parts.begin(), parts.end());
}

void SNNetwork::process_zap_requests(zmq::socket_t &zap_auth) {
    std::vector<zmq::message_t> frames;
    for (frames.reserve(7); recv_message_parts(zap_auth, std::back_inserter(frames), zmq::recv_flags::dontwait); frames.clear()) {
        if (want_logs(LogLevel::trace)) {
            std::ostringstream o;
            o << "Processing ZAP authentication request:";
            for (size_t i = 0; i < frames.size(); i++) {
                o << "\n[" << i << "]: ";
                auto v = view(frames[i]);
                if (i == 1 || i == 6)
                    o << as_hex(v);
                else
                    o << v;
            }
            logger(LogLevel::trace, __FILE__, __LINE__, o.str());
        } else {
            SN_LOG(debug, "Processing ZAP authentication request");
        }

        // https://rfc.zeromq.org/spec:27/ZAP/
        //
        // The request message SHALL consist of the following message frames:
        //
        //     The version frame, which SHALL contain the three octets "1.0".
        //     The request id, which MAY contain an opaque binary blob.
        //     The domain, which SHALL contain a (non-empty) string.
        //     The address, the origin network IP address.
        //     The identity, the connection Identity, if any.
        //     The mechanism, which SHALL contain a string.
        //     The credentials, which SHALL be zero or more opaque frames.
        //
        // The reply message SHALL consist of the following message frames:
        //
        //     The version frame, which SHALL contain the three octets "1.0".
        //     The request id, which MAY contain an opaque binary blob.
        //     The status code, which SHALL contain a string.
        //     The status text, which MAY contain a string.
        //     The user id, which SHALL contain a string.
        //     The metadata, which MAY contain a blob.
        //
        // (NB: there are also null address delimiters at the beginning of each mentioned in the
        // RFC, but those have already been removed through the use of a REP socket)

        std::vector<std::string> response_vals(6);
        response_vals[0] = "1.0"; // version
        if (frames.size() >= 2)
            response_vals[1] = view(frames[1]); // unique identifier
        std::string &status_code = response_vals[2], &status_text = response_vals[3];

        if (frames.size() < 6 || view(frames[0]) != "1.0") {
            SN_LOG(error, "Bad ZAP authentication request: version != 1.0 or invalid ZAP message parts");
            status_code = "500";
            status_text = "Internal error: invalid auth request";
        }
        else if (frames.size() != 7 || view(frames[5]) != "CURVE") {
            SN_LOG(error, "Bad ZAP authentication request: invalid CURVE authentication request");
            status_code = "500";
            status_text = "Invalid CURVE authentication request\n";
        }
        else if (frames[6].size() != 32) {
            SN_LOG(error, "Bad ZAP authentication request: invalid request pubkey");
            status_code = "500";
            status_text = "Invalid public key size for CURVE authentication";
        }
        else {
            auto domain = view(frames[2]);
            if (domain != AUTH_DOMAIN_SN) {
                SN_LOG(error, "Bad ZAP authentication request: invalid auth domain '" << domain << "'");
                status_code = "400";
                status_text = "Unknown authentication domain: " + std::string{domain};
            } else {
                std::string ip{view(frames[3])}, pubkey{view(frames[6])}, pubkey_hex{as_hex(pubkey)};
                auto result = allow_connection(ip, pubkey);
                bool sn = result == allow::service_node;
                if (sn || result == allow::client) {
                    SN_LOG(info, "Successfully " <<
                            (sn ? "authenticated incoming service node" : "accepted incoming non-SN client") <<
                            " connection from " << pubkey_hex << " at " << ip);
                    status_code = "200";
                    status_text = "";
                    // Set a user-id to the pubkey prefixed with "C:" or "S:" to indicate how we
                    // recognized the pubkey.
                    response_vals[4 /*user-id*/] = (sn ? "S:" : "C:") + pubkey_hex; // hex because zmq message property strings are null-terminated
                } else {
                    SN_LOG(info, "Access denied for incoming " << (sn ? "service node" : "non-SN client") <<
                            " connection from " << pubkey_hex << " at " << ip);
                    status_code = "400";
                    status_text = "Access denied";
                }
            }
        }

        SN_LOG(trace, "ZAP request result: " << status_code << " " << status_text);

        std::list<zmq::message_t> response;
        for (auto &r : response_vals) response.push_back(create_message(std::move(r)));
        send_message_parts(zap_auth, response.begin(), response.end());
    }
}

SNNetwork::~SNNetwork() {
    SN_LOG(info, "SNNetwork shutting down proxy thread");
    detail::send_control(get_control_socket(), "QUIT");
    proxy_thread.join();
    SN_LOG(info, "SNNetwork proxy thread has stopped");
}

void SNNetwork::connect(const std::string &pubkey, std::chrono::milliseconds keep_alive, const std::string &hint) {
    detail::send_control(get_control_socket(), "CONNECT", {{"pubkey",pubkey}, {"keep-alive",keep_alive.count()}, {"hint",hint}});
}


}

// vim:sw=4:et
