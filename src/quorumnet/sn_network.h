// Copyright (c)      2019, The Loki Project
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

// Please no epee.
#include "zmq.hpp"
#include "bt_serialize.h"
#include <string>
#include <list>
#include <unordered_map>
#include <memory>
#include <functional>
#include <thread>
#include <mutex>
#include <iostream>
#include <chrono>

namespace quorumnet {

/// Logging levels passed into LogFunc
enum class LogLevel { trace, debug, info, warn, error, fatal };

using namespace std::chrono_literals;

/**
 * Class that represents a listening service node on the quorum p2p network.  This object supports
 * connecting to service node peers and handles requests from node clients (for example, a remote
 * node submitting a Blink transaction to a Blink quorum).
 *
 * Internally the class uses a worker thread to handle messages from other service nodes, which it
 * then passed back into calling code via callbacks.
 */
class SNNetwork {
public:
    /// The function type for looking up where to connect to the SN with the given pubkey.  Should
    /// return an empty string for an invalid or unknown pubkey or one without a known address.
    using LookupFunc = std::function<std::string(const std::string &pubkey)>;

    /// Callback type invoked to determine whether the given ip and pubkey are allowed to connect to
    /// us.  This will be called in two contexts:
    ///
    /// - if the connection is from another SN for quorum-related duties, the pubkey will be set
    ///   to the verified pubkey of the remote service node.
    /// - otherwise, for a client connection (for example, a regular node connecting to submit a
    ///   blink transaction to a blink quorum) the pubkey will be empty.
    ///
    /// @param ip - the ip address of the incoming connection
    /// @param pubkey - the curve25519 pubkey (which is calculated from the SN ed25519 pubkey) of
    /// the connecting service node (32 byte string), or an empty string if this is a client
    /// connection without remote SN authentication.
    using AllowFunc = std::function<bool(const std::string &ip, const std::string &pubkey)>;

    /// Function pointer to ask whether a log of the given level is wanted.  If it returns true the
    /// log message will be built and then passed to Log.
    using WantLog = bool (*)(LogLevel);
    ///
    /// call to get somewhere to log to when there is a logging message.  If it
    /// returns a std::ostream pointer then output is sent to it; otherwise (i.e. nullptr) output is
    /// suppressed.  Takes three arguments: the log level, the __FILE__ value, and the __LINE__ value.
    using WriteLog = void (*)(LogLevel level, const char *file, int line, std::string msg);

    /// Explicitly non-copyable, non-movable because most things here aren't copyable, and a few
    /// things aren't movable.  If you need to pass the SNNetwork around, wrap it in a unique_ptr.
    SNNetwork(const SNNetwork &) = delete;
    SNNetwork &operator=(const SNNetwork &) = delete;
    SNNetwork(SNNetwork &&) = delete;
    SNNetwork &operator=(SNNetwork &&) = delete;

    /// Encapsulates an incoming message from a remote node with message details plus extra info
    /// need to send a reply back through the proxy thread via the `reply()` method.
    class message {
    private:
        SNNetwork &net;
    public:
        std::string command; ///< The command name
        bt_dict data; ///< The provided command data, if any.
        const std::string pubkey; ///< The originator pubkey (32 bytes), if from an authenticated service node; empty for a non-SN incoming message.
        const std::string route; ///< Opaque routing string used to route a reply back to the correct place when `pubkey` is empty.

        /// Constructor
        message(SNNetwork &net, std::string command, std::string pubkey, std::string route)
            : net{net}, command{std::move(command)}, pubkey{std::move(pubkey)}, route{std::move(route)} {
            assert(this->pubkey.empty() ? !this->route.empty() : this->pubkey.size() == 32);
        }

        /// True if this message is from a service node (i.e. pubkey is set)
        bool from_sn() const { return !pubkey.empty(); }

        /// Sends a reply.  For SN messages (i.e. where `from_sn()` is true) this is a "strong"
        /// reply in that the proxy will establish a new connection to the SN if no longer
        /// connected.  For non-SN messages the reply will be attempted using the available routing
        /// information, but if the connection has already been closed the reply will be dropped.
        void reply(const std::string &command, const bt_dict &data = {});
    };

    /// Opaque pointer sent to the callbacks, to allow for including arbitrary state data (for
    /// example, an owning object or state data).  Defaults to nullptr and has to be explicitly set
    /// if desired.
    void *data = nullptr;

private:
    zmq::context_t context;

    /// A unique id for this SNNetwork, assigned in a thread-safe manner during construction.
    const int object_id;

    /// The thread in which most of the intermediate work happens (handling external connections
    /// and proxying requests between them to worker threads)
    std::thread proxy_thread;

    /// Called to obtain a "command" socket that attaches to `control` to send commands to the
    /// proxy thread from other threads.  This socket is unique per thread and SNNetwork instance.
    zmq::socket_t &get_control_socket();
    /// Stores all of the sockets created in different threads via `get_control_socket`.  This is
    /// only used during destruction to close all of those open sockets, and is protected by an
    /// internal mutex which is only locked by new threads getting a control socket and the
    /// destructor.
    std::vector<std::shared_ptr<zmq::socket_t>> thread_control_sockets;




    ///////////////////////////////////////////////////////////////////////////////////
    /// NB: The following are all the domain of the proxy thread (once it is started)!

    /// The lookup function that tells us where to connect to a peer
    LookupFunc peer_lookup;
    /// Our listening socket for public connections
    std::shared_ptr<zmq::socket_t> listener = std::make_shared<zmq::socket_t>(context, zmq::socket_type::router);
    /// Our listening socket for ourselves (so that we can just "connect" and talk to ourselves
    /// without worrying about special casing it).
    std::shared_ptr<zmq::socket_t> self_listener = std::make_shared<zmq::socket_t>(context, zmq::socket_type::router);

    /// Callback to see whether the incoming connection is allowed
    AllowFunc allow_connection;

    /// Callback to see if we want a log message at the given level.
    WantLog want_logs;
    /// If want_logs returns true, the log message is build and passed into this.
    WriteLog logger;

    /// Info about a peer's established connection to us.  Note that "established" means both
    /// connected and authenticated.
    struct peer_info {
        /// Will be set to `listener` if we have an established incoming connection (but note that
        /// the connection might no longer be valid) and empty otherwise.
        std::weak_ptr<zmq::socket_t> incoming;

        /// FIXME: neither the above nor below are currently being set on an incoming connection!

        /// The routing prefix needed to reply to the connection on the incoming socket.
        std::string incoming_route;

        /// Our outgoing socket, if we have an established outgoing connection to this peer.  The
        /// owning pointer is in `remotes`.
        std::weak_ptr<zmq::socket_t> outgoing;

        /// The last time we sent or received a message (or had some other relevant activity) with
        /// this peer.  Used for closing outgoing connections that have reached an inactivity expiry
        /// time.
        std::chrono::steady_clock::time_point last_activity;

        /// Updates last_activity to the current time
        void activity() { last_activity = std::chrono::steady_clock::now(); }

        /// After more than this much activity we will close an idle connection
        std::chrono::milliseconds idle_expiry;

        /// Returns a socket to talk to the given peer, if we have one.  If we don't, the returned
        /// pointer will be empty.  If both outgoing and incoming connections are available the
        /// outgoing connection is preferred.
        std::shared_ptr<zmq::socket_t> socket();
    };
    /// Currently peer connections, pubkey -> peer_info
    std::unordered_map<std::string, peer_info> peers;

    /// different polling sockets the proxy handler polls: this always contains some internal
    /// sockets for inter-thread communication followed by listener socket and a pollitem for every
    /// (outgoing) remote socket in `remotes`.  This must be in a sequential vector because of zmq
    /// requirements (otherwise it would be far nicer to not have to synchronize these two vectors).
    std::vector<zmq::pollitem_t> pollitems;

    /// Properly adds a socket to poll for input to pollitems
    void add_pollitem(zmq::socket_t &sock);

    /// The number of internal sockets in `pollitems`
    static constexpr size_t poll_internal_size = 3;

    /// The pollitems location corresponding to `remotes[0]`.
    static constexpr size_t poll_remote_offset = poll_internal_size + 2; // +2 because we also have the incoming listener and self sockets

    /// The outgoing remote connections we currently have open.  Note that they are generally
    /// accessed via the weak_ptr inside the `peers` element.  Each element [i] here corresponds to
    /// an the pollitem_t at pollitems[i+1+poll_internal_size].  (Ideally we'd use one structure,
    /// but zmq requires the pollitems be in contiguous storage).
    std::vector<std::shared_ptr<zmq::socket_t>> remotes;

    /// Socket we listen on to receive control messages in the proxy thread. Each thread has its own
    /// internal "control" connection (returned by `get_control_socket()`) to this socket used to
    /// give instructions to the proxy such as instructing it to initiate a connection to a remote
    /// or send a message.
    zmq::socket_t command{context, zmq::socket_type::router};

    /// Router socket to reach internal worker threads from proxy
    zmq::socket_t workers{context, zmq::socket_type::router};

    /// Starts a new worker thread with the given id.  Note that the worker may not yet be ready
    /// until a READY signal arrives on the worker socket.
    void spawn_worker(std::string worker_id);

    /// Worker threads (ZMQ id -> thread)
    std::unordered_map<std::string, std::thread> worker_threads;

    /// ZMQ ids of idle, active workers
    std::list<std::string> idle_workers;

    /// Maximum number of worker threads created on demand up to this limit.
    unsigned int max_workers;

    /// Worker thread loop
    void worker_thread(std::string worker_id);

    /// Does the proxying work
    void proxy_loop(const std::vector<std::string> &bind);

    /// proxy thread command handlers for commands sent from the outer object QUIT.  This doesn't
    /// get called immediately on a QUIT command: the QUIT commands tells workers to quit, then this
    /// gets called after all works have done so.
    void proxy_quit();

    /// Common connection implementation used by proxy_connect/proxy_send.  Returns the socket
    /// and, if a routing prefix is needed, the required prefix (or an empty string if not needed).
    std::pair<std::shared_ptr<zmq::socket_t>, std::string> proxy_connect(const std::string &pubkey, const std::string &connect_hint, std::chrono::milliseconds keep_alive);

    /// CONNECT command telling us to connect to a new pubkey.  Returns the socket (which could be
    /// existing or a new one).
    std::pair<std::shared_ptr<zmq::socket_t>, std::string> proxy_connect(bt_dict &&data);

    /// SEND command.  Does a connect first, if necessary.
    void proxy_send(bt_dict &&data);

    /// REPLY command.  Like SEND, but only has a listening socket route to send back to and so is
    /// weaker (i.e. it cannot reconnect to the SN if the connection is no longer open).
    void proxy_reply(bt_dict &&data);

    /// ZAP (https://rfc.zeromq.org/spec:27/ZAP/) authentication handler; this is called with the
    /// zap auth socket to do non-blocking processing of any waiting authentication requests waiting
    /// on it to verify whether the connection is from a valid/allowed SN.
    void process_zap_requests(zmq::socket_t &zap_auth);

    /// Handles a control message from some outer thread to the proxy
    void proxy_control_message(std::list<zmq::message_t> parts);

    /// Closing any idle connections that have outlived their idle time.  Note that this only
    /// affects outgoing connections; incomings connections are the responsibility of the other end.
    void expire_idle_peers();


    /// End of proxy-specific members
    ///////////////////////////////////////////////////////////////////////////////////




    /// Callbacks for data commands.  Must be fully populated before starting SNNetwork instances
    /// as this is accessed without a lock from worker threads.
    ///
    /// The value is the {callback, public} pair where `public` is true if unauthenticated
    /// connections may call this and false if only authenricated SNs may invoke the command.
    static std::unordered_map<std::string, std::pair<std::function<void(SNNetwork::message &message, void *data)>, bool>> commands;
    static bool commands_mutable;

public:
    /**
     * Constructs a SNNetwork connection listening on the given bind string.
     *
     * @param pubkey the service node's public key (32-byte binary string)
     * @param privkey the service node's private key (32-byte binary string)
     * @param bind list of addresses to bind to.  Can be any string zmq supports; typically a tcp
     * IP/port combination such as: "tcp://\*:4567" or "tcp://1.2.3.4:5678".
     * @param peer_lookup function that takes a pubkey key (32-byte binary string) and returns a
     * connection string such as "tcp://1.2.3.4:23456" to which a connection should be established
     * to reach that service node.  Note that this function is only called if there is no existing
     * connection to that service node, and that the function is never called for a connection to
     * self (that uses an internal connection instead).
     * @param allow_incoming called on incoming connections with the (verified) incoming connection
     * pubkey (32-byte binary string) to determine whether the given SN should be allowed to
     * connect.
     * @param data - an opaque pointer to pass along to command callbacks
     * @param want_log 
     * @param log a function pointer (or non-capturing lambda) to call to get a std::ostream pointer
     * to send output to, or nullptr to suppress output.  Optional; if omitted the default returns
     * std::cerr for WARN and higher.
     * @param max_workers the maximum number of simultaneous worker threads to start.  Defaults to
     * std::thread::hardware_concurrency().  Note that threads are only started on demand (i.e. when
     * a request arrives when all existing threads are busy handling requests).
     */
    SNNetwork(std::string pubkey, std::string privkey,
            const std::vector<std::string> &bind,
            LookupFunc peer_lookup,
            AllowFunc allow_connection,
            WantLog want_log = [](LogLevel l) { return l >= LogLevel::warn; },
            WriteLog logger = [](LogLevel, const char *f, int line, std::string msg) { std::cerr << f << ':' << line << ": " << msg << std::endl; },
            unsigned int max_workers = std::thread::hardware_concurrency());

    /**
     * Destructor; instructs the proxy to quit.  The proxy tells all workers to quit, waits for them
     * to quit and rejoins the threads then quits itself.  The outer thread (where the destructor is
     * running) rejoins the proxy thread.
     */
    ~SNNetwork();

    /**
     * Try to initiate a connection to the given SN in anticipation of needing a connection in the
     * future.  If a connection is already established, the connection's idle timer will be reset
     * (so that the connection will not be closed too soon).  If the given idle timeout is greater
     * than the current idle timeout then the timeout increases to the new value; if less than the
     * current timeout it is ignored.
     *
     * Note that this method (along with send) doesn't block waiting for a connection; it merely
     * instructs the proxy thread that it should establish a connection.
     *
     * @param pubkey - the public key (32-byte binary string) of the service node to connect to
     * @param idle_timeout - the connection will be kept alive if there was valid activity within
     *                       the past `keep_alive` milliseconds.  If a connection already exists,
     *                       the longer of the existing and the given keep alive is used.
     */
    void connect(const std::string &pubkey, std::chrono::milliseconds idle_timeout = 600s);

    /**
     * Queue a message to be relayed to SN identified with the given pubkey without expecting a
     * reply.  The SN will attempt to relay (first connecting and handshaking if not already
     * connected to the given SN).
     *
     * If a new connection it established it will have a relatively short (15s) idle timeout.  If
     * the connection should stay open longer you should call `connect(pubkey, IDLETIME)` first.
     *
     * Note that this method (along with connect) doesn't block waiting for a connection or for the
     * message to send; it merely instructs the proxy thread that it should send.
     *
     * @param pubkey - the pubkey to send this to
     * @param cmd - the command
     * @param value - the optional bt_dict value to serialize and send (only included if specified
     *                and non-empty)
     */
    void send(const std::string &pubkey, const std::string &cmd, const bt_dict &data = {});

    /**
     * Works just like send(), but also takes a connection hint.  If there is no current connection
     * to the peer then the hint is used to save a call to the LookupFunc to get the connection
     * location.  (Note that there is no guarantee that the given hint will be used.)
     */
    void send_hint(const std::string &pubkey, const std::string &connect_hint, const std::string &cmd, const bt_dict &data = {});

    /** Queue a message to be replied to the given incoming route.  This method is typically invoked
     * indirectly by calling `message.reply(...)` which either calls `send()` or this message,
     * depending on the original source of the message.
     */
    void reply_incoming(const std::string &route, const std::string &cmd, const bt_dict &data = {});

    /** The keep-alive time for a send() that results in a new connection.  To use a longer
     * keep-alive to a host call `connect()` first with the desired keep-alive time.
     */
    static constexpr std::chrono::milliseconds default_send_keep_alive{15000};

    /// The key pair this SN was created with
    const std::string pubkey, privkey;

    /**
     * Registers a quorum command that may be invoked by authenticated SN connections but not
     * unauthenticated (non-SN) connections.
     *
     * Commands may only be registered before any SNNetwork instance has been constructed.
     *
     * @param command - the command string to assign.  If it already exists it will be replaced.
     * @param callback - a callback that takes the message info and the opaque `data` pointer
     */
    static void register_quorum_command(std::string command, std::function<void(SNNetwork::message &message, void *data)> callback);

    /**
     * Registers a network command that may be invoked by both authenticated SN connections and
     * unauthenticated (non-SN) connections.
     *
     * Commands may only be registered before any SNNetwork instance has been constructed.
     *
     * @param command - the command string to assign.  If it already exists it will be replaced.
     * @param callback - a callback that takes the message info and the opaque `data` pointer
     */
    static void register_public_command(std::string command, std::function<void(SNNetwork::message &message, void *data)> callback);
};

// Creates a hex string from a character sequence.
template <typename It>
std::string as_hex(It begin, It end) {
    constexpr std::array<char, 16> lut{{'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'}};
    std::string hex;
    using std::distance;
    hex.reserve(distance(begin, end) * 2);
    while (begin != end) {
        char c = *begin;
        hex += lut[(c & 0xf0) >> 4];
        hex += lut[c & 0x0f];
        ++begin;
    }
    return hex;
}

template <typename String>
inline std::string as_hex(const String &s) {
    return as_hex(s.begin(), s.end());
}



}

// vim:sw=4:et
