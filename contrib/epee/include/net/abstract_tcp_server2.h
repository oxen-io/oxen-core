/**
@file
@author from CrypoNote (see copyright below; Andrey N. Sabelnikov)
@monero rfree
@brief the connection templated-class for one peer connection
*/
// Copyright (c) 2006-2013, Andrey N. Sabelnikov, www.sabelnikov.net
// All rights reserved.
// 
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
// * Redistributions of source code must retain the above copyright
// notice, this list of conditions and the following disclaimer.
// * Redistributions in binary form must reproduce the above copyright
// notice, this list of conditions and the following disclaimer in the
// documentation and/or other materials provided with the distribution.
// * Neither the name of the Andrey N. Sabelnikov nor the
// names of its contributors may be used to endorse or promote products
// derived from this software without specific prior written permission.
// 
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
// ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER  BE LIABLE FOR ANY
// DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
// LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
// ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
// 



#ifndef _ABSTRACT_TCP_SERVER2_H_ 
#define _ABSTRACT_TCP_SERVER2_H_ 


#include <mutex>
#include <string>
#include <vector>
#include <atomic>
#include <cassert>
#include <map>
#include <memory>

#include <boost/asio.hpp>
#include <boost/asio/steady_timer.hpp>
#include "net_utils_base.h"
#include "connection_basic.hpp"
#include "network_throttle-detail.hpp"

#undef LOKI_DEFAULT_LOG_CATEGORY
#define LOKI_DEFAULT_LOG_CATEGORY "net"

#define ABSTRACT_SERVER_SEND_QUE_MAX_COUNT 1000

namespace epee
{
namespace net_utils
{

  struct i_connection_filter
  {
    virtual bool is_remote_host_allowed(const epee::net_utils::network_address &address, time_t *t = NULL)=0;
  protected:
    virtual ~i_connection_filter(){}
  };
  

  /************************************************************************/
  /*                                                                      */
  /************************************************************************/
  /// Represents a single connection from a client.
  template<class t_protocol_handler>
  class connection
    : public std::enable_shared_from_this<connection<t_protocol_handler>>,
    public i_service_endpoint,
    public connection_basic
  {
  public:
    connection(const connection&) = delete;
    connection& operator=(const connection&) = delete;

    typedef typename t_protocol_handler::connection_context t_connection_context;

    struct shared_state : connection_basic_shared_state, t_protocol_handler::config_type
    {
      shared_state()
        : connection_basic_shared_state(), t_protocol_handler::config_type(), pfilter(nullptr), stop_signal_sent(false)
      {}

      i_connection_filter* pfilter;
      bool stop_signal_sent;
    };

    /// Construct a connection with the given io_service.
    explicit connection( boost::asio::io_service& io_service,
                        std::shared_ptr<shared_state> state,
			t_connection_type connection_type);

    explicit connection( boost::asio::ip::tcp::socket&& sock,
			 std::shared_ptr<shared_state> state,
			t_connection_type connection_type);



    virtual ~connection() noexcept(false);

    /// Start the first asynchronous operation for the connection.
    bool start(bool is_income, bool is_multithreaded);

    // `real_remote` is the actual endpoint (if connection is to proxy, etc.)
    bool start(bool is_income, bool is_multithreaded, network_address real_remote);

    void get_context(t_connection_context& context_){context_ = context;}

    void call_back_starter();
    
    void save_dbg_log();


		bool speed_limit_is_enabled() const; ///< tells us should we be sleeping here (e.g. do not sleep on RPC connections)

    bool cancel();
    
  private:
    //----------------- i_service_endpoint ---------------------
    virtual bool do_send(shared_sv message); ///< (see do_send from i_service_endpoint)
    virtual bool send_done();
    virtual bool close();
    virtual bool call_run_once_service_io();
    virtual bool request_callback();
    virtual boost::asio::io_service& get_io_service();
    virtual bool add_ref();
    virtual bool release();
    //------------------------------------------------------
    bool do_send_chunk(shared_sv chunk); ///< will send (or queue) a part of data. internal use only

    std::shared_ptr<connection<t_protocol_handler> > safe_shared_from_this();
    bool shutdown();
    /// Handle completion of a receive operation.
    void handle_receive(const boost::system::error_code& e,
      std::size_t bytes_transferred);

    /// Handle completion of a read operation.
    void handle_read(const boost::system::error_code& e,
      std::size_t bytes_transferred);

    /// Handle completion of a write operation.
    void handle_write(const boost::system::error_code& e, size_t cb);

    /// reset connection timeout timer and callback
    void reset_timer(std::chrono::milliseconds ms, bool add);
    std::chrono::milliseconds get_default_timeout();
    std::chrono::milliseconds get_timeout_from_bytes_read(size_t bytes);

    /// host connection count tracking
    unsigned int host_count(const std::string &host, int delta = 0);

    /// Buffer for incoming data.
    std::array<char, 8192> buffer_;

    t_connection_context context;

	// TODO what do they mean about wait on destructor?? --rfree :
    //this should be the last one, because it could be wait on destructor, while other activities possible on other threads
    t_protocol_handler m_protocol_handler;
    //typename t_protocol_handler::config_type m_dummy_config;
    size_t m_reference_count = 0; // reference count managed through add_ref/release support
    std::shared_ptr<connection<t_protocol_handler> > m_self_ref; // the reference to hold
    std::mutex m_self_refs_lock;
    std::mutex m_chunking_lock; // held while we add small chunks of the big do_send() to small do_send_chunk()
    std::mutex m_shutdown_lock; // held while shutting down
    
    t_connection_type m_connection_type;
    
    // for calculate speed (last 60 sec)
    network_throttle m_throttle_speed_in;
    network_throttle m_throttle_speed_out;
    std::mutex m_throttle_speed_in_mutex;
    std::mutex m_throttle_speed_out_mutex;

    boost::asio::steady_timer m_timer;
    bool m_local;
    bool m_ready_to_close;
    std::string m_host;

	public:
			void setRpcStation();
  };


  /************************************************************************/
  /*                                                                      */
  /************************************************************************/
  template<class t_protocol_handler>
  class boosted_tcp_server
  {
    boosted_tcp_server(const boosted_tcp_server&) = delete;
    boosted_tcp_server& operator=(const boosted_tcp_server&) = delete;

    enum try_connect_result_t
    {
      CONNECT_SUCCESS,
      CONNECT_FAILURE,
    };

  public:
    typedef std::shared_ptr<connection<t_protocol_handler> > connection_ptr;
    typedef typename t_protocol_handler::connection_context t_connection_context;
    /// Construct the server to listen on the specified TCP address and port, and
    /// serve up files from the given directory.

    boosted_tcp_server(t_connection_type connection_type);
    explicit boosted_tcp_server(boost::asio::io_service& external_io_service, t_connection_type connection_type);
    ~boosted_tcp_server();
    
    std::map<std::string, t_connection_type> server_type_map;
    void create_server_type_map();

    bool init_server(uint32_t port, const std::string& address = "0.0.0.0",
        uint32_t port_ipv6 = 0, const std::string& address_ipv6 = "::", bool use_ipv6 = false, bool require_ipv4 = true);
    bool init_server(const std::string port,  const std::string& address = "0.0.0.0",
        const std::string port_ipv6 = "", const std::string address_ipv6 = "::", bool use_ipv6 = false, bool require_ipv4 = true);

    /// Run the server's io_service loop.
    bool run_server(size_t threads_count, bool wait = true);

    /// wait for service workers stop
    bool server_stop();

    /// Stop the server.
    void send_stop_signal();

    bool is_stop_signal_sent() const noexcept { return m_stop_signal_sent; };

    const std::atomic<bool>& get_stop_signal() const noexcept { return m_stop_signal_sent; }

    void set_threads_prefix(const std::string& prefix_name);

    bool deinit_server(){return true;}

    size_t get_threads_count(){return m_threads_count;}

    void set_connection_filter(i_connection_filter* pfilter);

    void set_default_remote(epee::net_utils::network_address remote)
    {
      default_remote = std::move(remote);
    }

    bool add_connection(t_connection_context& out, boost::asio::ip::tcp::socket&& sock, network_address real_remote);
    try_connect_result_t try_connect(connection_ptr new_connection_l, const std::string& adr, const std::string& port, boost::asio::ip::tcp::socket &sock_, const boost::asio::ip::tcp::endpoint &remote_endpoint, const std::string &bind_ip, uint32_t conn_timeout);
    bool connect(const std::string& adr, const std::string& port, uint32_t conn_timeot, t_connection_context& cn, const std::string& bind_ip = "0.0.0.0");
    template<class t_callback>
    bool connect_async(const std::string& adr, const std::string& port, uint32_t conn_timeot, const t_callback &cb, const std::string& bind_ip = "0.0.0.0");

    typename t_protocol_handler::config_type& get_config_object()
    {
      assert(m_state != nullptr); // always set in constructor
      return *m_state;
    }

    std::shared_ptr<typename t_protocol_handler::config_type> get_config_shared()
    {
      assert(m_state != nullptr); // always set in constructor
      return {m_state};
    }

    int get_binded_port(){return m_port;}
    int get_binded_port_ipv6(){return m_port_ipv6;}

    long get_connections_count() const
    {
      assert(m_state != nullptr); // always set in constructor
      auto connections_count = m_state->sock_count > 0 ? (m_state->sock_count - 1) : 0; // Socket count minus listening socket
      return connections_count;
    }

    boost::asio::io_service& get_io_service(){return io_service_;}

    template <class Callback>
    struct idle_callback_conext
    {
      idle_callback_conext(boost::asio::io_service& io_service, Callback h, std::chrono::milliseconds period)
        : m_timer{io_service}, m_handler{std::move(h)}, m_period{period}
      {}

      bool call_handler()
      {
        return m_handler();
      }

      Callback m_handler;
      std::chrono::milliseconds m_period;
      boost::asio::steady_timer m_timer;
    };

    template<class t_handler>
    bool add_idle_handler(t_handler callback, std::chrono::milliseconds timeout)
      {
        auto ptr = std::make_shared<idle_callback_conext<t_handler>>(io_service_, std::move(callback), timeout);
        //needed call handler here ?...
        ptr->m_timer.expires_from_now(ptr->m_period);
        ptr->m_timer.async_wait([this, ptr] (const boost::system::error_code&) { global_timer_handler<t_handler>(ptr); });
        return true;
      }

    template<class t_handler>
    void global_timer_handler(/*const boost::system::error_code& err, */std::shared_ptr<idle_callback_conext<t_handler>> ptr)
    {
      //if handler return false - he don't want to be called anymore
      if(!ptr->call_handler())
        return;
      ptr->m_timer.expires_from_now(ptr->m_period);
      ptr->m_timer.async_wait([this, ptr] (const boost::system::error_code&) { global_timer_handler<t_handler>(ptr); });
    }

    template<class t_handler>
    bool async_call(t_handler t_callback)
    {
      io_service_.post(std::move(t_callback));
      return true;
    }

  private:
    /// Run the server's io_service loop.
    bool worker_thread();
    /// Handle completion of an asynchronous accept operation.
    void handle_accept_ipv4(const boost::system::error_code& e);
    void handle_accept_ipv6(const boost::system::error_code& e);
    void handle_accept(const boost::system::error_code& e, bool ipv6 = false);

    bool is_thread_worker();

    const std::shared_ptr<typename connection<t_protocol_handler>::shared_state> m_state;

    /// The io_service used to perform asynchronous operations.
    struct worker
    {
      worker()
        : io_service(), work(io_service)
      {}

      boost::asio::io_service io_service;
      boost::asio::io_service::work work;
    };
    std::unique_ptr<worker> m_io_service_local_instance;
    boost::asio::io_service& io_service_;    

    /// Acceptor used to listen for incoming connections.
    boost::asio::ip::tcp::acceptor acceptor_;
    boost::asio::ip::tcp::acceptor acceptor_ipv6;
    epee::net_utils::network_address default_remote;

    std::atomic<bool> m_stop_signal_sent;
    uint32_t m_port;
    uint32_t m_port_ipv6;
    std::string m_address;
    std::string m_address_ipv6;
    bool m_use_ipv6;
    bool m_require_ipv4;
    std::string m_thread_name_prefix; //TODO: change to enum server_type, now used
    size_t m_threads_count;
    std::vector<std::thread> m_threads;
    std::thread::id m_main_thread_id;
    std::mutex m_threads_lock;
    std::atomic<uint32_t> m_thread_index;

    t_connection_type m_connection_type;

    /// The next connection to be accepted
    connection_ptr new_connection_;
    connection_ptr new_connection_ipv6;


    std::mutex connections_mutex;
    std::set<connection_ptr> connections_;
  }; // class <>boosted_tcp_server


} // namespace
} // namespace

#include "abstract_tcp_server2.inl"

#endif
