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



#include <boost/bind/bind.hpp>
#include <boost/uuid/random_generator.hpp>
#include <boost/asio/steady_timer.hpp>
#include "warnings.h"
#include "string_tools.h"
#include "misc_language.h"
#include "net/local_ip.h"
#include "pragma_comp_defs.h"

#include <chrono>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <functional>
#include <random>

#undef LOKI_DEFAULT_LOG_CATEGORY
#define LOKI_DEFAULT_LOG_CATEGORY "net"

#define AGGRESSIVE_TIMEOUT_THRESHOLD 120 // sockets
#define NEW_CONNECTION_TIMEOUT_LOCAL 1200000 // 2 minutes
#define NEW_CONNECTION_TIMEOUT_REMOTE 10000 // 10 seconds
#define DEFAULT_TIMEOUT_MS_LOCAL 1800000 // 30 minutes
#define DEFAULT_TIMEOUT_MS_REMOTE 300000 // 5 minutes
#define TIMEOUT_EXTRA_MS_PER_BYTE 0.2


PRAGMA_WARNING_PUSH
namespace epee
{
namespace net_utils
{
  template<typename T>
  T& check_and_get(std::shared_ptr<T>& ptr)
  {
    CHECK_AND_ASSERT_THROW_MES(bool(ptr), "shared_state cannot be null");
    return *ptr;
  }

  /************************************************************************/
  /*                                                                      */
  /************************************************************************/
PRAGMA_WARNING_DISABLE_VS(4355)

  template<class t_protocol_handler>
  connection<t_protocol_handler>::connection( boost::asio::io_service& io_service,
                std::shared_ptr<shared_state> state,
		t_connection_type connection_type
	)
	: connection(boost::asio::ip::tcp::socket{io_service}, std::move(state), connection_type)
  {
  }

  template<class t_protocol_handler>
  connection<t_protocol_handler>::connection( boost::asio::ip::tcp::socket&& sock,
                std::shared_ptr<shared_state> state,
		t_connection_type connection_type
	)
	: 
		connection_basic(std::move(sock), state),
		m_protocol_handler(this, check_and_get(state), context),
		m_connection_type( connection_type ),
		m_throttle_speed_in("speed_in", "throttle_speed_in"),
		m_throttle_speed_out("speed_out", "throttle_speed_out"),
		m_timer(GET_IO_SERVICE(socket_)),
		m_local(false),
		m_ready_to_close(false)
  {
    MDEBUG("test, connection constructor set m_connection_type="<<m_connection_type);
  }

PRAGMA_WARNING_DISABLE_VS(4355)
  //---------------------------------------------------------------------------------
  template<class t_protocol_handler>
  connection<t_protocol_handler>::~connection() noexcept(false)
  {
    if(!m_was_shutdown)
    {
      MTRACE("[sock " << socket().native_handle() << "] Socket destroyed without shutdown.");
      shutdown();
    }

    MTRACE("[sock " << socket().native_handle() << "] Socket destroyed");
  }
  //---------------------------------------------------------------------------------
  template<class t_protocol_handler>
  std::shared_ptr<connection<t_protocol_handler> > connection<t_protocol_handler>::safe_shared_from_this()
  {
    try
    {
      return connection<t_protocol_handler>::shared_from_this();
    }
    catch (const std::bad_weak_ptr&)
    {
      // It happens when the connection is being deleted
      return nullptr;
    }
  }
  //---------------------------------------------------------------------------------
  template<class t_protocol_handler>
  bool connection<t_protocol_handler>::start(bool is_income, bool is_multithreaded)
  {
    TRY_ENTRY();

    boost::system::error_code ec;
    auto remote_ep = socket().remote_endpoint(ec);
    CHECK_AND_NO_ASSERT_MES(!ec, false, "Failed to get remote endpoint: " << ec.message() << ':' << ec.value());
    CHECK_AND_NO_ASSERT_MES(remote_ep.address().is_v4() || remote_ep.address().is_v6(), false, "only IPv4 and IPv6 supported here");

    if (remote_ep.address().is_v4())
    {
      const unsigned long ip_ = boost::asio::detail::socket_ops::host_to_network_long(remote_ep.address().to_v4().to_ulong());
      return start(is_income, is_multithreaded, ipv4_network_address{uint32_t(ip_), remote_ep.port()});
    }
    else
    {
      const auto ip_ = remote_ep.address().to_v6();
      return start(is_income, is_multithreaded, ipv6_network_address{ip_, remote_ep.port()});
    }
    CATCH_ENTRY_L0("connection<t_protocol_handler>::start()", false);
  }
  //---------------------------------------------------------------------------------
  template<class t_protocol_handler>
  bool connection<t_protocol_handler>::start(bool is_income, bool is_multithreaded, network_address real_remote)
  {
    TRY_ENTRY();

    // Use safe_shared_from_this, because of this is public method and it can be called on the object being deleted
    auto self = safe_shared_from_this();
    if(!self)
      return false;

    m_is_multithreaded = is_multithreaded;
    m_local = real_remote.is_loopback() || real_remote.is_local();

    // create a random uuid, we don't need crypto strength here
    const boost::uuids::uuid random_uuid = boost::uuids::random_generator()();

    context = t_connection_context{};
    context.set_details(random_uuid, std::move(real_remote), is_income);

    boost::system::error_code ec;
    auto local_ep = socket().local_endpoint(ec);
    CHECK_AND_NO_ASSERT_MES(!ec, false, "Failed to get local endpoint: " << ec.message() << ':' << ec.value());

    MTRACE("[sock " << socket_.native_handle() << "] new connection from " << print_connection_context_short(context) <<
      " to " << local_ep.address().to_string() << ':' << local_ep.port() <<
      ", total sockets objects " << get_state().sock_count);

    if(static_cast<shared_state&>(get_state()).pfilter && !static_cast<shared_state&>(get_state()).pfilter->is_remote_host_allowed(context.m_remote_address))
    {
      MDEBUG("[sock " << socket().native_handle() << "] host denied " << context.m_remote_address.host_str() << ", shutdowning connection");
      close();
      return false;
    }

    m_host = context.m_remote_address.host_str();
    try { host_count(m_host, 1); } catch(...) { /* ignore */ }

    m_protocol_handler.after_init_connection();

    reset_timer(std::chrono::milliseconds(m_local ? NEW_CONNECTION_TIMEOUT_LOCAL : NEW_CONNECTION_TIMEOUT_REMOTE), false);

    socket().async_read_some(boost::asio::buffer(buffer_),
      strand_.wrap(
        boost::bind(&connection<t_protocol_handler>::handle_read, self,
          boost::asio::placeholders::error,
          boost::asio::placeholders::bytes_transferred)));
#if !defined(_WIN32) || !defined(__i686)
	// not supported before Windows7, too lazy for runtime check
	// Just exclude for 32bit windows builds
	//set ToS flag
	int tos = get_tos_flag();
	boost::asio::detail::socket_option::integer< IPPROTO_IP, IP_TOS >
	optionTos( tos );
    socket().set_option( optionTos );
	//MDEBUG("Set ToS flag to " << tos);
#endif
	
	boost::asio::ip::tcp::no_delay noDelayOption(false);
	socket().set_option(noDelayOption);
	
    return true;

    CATCH_ENTRY_L0("connection<t_protocol_handler>::start()", false);
  }
  //---------------------------------------------------------------------------------
  template<class t_protocol_handler>
  bool connection<t_protocol_handler>::request_callback()
  {
    TRY_ENTRY();
    MDEBUG("[" << print_connection_context_short(context) << "] request_callback");
    // Use safe_shared_from_this, because of this is public method and it can be called on the object being deleted
    auto self = safe_shared_from_this();
    if(!self)
      return false;

    strand_.post(boost::bind(&connection<t_protocol_handler>::call_back_starter, self));
    CATCH_ENTRY_L0("connection<t_protocol_handler>::request_callback()", false);
    return true;
  }
  //---------------------------------------------------------------------------------
  template<class t_protocol_handler>
  boost::asio::io_service& connection<t_protocol_handler>::get_io_service()
  {
    return GET_IO_SERVICE(socket());
  }
  //---------------------------------------------------------------------------------
  template<class t_protocol_handler>
  bool connection<t_protocol_handler>::add_ref()
  {
    TRY_ENTRY();

    // Use safe_shared_from_this, because of this is public method and it can be called on the object being deleted
    auto self = safe_shared_from_this();
    if(!self)
      return false;
    //MTRACE("[sock " << socket().native_handle() << "] add_ref, m_peer_number=" << mI->m_peer_number);
    std::lock_guard lock{self->m_self_refs_lock};
    //MTRACE("[sock " << socket().native_handle() << "] add_ref 2, m_peer_number=" << mI->m_peer_number);
    if(m_was_shutdown)
      return false;
    ++m_reference_count;
    m_self_ref = std::move(self);
    return true;
    CATCH_ENTRY_L0("connection<t_protocol_handler>::add_ref()", false);
  }
  //---------------------------------------------------------------------------------
  template<class t_protocol_handler>
  bool connection<t_protocol_handler>::release()
  {
    TRY_ENTRY();
    std::shared_ptr<connection<t_protocol_handler> >  back_connection_copy;
    LOG_TRACE_CC(context, "[sock " << socket().native_handle() << "] release");
    std::lock_guard lock{m_self_refs_lock};
    CHECK_AND_ASSERT_MES(m_reference_count, false, "[sock " << socket().native_handle() << "] m_reference_count already at 0 at connection<t_protocol_handler>::release() call");
    // is this the last reference?
    if (--m_reference_count == 0) {
        // move the held reference to a local variable, keeping the object alive until the function terminates
        std::swap(back_connection_copy, m_self_ref);
    }
    return true;
    CATCH_ENTRY_L0("connection<t_protocol_handler>::release()", false);
  }
  //---------------------------------------------------------------------------------
  template<class t_protocol_handler>
  void connection<t_protocol_handler>::call_back_starter()
  {
    TRY_ENTRY();
    MDEBUG("[" << print_connection_context_short(context) << "] fired_callback");
    m_protocol_handler.handle_qued_callback();
    CATCH_ENTRY_L0("connection<t_protocol_handler>::call_back_starter()", void());
  }
  //---------------------------------------------------------------------------------
  template<class t_protocol_handler>
  void connection<t_protocol_handler>::save_dbg_log()
  {
    std::string address, port;
    boost::system::error_code e;

    boost::asio::ip::tcp::endpoint endpoint = socket().remote_endpoint(e);
    if (e)
    {
      address = "<not connected>";
      port = "<not connected>";
    }
    else
    {
      address = endpoint.address().to_string();
      port = boost::lexical_cast<std::string>(endpoint.port());
    }
    MDEBUG(" connection type " << to_string( m_connection_type ) << " "
        << socket().local_endpoint().address().to_string() << ":" << socket().local_endpoint().port()
        << " <--> " << context.m_remote_address.str() << " (via " << address << ":" << port << ")");
  }
  //---------------------------------------------------------------------------------
  template<class t_protocol_handler>
  void connection<t_protocol_handler>::handle_read(const boost::system::error_code& e,
    std::size_t bytes_transferred)
  {
    TRY_ENTRY();
    //MINFO("[sock " << socket().native_handle() << "] Async read calledback.");
    
    if (!e)
    {
        double current_speed_down;
		{
			std::lock_guard lock{m_throttle_speed_in_mutex};
			m_throttle_speed_in.handle_trafic_exact(bytes_transferred);
			current_speed_down = m_throttle_speed_in.get_current_speed();
		}
        context.m_current_speed_down = current_speed_down;
        context.m_max_speed_down = std::max(context.m_max_speed_down, current_speed_down);
    
    {
			std::lock_guard lock{epee::net_utils::network_throttle_manager::network_throttle_manager::m_lock_get_global_throttle_in};
			epee::net_utils::network_throttle_manager::network_throttle_manager::get_global_throttle_in().handle_trafic_exact(bytes_transferred);
		}

		double delay=0; // will be calculated - how much we should sleep to obey speed limit etc


		if (speed_limit_is_enabled()) {
			do // keep sleeping if we should sleep
			{
				{
					std::lock_guard lock{epee::net_utils::network_throttle_manager::m_lock_get_global_throttle_in};
					delay = epee::net_utils::network_throttle_manager::get_global_throttle_in().get_sleep_time_after_tick( bytes_transferred );
				}
				
				delay *= 0.5;
				long int ms = (long int)(delay * 100);
				if (ms > 0) {
					reset_timer(std::chrono::milliseconds(ms + 1), true);
					std::this_thread::sleep_for(std::chrono::milliseconds{ms});
				}
			} while(delay > 0);
		} // any form of sleeping
		
      //MINFO("[sock " << socket().native_handle() << "] RECV " << bytes_transferred);
      logger_handle_net_read(bytes_transferred);
      context.m_last_recv = std::chrono::steady_clock::now();
      context.m_recv_cnt += bytes_transferred;
      m_ready_to_close = false;
      bool recv_res = m_protocol_handler.handle_recv(buffer_.data(), bytes_transferred);
      if(!recv_res)
      {  
        //MINFO("[sock " << socket().native_handle() << "] protocol_want_close");
        //some error in protocol, protocol handler ask to close connection
        m_want_close_connection = true;
        bool do_shutdown = false;
        {
          std::lock_guard lock{m_send_que_lock};
          if(!m_send_que.size())
            do_shutdown = true;
        }
        if(do_shutdown)
          shutdown();
      }else
      {
        reset_timer(get_timeout_from_bytes_read(bytes_transferred), false);
        socket().async_read_some(boost::asio::buffer(buffer_),
          strand_.wrap(
            boost::bind(&connection<t_protocol_handler>::handle_read, connection<t_protocol_handler>::shared_from_this(),
              boost::asio::placeholders::error,
              boost::asio::placeholders::bytes_transferred)));
        //MINFO("[sock " << socket().native_handle() << "]Async read requested.");
      }
    }else
    {
      MTRACE("[sock " << socket().native_handle() << "] Some not success at read: " << e.message() << ':' << e.value());
      if(e.value() != 2)
      {
        MTRACE("[sock " << socket().native_handle() << "] Some problems at read: " << e.message() << ':' << e.value());
        shutdown();
      }
      else
      {
        MTRACE("[sock " << socket().native_handle() << "] peer closed connection");
        bool do_shutdown = false;
        {
          std::lock_guard lock{m_send_que_lock};
          if(!m_send_que.size())
            do_shutdown = true;
        }
        if (m_ready_to_close || do_shutdown)
          shutdown();
      }
      m_ready_to_close = true;
    }
    // If an error occurs then no new asynchronous operations are started. This
    // means that all shared_ptr references to the connection object will
    // disappear and the object will be destroyed automatically after this
    // handler returns. The connection class's destructor closes the socket.
    CATCH_ENTRY_L0("connection<t_protocol_handler>::handle_read", void());
  }
  //---------------------------------------------------------------------------------
  template<class t_protocol_handler>
  bool connection<t_protocol_handler>::call_run_once_service_io()
  {
    TRY_ENTRY();
    if(!m_is_multithreaded)
    {
      //single thread model, we can wait in blocked call
      size_t cnt = GET_IO_SERVICE(socket()).run_one();
      if(!cnt)//service is going to quit
        return false;
    }else
    {
      //multi thread model, we can't(!) wait in blocked call
      //so we make non blocking call and releasing CPU by calling sleep(0); 
      //if no handlers were called
      //TODO: Maybe we need to have have critical section + event + callback to upper protocol to
      //ask it inside(!) critical region if we still able to go in event wait...
      size_t cnt = GET_IO_SERVICE(socket()).poll_one();
      if(!cnt)
        misc_utils::sleep_no_w(1);
    }
    
    return true;
    CATCH_ENTRY_L0("connection<t_protocol_handler>::call_run_once_service_io", false);
  }
  //---------------------------------------------------------------------------------
    template<class t_protocol_handler>
  bool connection<t_protocol_handler>::do_send(shared_sv message) {
    TRY_ENTRY();

    // Use safe_shared_from_this, because of this is public method and it can be called on the object being deleted
    auto self = safe_shared_from_this();
    if (!self) return false;
    if (m_was_shutdown) return false;
		// TODO avoid copy

		const double factor = 32; // TODO config
		typedef long long signed int t_safe; // my t_size to avoid any overunderflow in arithmetic
		const t_safe chunksize_good = (t_safe)( 1024 * std::max(1.0,factor) );
        const t_safe chunksize_max = chunksize_good * 2 ;
		const bool allow_split = (m_connection_type == e_connection_type_RPC) ? false : true; // do not split RPC data

        CHECK_AND_ASSERT_MES(! (chunksize_max<0), false, "Negative chunksize_max" ); // make sure it is unsigned before removin sign with cast:
        long long unsigned int chunksize_max_unsigned = static_cast<long long unsigned int>( chunksize_max ) ;

        if (allow_split && (message.size() > chunksize_max_unsigned)) {
            { // LOCK: chunking
                std::lock_guard send_guard{m_chunking_lock};

                MDEBUG("do_send() will SPLIT into small chunks, from packet="<<message.size()<<" B for ptr="<<(void*)message.ptr.get());

                while (!message.view.empty()) {
                    bool ok = do_send_chunk(message.extract_prefix(chunksize_good));

                    if (!ok) {
                        MDEBUG("do_send() DONE ***FAILED***");
                        MDEBUG("do_send() SEND was aborted in middle of big package - this is probably harmless (e.g. peer closed connection)");
                        return false; // partial failure in sending
                    }
                }

				MDEBUG("do_send() DONE SPLIT send");
                MDEBUG("do_send() m_connection_type = " << m_connection_type);

				return true; // done - e.g. queued - all the chunks of current do_send call
			} // LOCK: chunking
		} // a big block (to be chunked) - all chunks
		else { // small block
			return do_send_chunk(std::move(message)); // just send as 1 big chunk
		}

    CATCH_ENTRY_L0("connection<t_protocol_handler>::do_send", false);
	} // do_send()

  //---------------------------------------------------------------------------------
  template<class t_protocol_handler>
  bool connection<t_protocol_handler>::do_send_chunk(shared_sv chunk)
  {
    TRY_ENTRY();
    // Use safe_shared_from_this, because of this is public method and it can be called on the object being deleted
    auto self = safe_shared_from_this();
    if(!self)
      return false;
    if(m_was_shutdown)
      return false;
    double current_speed_up;
    {
		std::lock_guard lock{m_throttle_speed_out_mutex};
		m_throttle_speed_out.handle_trafic_exact(chunk.size());
		current_speed_up = m_throttle_speed_out.get_current_speed();
	}
    context.m_current_speed_up = current_speed_up;
    context.m_max_speed_up = std::max(context.m_max_speed_up, current_speed_up);

    //MINFO("[sock " << socket().native_handle() << "] SEND " << cb);
    context.m_last_send = std::chrono::steady_clock::now();
    context.m_send_cnt += chunk.size();
    //some data should be wrote to stream
    //request complete
    
    // No sleeping here; sleeping is done once and for all in "handle_write"

    std::unique_lock queue_lock{m_send_que_lock};

    long int retry=0;
    const long int retry_limit = 5*4;
    while (m_send_que.size() > ABSTRACT_SERVER_SEND_QUE_MAX_COUNT)
    {
        retry++;

        /* if ( ::cryptonote::core::get_is_stopping() ) { // TODO re-add fast stop
            MDEBUG("ABORT queue wait due to stopping");
            return false; // aborted
        }*/

        using engine           = std::mt19937;
        static bool initialized = false;
        static engine rng;
        if (!initialized)
        {
          initialized = true;
          std::random_device dev;
          std::seed_seq::result_type rand[engine::state_size]{}; // Use complete bit space
          std::generate_n(rand, engine::state_size, std::ref(dev));
          std::seed_seq seed(rand, rand + engine::state_size);
          rng.seed(seed);
        }

        int ms = std::uniform_int_distribution<>{250, 299}(rng);
        MDEBUG("Sleeping because QUEUE is FULL, in " << __FUNCTION__ << " for " << ms << " ms before packet_size="<<chunk.size()); // XXX debug sleep
        queue_lock.unlock();
        std::this_thread::sleep_for(std::chrono::milliseconds{ms});
        queue_lock.lock();
        MDEBUG("sleep for queue: " << ms);

        if (retry > retry_limit) {
            MWARNING("send que size is more than ABSTRACT_SERVER_SEND_QUE_MAX_COUNT(" << ABSTRACT_SERVER_SEND_QUE_MAX_COUNT << "), shutting down connection");
            shutdown();
            return false;
        }
    }

    m_send_que.push_back(std::move(chunk));

    if(m_send_que.size() > 1)
    { // active operation should be in progress, nothing to do, just wait last operation callback
        auto size_now = m_send_que.back().size();
        MDEBUG("do_send_chunk() NOW just queues: packet="<<size_now<<" B, is added to queue-size="<<m_send_que.size());
        //do_send_handler_delayed( ptr , size_now ); // (((H))) // empty function
      
      LOG_TRACE_CC(context, "[sock " << socket().native_handle() << "] Async send requested " << m_send_que.front().size());
    }
    else
    { // no active operation

        if(m_send_que.size()!=1)
        {
            MERROR("Looks like no active operations, but send que size != 1!!");
            return false;
        }

        auto size_now = m_send_que.front().size();
        MDEBUG("do_send_chunk() NOW SENSD: packet="<<size_now<<" B");
        if (speed_limit_is_enabled())
			do_send_handler_write( m_send_que.back().data(), m_send_que.back().size() ); // (((H)))

        CHECK_AND_ASSERT_MES( size_now == m_send_que.front().size(), false, "Unexpected queue size");
        reset_timer(get_default_timeout(), false);
        using namespace boost::placeholders;
        boost::asio::async_write(socket(), boost::asio::buffer(m_send_que.front().data(), size_now ) ,
                                 strand_.wrap(
                                 boost::bind(&connection<t_protocol_handler>::handle_write, self, _1, _2)
                                 )
                                 );
        //MTRACE("(chunk): " << size_now);
        //logger_handle_net_write(size_now);
        //MINFO("[sock " << socket().native_handle() << "] Async send requested " << m_send_que.front().size());
    }
    
    //do_send_handler_stop( ptr , cb ); // empty function

    return true;

    CATCH_ENTRY_L0("connection<t_protocol_handler>::do_send_chunk", false);
  } // do_send_chunk
  //---------------------------------------------------------------------------------
  template<class t_protocol_handler>
  std::chrono::milliseconds connection<t_protocol_handler>::get_default_timeout()
  {
    unsigned count;
    try { count = host_count(m_host); } catch (...) { count = 0; }
    const unsigned shift = get_state().sock_count > AGGRESSIVE_TIMEOUT_THRESHOLD ? std::min(std::max(count, 1u) - 1, 8u) : 0;
    if (m_local)
      return std::chrono::milliseconds{DEFAULT_TIMEOUT_MS_LOCAL >> shift};
    else
      return std::chrono::milliseconds{DEFAULT_TIMEOUT_MS_REMOTE >> shift};
  }
  //---------------------------------------------------------------------------------
  template<class t_protocol_handler>
  std::chrono::milliseconds connection<t_protocol_handler>::get_timeout_from_bytes_read(size_t bytes)
  {
    std::chrono::milliseconds ms{(unsigned)(bytes * TIMEOUT_EXTRA_MS_PER_BYTE)};
    if (auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(m_timer.expires_at() - std::chrono::steady_clock::now());
        remaining > 0ms)
      ms += remaining;
    if (ms > get_default_timeout())
      ms = get_default_timeout();
    return ms;
  }
  //---------------------------------------------------------------------------------
  template<class t_protocol_handler>
  unsigned int connection<t_protocol_handler>::host_count(const std::string &host, int delta)
  {
    static std::mutex hosts_mutex;
    std::lock_guard lock{hosts_mutex};
    static std::map<std::string, unsigned int> hosts;
    unsigned int &val = hosts[host];
    if (delta > 0)
      MTRACE("New connection from host " << host << ": " << val);
    else if (delta < 0)
      MTRACE("Closed connection from host " << host << ": " << val);
    CHECK_AND_ASSERT_THROW_MES(delta >= 0 || val >= (unsigned)-delta, "Count would go negative");
    CHECK_AND_ASSERT_THROW_MES(delta <= 0 || val <= std::numeric_limits<unsigned int>::max() - (unsigned)delta, "Count would wrap");
    val += delta;
    return val;
  }
  //---------------------------------------------------------------------------------
  template<class t_protocol_handler>
  void connection<t_protocol_handler>::reset_timer(std::chrono::milliseconds ms, bool add)
  {
    if (ms < 0s)
    {
      MWARNING("Ignoring negative timeout " << ms.count());
      return;
    }
    MTRACE((add ? "Adding" : "Setting") << " " << ms.count() << "ms expiry");
    auto self = safe_shared_from_this();
    if(!self)
    {
      MERROR("Resetting timer on a dead object");
      return;
    }
    if (m_was_shutdown)
    {
      MERROR("Setting timer on a shut down object");
      return;
    }
    if (add)
    {
      if (const auto cur = std::chrono::duration_cast<std::chrono::milliseconds>(m_timer.expires_at() - std::chrono::steady_clock::now());
          cur > 0s)
        ms += cur;
    }
    m_timer.expires_from_now(ms);
    m_timer.async_wait([=](const boost::system::error_code& ec)
    {
      if(ec == boost::asio::error::operation_aborted)
        return;
      MDEBUG(context << "connection timeout, closing");
      self->close();
    });
  }
  //---------------------------------------------------------------------------------
  template<class t_protocol_handler>
  bool connection<t_protocol_handler>::shutdown()
  {
    std::unique_lock lock{m_shutdown_lock};
    if (m_was_shutdown)
      return true;
    m_was_shutdown = true;
    // Initiate graceful connection closure.
    m_timer.cancel();
    boost::system::error_code ignored_ec;
    socket().shutdown(boost::asio::ip::tcp::socket::shutdown_both, ignored_ec);
    if (!m_host.empty())
    {
      try { host_count(m_host, -1); } catch (...) { /* ignore */ }
      m_host = "";
    }
    lock.unlock();
    m_protocol_handler.release_protocol();
    return true;
  }
  //---------------------------------------------------------------------------------
  template<class t_protocol_handler>
  bool connection<t_protocol_handler>::close()
  {
    TRY_ENTRY();
    auto self = safe_shared_from_this();
    if(!self)
      return false;
    //MINFO("[sock " << socket().native_handle() << "] Que Shutdown called.");
    m_timer.cancel();
    size_t send_que_size = 0;
    {
      std::lock_guard lock{m_send_que_lock};
      send_que_size = m_send_que.size();
    }
    m_want_close_connection = true;
    if(!send_que_size)
    {
      shutdown();
    }
    
    return true;
    CATCH_ENTRY_L0("connection<t_protocol_handler>::close", false);
  }
  //---------------------------------------------------------------------------------
  template<class t_protocol_handler>
  bool connection<t_protocol_handler>::send_done()
  {
    if (m_ready_to_close)
      return close();
    m_ready_to_close = true;
    return true;
  }
  //---------------------------------------------------------------------------------
  template<class t_protocol_handler>
  bool connection<t_protocol_handler>::cancel()
  {
    return close();
  }
  //---------------------------------------------------------------------------------
  template<class t_protocol_handler>
  void connection<t_protocol_handler>::handle_write(const boost::system::error_code& e, size_t cb)
  {
    TRY_ENTRY();
    LOG_TRACE_CC(context, "[sock " << socket().native_handle() << "] Async send calledback " << cb);

    if (e)
    {
      MDEBUG("[sock " << socket().native_handle() << "] Some problems at write: " << e.message() << ':' << e.value());
      shutdown();
      return;
    }
    logger_handle_net_write(cb);

                // The single sleeping that is needed for correctly handling "out" speed throttling
		if (speed_limit_is_enabled()) {
			sleep_before_packet(cb, 1, 1);
		}

    bool do_shutdown = false;
    std::unique_lock lock{m_send_que_lock};
    if(m_send_que.empty())
    {
      MERROR("[sock " << socket().native_handle() << "] m_send_que.size() == 0 at handle_write!");
      return;
    }

    m_send_que.pop_front();
    if(m_send_que.empty())
    {
      if(m_want_close_connection)
      {
        do_shutdown = true;
      }
    }else
    {
      //have more data to send
		reset_timer(get_default_timeout(), false);
		auto size_now = m_send_que.front().size();
		MDEBUG("handle_write() NOW SENDS: packet="<<size_now<<" B" <<", from  queue size="<<m_send_que.size());
		if (speed_limit_is_enabled())
			do_send_handler_write_from_queue(e, m_send_que.front().size() , m_send_que.size()); // (((H)))
		CHECK_AND_ASSERT_MES( size_now == m_send_que.front().size(), void(), "Unexpected queue size");
        using namespace boost::placeholders;
        boost::asio::async_write(socket(), boost::asio::buffer(m_send_que.front().data(), size_now) , 
           strand_.wrap(
            boost::bind(&connection<t_protocol_handler>::handle_write, connection<t_protocol_handler>::shared_from_this(), _1, _2)
			  )
          );
      //MTRACE("(normal)" << size_now);
    }
    lock.unlock();

    if(do_shutdown)
    {
      shutdown();
    }
    CATCH_ENTRY_L0("connection<t_protocol_handler>::handle_write", void());
  }

  //---------------------------------------------------------------------------------
  template<class t_protocol_handler>
  void connection<t_protocol_handler>::setRpcStation()
  {
    m_connection_type = e_connection_type_RPC; 
    MDEBUG("set m_connection_type = RPC ");
  }


  template<class t_protocol_handler>
  bool connection<t_protocol_handler>::speed_limit_is_enabled() const {
		return m_connection_type != e_connection_type_RPC ;
	}

  /************************************************************************/
  /*                                                                      */
  /************************************************************************/

  template<class t_protocol_handler>
  boosted_tcp_server<t_protocol_handler>::boosted_tcp_server( t_connection_type connection_type ) :
    m_state(std::make_shared<typename connection<t_protocol_handler>::shared_state>()),
    m_io_service_local_instance(new worker()),
    io_service_(m_io_service_local_instance->io_service),
    acceptor_(io_service_),
    acceptor_ipv6(io_service_),
    default_remote(),
    m_stop_signal_sent(false), m_port(0), 
    m_threads_count(0),
    m_thread_index(0),
		m_connection_type( connection_type ),
    new_connection_(),
    new_connection_ipv6()
  {
    create_server_type_map();
    m_thread_name_prefix = "NET";
  }

  template<class t_protocol_handler>
  boosted_tcp_server<t_protocol_handler>::boosted_tcp_server(boost::asio::io_service& extarnal_io_service, t_connection_type connection_type) :
    m_state(std::make_shared<typename connection<t_protocol_handler>::shared_state>()),
    io_service_(extarnal_io_service),
    acceptor_(io_service_),
    acceptor_ipv6(io_service_),
    default_remote(),
    m_stop_signal_sent(false), m_port(0),
    m_threads_count(0),
    m_thread_index(0),
		m_connection_type(connection_type),
    new_connection_(),
    new_connection_ipv6()
  {
    create_server_type_map();
    m_thread_name_prefix = "NET";
  }
  //---------------------------------------------------------------------------------
  template<class t_protocol_handler>
  boosted_tcp_server<t_protocol_handler>::~boosted_tcp_server()
  {
    send_stop_signal();
    server_stop();
  }
  //---------------------------------------------------------------------------------
  template<class t_protocol_handler>
  void boosted_tcp_server<t_protocol_handler>::create_server_type_map() 
  {
    server_type_map["NET"] = e_connection_type_NET;
    server_type_map["RPC"] = e_connection_type_RPC;
    server_type_map["P2P"] = e_connection_type_P2P;
  }
  //---------------------------------------------------------------------------------
  template<class t_protocol_handler>
    bool boosted_tcp_server<t_protocol_handler>::init_server(uint32_t port,  const std::string& address,
	uint32_t port_ipv6, const std::string& address_ipv6, bool use_ipv6, bool require_ipv4)
  {
    TRY_ENTRY();
    m_stop_signal_sent = false;
    m_port = port;
    m_port_ipv6 = port_ipv6;
    m_address = address;
    m_address_ipv6 = address_ipv6;
    m_use_ipv6 = use_ipv6;
    m_require_ipv4 = require_ipv4;

    std::string ipv4_failed = "";
    std::string ipv6_failed = "";
    try
    {
      boost::asio::ip::tcp::resolver resolver(io_service_);
      boost::asio::ip::tcp::resolver::query query(address, boost::lexical_cast<std::string>(port), boost::asio::ip::tcp::resolver::query::canonical_name);
      boost::asio::ip::tcp::endpoint endpoint = *resolver.resolve(query);
      acceptor_.open(endpoint.protocol());
#if !defined(_WIN32)
      acceptor_.set_option(boost::asio::ip::tcp::acceptor::reuse_address(true));
#endif
      acceptor_.bind(endpoint);
      acceptor_.listen();
      boost::asio::ip::tcp::endpoint binded_endpoint = acceptor_.local_endpoint();
      m_port = binded_endpoint.port();
      MDEBUG("start accept (IPv4)");
      new_connection_.reset(new connection<t_protocol_handler>(io_service_, m_state, m_connection_type));
      acceptor_.async_accept(new_connection_->socket(),
	boost::bind(&boosted_tcp_server<t_protocol_handler>::handle_accept_ipv4, this,
	boost::asio::placeholders::error));
    }
    catch (const std::exception &e)
    {
      ipv4_failed = e.what();
    }

    if (ipv4_failed != "")
    {
      MERROR("Failed to bind IPv4: " << ipv4_failed);
      if (require_ipv4)
      {
        throw std::runtime_error("Failed to bind IPv4 (set to required)");
      }
    }

    if (use_ipv6)
    {
      try
      {
        if (port_ipv6 == 0) port_ipv6 = port; // default arg means bind to same port as ipv4
        boost::asio::ip::tcp::resolver resolver(io_service_);
        boost::asio::ip::tcp::resolver::query query(address_ipv6, boost::lexical_cast<std::string>(port_ipv6), boost::asio::ip::tcp::resolver::query::canonical_name);
        boost::asio::ip::tcp::endpoint endpoint = *resolver.resolve(query);
        acceptor_ipv6.open(endpoint.protocol());
#if !defined(_WIN32)
        acceptor_ipv6.set_option(boost::asio::ip::tcp::acceptor::reuse_address(true));
#endif
        acceptor_ipv6.set_option(boost::asio::ip::v6_only(true));
        acceptor_ipv6.bind(endpoint);
        acceptor_ipv6.listen();
        boost::asio::ip::tcp::endpoint binded_endpoint = acceptor_ipv6.local_endpoint();
        m_port_ipv6 = binded_endpoint.port();
        MDEBUG("start accept (IPv6)");
        new_connection_ipv6.reset(new connection<t_protocol_handler>(io_service_, m_state, m_connection_type));
        acceptor_ipv6.async_accept(new_connection_ipv6->socket(),
            boost::bind(&boosted_tcp_server<t_protocol_handler>::handle_accept_ipv6, this,
              boost::asio::placeholders::error));
      }
      catch (const std::exception &e)
      {
        ipv6_failed = e.what();
      }
    }

      if (use_ipv6 && ipv6_failed != "")
      {
        MERROR("Failed to bind IPv6: " << ipv6_failed);
        if (ipv4_failed != "")
        {
          throw std::runtime_error("Failed to bind IPv4 and IPv6");
        }
      }

    return true;
    }
    catch (const std::exception &e)
    {
      MFATAL("Error starting server: " << e.what());
      return false;
    }
    catch (...)
    {
      MFATAL("Error starting server");
      return false;
    }
  }
  //-----------------------------------------------------------------------------
PUSH_WARNINGS
DISABLE_GCC_WARNING(maybe-uninitialized)
  template<class t_protocol_handler>
  bool boosted_tcp_server<t_protocol_handler>::init_server(const std::string port,  const std::string& address,
      const std::string port_ipv6, const std::string address_ipv6, bool use_ipv6, bool require_ipv4)
  {
    uint32_t p = 0;
    uint32_t p_ipv6 = 0;

    if (port.size() && !string_tools::get_xtype_from_string(p, port)) {
      MERROR("Failed to convert port no = " << port);
      return false;
    }

    if (port_ipv6.size() && !string_tools::get_xtype_from_string(p_ipv6, port_ipv6)) {
      MERROR("Failed to convert port no = " << port_ipv6);
      return false;
    }
    return this->init_server(p, address, p_ipv6, address_ipv6, use_ipv6, require_ipv4);
  }
POP_WARNINGS
  //---------------------------------------------------------------------------------
  template<class t_protocol_handler>
  bool boosted_tcp_server<t_protocol_handler>::worker_thread()
  {
    TRY_ENTRY();
    uint32_t local_thr_index = m_thread_index++;
    std::string thread_name = std::string("[") + m_thread_name_prefix;
    thread_name += std::to_string(local_thr_index) + "]";
    MLOG_SET_THREAD_NAME(thread_name);
    //   MDEBUG("Thread name: " << m_thread_name_prefix);
    while(!m_stop_signal_sent)
    {
      try
      {
        io_service_.run();
        return true;
      }
      catch(const std::exception& ex)
      {
        MERROR("Exception at server worker thread, what=" << ex.what());
      }
      catch(...)
      {
        MERROR("Exception at server worker thread, unknown execption");
      }
    }
    //MINFO("Worker thread finished");
    return true;
    CATCH_ENTRY_L0("boosted_tcp_server<t_protocol_handler>::worker_thread", false);
  }
  //---------------------------------------------------------------------------------
  template<class t_protocol_handler>
  void boosted_tcp_server<t_protocol_handler>::set_threads_prefix(const std::string& prefix_name)
  {
    m_thread_name_prefix = prefix_name;
		auto it = server_type_map.find(m_thread_name_prefix);
		if (it==server_type_map.end()) throw std::runtime_error("Unknown prefix/server type:" + std::string(prefix_name));
    auto connection_type = it->second; // the value of type
    MINFO("Set server type to: " << connection_type << " from name: " << m_thread_name_prefix << ", prefix_name = " << prefix_name);
  }
  //---------------------------------------------------------------------------------
  template<class t_protocol_handler>
  void boosted_tcp_server<t_protocol_handler>::set_connection_filter(i_connection_filter* pfilter)
  {
    assert(m_state != nullptr); // always set in constructor
    m_state->pfilter = pfilter;
  }
  //---------------------------------------------------------------------------------
  template<class t_protocol_handler>
  bool boosted_tcp_server<t_protocol_handler>::run_server(size_t threads_count, bool wait)
  {
    TRY_ENTRY();
    m_threads_count = threads_count;
    m_main_thread_id = std::this_thread::get_id();
    MLOG_SET_THREAD_NAME("[SRV_MAIN]");
    while(!m_stop_signal_sent)
    {

      // Create a pool of threads to run all of the io_services.
      {
        std::lock_guard lock{m_threads_lock};
        for (std::size_t i = 0; i < threads_count; ++i)
        {
          m_threads.emplace_back([this] { worker_thread(); });
          MDEBUG("Run server thread name: " << m_thread_name_prefix);
        }
      }
      // Wait for all threads in the pool to exit.
      if (wait)
      {
		MDEBUG("JOINING all threads");
        for (auto& th: m_threads)
          th.join();
        MDEBUG("JOINING all threads - almost");
        m_threads.clear();
        MDEBUG("JOINING all threads - DONE");

      } 
      else {
		MDEBUG("Reiniting OK.");
        return true;
      }

      if(wait && !m_stop_signal_sent)
      {
        //some problems with the listening socket ?..
        MDEBUG("Net service stopped without stop request, restarting...");
        if(!this->init_server(m_port, m_address, m_port_ipv6, m_address_ipv6, m_use_ipv6, m_require_ipv4))
        {
          MDEBUG("Reiniting service failed, exit.");
          return false;
        }else
        {
          MDEBUG("Reiniting OK.");
        }
      }
    }
    return true;
    CATCH_ENTRY_L0("boosted_tcp_server<t_protocol_handler>::run_server", false);
  }
  //---------------------------------------------------------------------------------
  template<class t_protocol_handler>
  bool boosted_tcp_server<t_protocol_handler>::is_thread_worker()
  {
    TRY_ENTRY();
    std::lock_guard lock{m_threads_lock};
    for (auto& th : m_threads)
      if(th.get_id() == std::this_thread::get_id())
        return true;
    if(m_threads_count == 1 && std::this_thread::get_id() == m_main_thread_id)
      return true;
    return false;
    CATCH_ENTRY_L0("boosted_tcp_server<t_protocol_handler>::is_thread_worker", false);
  }
  //---------------------------------------------------------------------------------
  template<class t_protocol_handler>
  bool boosted_tcp_server<t_protocol_handler>::server_stop()
  {
    TRY_ENTRY();
    for (auto& th : m_threads)
      if (th.joinable())
        th.join();
    return true;
    CATCH_ENTRY_L0("boosted_tcp_server<t_protocol_handler>::server_stop", false);
  }
  //---------------------------------------------------------------------------------
  template<class t_protocol_handler>
  void boosted_tcp_server<t_protocol_handler>::send_stop_signal()
  {
    m_stop_signal_sent = true;
    typename connection<t_protocol_handler>::shared_state *state = static_cast<typename connection<t_protocol_handler>::shared_state*>(m_state.get());
    state->stop_signal_sent = true;
    TRY_ENTRY();
    connections_mutex.lock();
    for (auto &c: connections_)
    {
      c->cancel();
    }
    connections_.clear();
    connections_mutex.unlock();
    io_service_.stop();
    CATCH_ENTRY_L0("boosted_tcp_server<t_protocol_handler>::send_stop_signal()", void());
  }
  //---------------------------------------------------------------------------------
  template<class t_protocol_handler>
  void boosted_tcp_server<t_protocol_handler>::handle_accept_ipv4(const boost::system::error_code& e)
  {
    this->handle_accept(e, false);
  }
  //---------------------------------------------------------------------------------
  template<class t_protocol_handler>
  void boosted_tcp_server<t_protocol_handler>::handle_accept_ipv6(const boost::system::error_code& e)
  {
    this->handle_accept(e, true);
  }
  //---------------------------------------------------------------------------------
  template<class t_protocol_handler>
  void boosted_tcp_server<t_protocol_handler>::handle_accept(const boost::system::error_code& e, bool ipv6)
  {
    MDEBUG("handle_accept");

    boost::asio::ip::tcp::acceptor* current_acceptor = &acceptor_;
    connection_ptr* current_new_connection = &new_connection_;
    auto accept_function_pointer = &boosted_tcp_server<t_protocol_handler>::handle_accept_ipv4;
    if (ipv6)
    {
      current_acceptor = &acceptor_ipv6;
      current_new_connection = &new_connection_ipv6;
      accept_function_pointer = &boosted_tcp_server<t_protocol_handler>::handle_accept_ipv6;
    }

    try
    {
    if (!e)
    {
      if (m_connection_type == e_connection_type_RPC) {
        MDEBUG("New server for RPC connections");
        (*current_new_connection)->setRpcStation(); // hopefully this is not needed actually
      }
      connection_ptr conn(std::move((*current_new_connection)));
      (*current_new_connection).reset(new connection<t_protocol_handler>(io_service_, m_state, m_connection_type));
      current_acceptor->async_accept((*current_new_connection)->socket(),
          boost::bind(accept_function_pointer, this,
            boost::asio::placeholders::error));

      boost::asio::socket_base::keep_alive opt(true);
      conn->socket().set_option(opt);

      bool res;
      if (default_remote.get_type_id() == net_utils::address_type::invalid)
        res = conn->start(true, 1 < m_threads_count);
      else
        res = conn->start(true, 1 < m_threads_count, default_remote);
      if (!res)
      {
        conn->cancel();
        return;
      }
      conn->save_dbg_log();
      return;
    }
    else
    {
      MERROR("Error in boosted_tcp_server<t_protocol_handler>::handle_accept: " << e);
    }
    }
    catch (const std::exception &e)
    {
      MERROR("Exception in boosted_tcp_server<t_protocol_handler>::handle_accept: " << e.what());
    }

    // error path, if e or exception
    assert(m_state != nullptr); // always set in constructor
    MERROR("Some problems at accept: " << e.message() << ", connections_count = " << m_state->sock_count);
    misc_utils::sleep_no_w(100);
    (*current_new_connection).reset(new connection<t_protocol_handler>(io_service_, m_state, m_connection_type));
    current_acceptor->async_accept((*current_new_connection)->socket(),
        boost::bind(accept_function_pointer, this,
          boost::asio::placeholders::error));
  }
  //---------------------------------------------------------------------------------
  template<class t_protocol_handler>
  bool boosted_tcp_server<t_protocol_handler>::add_connection(t_connection_context& out, boost::asio::ip::tcp::socket&& sock, network_address real_remote)
  {
    if(std::addressof(get_io_service()) == std::addressof(GET_IO_SERVICE(sock)))
    {
      connection_ptr conn(new connection<t_protocol_handler>(std::move(sock), m_state, m_connection_type));
      if(conn->start(false, 1 < m_threads_count, std::move(real_remote)))
      {
        conn->get_context(out);
        conn->save_dbg_log();
        return true;
      }
    }
    else
    {
	MWARNING(out << " was not added, socket/io_service mismatch");
    }
    return false;
  }
  //---------------------------------------------------------------------------------
  template<class t_protocol_handler>
  typename boosted_tcp_server<t_protocol_handler>::try_connect_result_t boosted_tcp_server<t_protocol_handler>::try_connect(connection_ptr new_connection_l, const std::string& adr, const std::string& port, boost::asio::ip::tcp::socket &sock_, const boost::asio::ip::tcp::endpoint &remote_endpoint, const std::string &bind_ip, uint32_t conn_timeout)
  {
    TRY_ENTRY();

    sock_.open(remote_endpoint.protocol());
    if(bind_ip != "0.0.0.0" && bind_ip != "0" && bind_ip != "" )
    {
      boost::asio::ip::tcp::endpoint local_endpoint(boost::asio::ip::address::from_string(bind_ip.c_str()), 0);
      boost::system::error_code ec;
      sock_.bind(local_endpoint, ec);
      if (ec)
      {
        MERROR("Error binding to " << bind_ip << ": " << ec.message());
        if (sock_.is_open())
          sock_.close();
        return CONNECT_FAILURE;
      }
    }

    /*
    NOTICE: be careful to make sync connection from event handler: in case if all threads suddenly do sync connect, there will be no thread to dispatch events from io service.
    */

    boost::system::error_code ec = boost::asio::error::would_block;

    //have another free thread(s), work in wait mode, without event handling
    struct local_async_context
    {
      boost::system::error_code ec;
      std::mutex connect_mut;
      std::condition_variable cond;
    };

    std::shared_ptr<local_async_context> local_shared_context(new local_async_context());
    local_shared_context->ec = boost::asio::error::would_block;
    std::unique_lock lock{local_shared_context->connect_mut};
    auto connect_callback = [](boost::system::error_code ec_, std::shared_ptr<local_async_context> shared_context)
    {
      shared_context->connect_mut.lock(); shared_context->ec = ec_; shared_context->cond.notify_one(); shared_context->connect_mut.unlock();
    };

    using namespace boost::placeholders;
    sock_.async_connect(remote_endpoint, boost::bind<void>(connect_callback, _1, local_shared_context));
    while(local_shared_context->ec == boost::asio::error::would_block)
    {
      auto wait_stat = local_shared_context->cond.wait_for(lock, std::chrono::milliseconds{conn_timeout});
      if (m_stop_signal_sent)
      {
        if (sock_.is_open())
          sock_.close();
        return CONNECT_FAILURE;
      }
      if(local_shared_context->ec == boost::asio::error::would_block && wait_stat == std::cv_status::timeout)
      {
        //timeout
        sock_.close();
        MTRACE("Failed to connect to " << adr << ":" << port << ", because of timeout (" << conn_timeout << ")");
        return CONNECT_FAILURE;
      }
    }
    ec = local_shared_context->ec;

    if (ec || !sock_.is_open())
    {
      MTRACE("Some problems at connect, message: " << ec.message());
      if (sock_.is_open())
        sock_.close();
      return CONNECT_FAILURE;
    }

    MTRACE("Connected success to " << adr << ':' << port);

    return CONNECT_SUCCESS;

    CATCH_ENTRY_L0("boosted_tcp_server<t_protocol_handler>::try_connect", CONNECT_FAILURE);
  }
  //---------------------------------------------------------------------------------
  template<class t_protocol_handler>
  bool boosted_tcp_server<t_protocol_handler>::connect(const std::string& adr, const std::string& port, uint32_t conn_timeout, t_connection_context& conn_context, const std::string& bind_ip)
  {
    TRY_ENTRY();

    connection_ptr new_connection_l(new connection<t_protocol_handler>(io_service_, m_state, m_connection_type) );
    connections_mutex.lock();
    connections_.insert(new_connection_l);
    MDEBUG("connections_ size now " << connections_.size());
    connections_mutex.unlock();
    epee::misc_utils::auto_scope_leave_caller scope_exit_handler = epee::misc_utils::create_scope_leave_handler([&](){ std::lock_guard lock{connections_mutex}; connections_.erase(new_connection_l); });
    boost::asio::ip::tcp::socket&  sock_ = new_connection_l->socket();

    bool try_ipv6 = false;

    boost::asio::ip::tcp::resolver resolver(io_service_);
    boost::asio::ip::tcp::resolver::query query(boost::asio::ip::tcp::v4(), adr, port, boost::asio::ip::tcp::resolver::query::canonical_name);
    boost::system::error_code resolve_error;
    boost::asio::ip::tcp::resolver::iterator iterator;
    try
    {
      //resolving ipv4 address as ipv6 throws, catch here and move on
      iterator = resolver.resolve(query, resolve_error);
    }
    catch (const boost::system::system_error& e)
    {
      if (!m_use_ipv6 || (resolve_error != boost::asio::error::host_not_found &&
            resolve_error != boost::asio::error::host_not_found_try_again))
      {
        throw;
      }
      try_ipv6 = true;
    }
    catch (...)
    {
      throw;
    }

    std::string bind_ip_to_use;

    boost::asio::ip::tcp::resolver::iterator end;
    if(iterator == end)
    {
      if (!m_use_ipv6)
      {
        MERROR("Failed to resolve " << adr);
        return false;
      }
      else
      {
        try_ipv6 = true;
        MINFO("Resolving address as IPv4 failed, trying IPv6");
      }
    }
    else
    {
      bind_ip_to_use = bind_ip;
    }

    if (try_ipv6)
    {
      boost::asio::ip::tcp::resolver::query query6(boost::asio::ip::tcp::v6(), adr, port, boost::asio::ip::tcp::resolver::query::canonical_name);

      iterator = resolver.resolve(query6, resolve_error);

      if(iterator == end)
      {
        MERROR("Failed to resolve " << adr);
        return false;
      }
      else
      {
        if (bind_ip == "0.0.0.0")
        {
          bind_ip_to_use = "::";
        }
        else
        {
          bind_ip_to_use = "";
        }

      }

    }

    MDEBUG("Trying to connect to " << adr << ":" << port << ", bind_ip = " << bind_ip_to_use);

    //boost::asio::ip::tcp::endpoint remote_endpoint(boost::asio::ip::address::from_string(addr.c_str()), port);
    boost::asio::ip::tcp::endpoint remote_endpoint(*iterator);

    auto try_connect_result = try_connect(new_connection_l, adr, port, sock_, remote_endpoint, bind_ip_to_use, conn_timeout);
    if (try_connect_result == CONNECT_FAILURE)
      return false;

    // start adds the connection to the config object's list, so we don't need to have it locally anymore
    connections_mutex.lock();
    connections_.erase(new_connection_l);
    connections_mutex.unlock();
    bool r = new_connection_l->start(false, 1 < m_threads_count);
    if (r)
    {
      new_connection_l->get_context(conn_context);
      //new_connection_l.reset(new connection<t_protocol_handler>(io_service_, m_config, m_sock_count, m_pfilter));
    }
    else
    {
      assert(m_state != nullptr); // always set in constructor
      MERROR("[sock " << new_connection_l->socket().native_handle() << "] Failed to start connection, connections_count = " << m_state->sock_count);
    }
    
	new_connection_l->save_dbg_log();

    return r;

    CATCH_ENTRY_L0("boosted_tcp_server<t_protocol_handler>::connect", false);
  }
  //---------------------------------------------------------------------------------
  template<class t_protocol_handler> template<class t_callback>
  bool boosted_tcp_server<t_protocol_handler>::connect_async(const std::string& adr, const std::string& port, uint32_t conn_timeout, const t_callback &cb, const std::string& bind_ip)
  {
    TRY_ENTRY();    
    connection_ptr new_connection_l(new connection<t_protocol_handler>(io_service_, m_state, m_connection_type) );
    connections_mutex.lock();
    connections_.insert(new_connection_l);
    MDEBUG("connections_ size now " << connections_.size());
    connections_mutex.unlock();
    epee::misc_utils::auto_scope_leave_caller scope_exit_handler = epee::misc_utils::create_scope_leave_handler([&](){ std::lock_guard lock{connections_mutex}; connections_.erase(new_connection_l); });
    boost::asio::ip::tcp::socket&  sock_ = new_connection_l->socket();
    
    bool try_ipv6 = false;

    boost::asio::ip::tcp::resolver resolver(io_service_);
    boost::asio::ip::tcp::resolver::query query(boost::asio::ip::tcp::v4(), adr, port, boost::asio::ip::tcp::resolver::query::canonical_name);
    boost::system::error_code resolve_error;
    boost::asio::ip::tcp::resolver::iterator iterator;
    try
    {
      //resolving ipv4 address as ipv6 throws, catch here and move on
      iterator = resolver.resolve(query, resolve_error);
    }
    catch (const boost::system::system_error& e)
    {
      if (!m_use_ipv6 || (resolve_error != boost::asio::error::host_not_found &&
            resolve_error != boost::asio::error::host_not_found_try_again))
      {
        throw;
      }
      try_ipv6 = true;
    }
    catch (...)
    {
      throw;
    }

    boost::asio::ip::tcp::resolver::iterator end;

    if(iterator == end)
    {
      if (!try_ipv6)
      {
        MERROR("Failed to resolve " << adr);
        return false;
      }
      else
      {
        MINFO("Resolving address as IPv4 failed, trying IPv6");
      }
    }

    if (try_ipv6)
    {
      boost::asio::ip::tcp::resolver::query query6(boost::asio::ip::tcp::v6(), adr, port, boost::asio::ip::tcp::resolver::query::canonical_name);

      iterator = resolver.resolve(query6, resolve_error);

      if(iterator == end)
      {
        MERROR("Failed to resolve " << adr);
        return false;
      }
    }


    boost::asio::ip::tcp::endpoint remote_endpoint(*iterator);
     
    sock_.open(remote_endpoint.protocol());
    if(bind_ip != "0.0.0.0" && bind_ip != "0" && bind_ip != "" )
    {
      boost::asio::ip::tcp::endpoint local_endpoint(boost::asio::ip::address::from_string(bind_ip.c_str()), 0);
      boost::system::error_code ec;
      sock_.bind(local_endpoint, ec);
      if (ec)
      {
        MERROR("Error binding to " << bind_ip << ": " << ec.message());
        if (sock_.is_open())
          sock_.close();
        return false;
      }
    }
    
    std::shared_ptr<boost::asio::steady_timer> sh_deadline(new boost::asio::steady_timer(io_service_));
    //start deadline
    sh_deadline->expires_from_now(std::chrono::milliseconds(conn_timeout));
    sh_deadline->async_wait([=](const boost::system::error_code& error)
      {
          if(error != boost::asio::error::operation_aborted) 
          {
            MTRACE("Failed to connect to " << adr << ':' << port << ", because of timeout (" << conn_timeout << ")");
            new_connection_l->socket().close();
          }
      });
    //start async connect
    sock_.async_connect(remote_endpoint, [=](const boost::system::error_code& ec_)
      {
        t_connection_context conn_context{};
        boost::system::error_code ignored_ec;
        boost::asio::ip::tcp::socket::endpoint_type lep = new_connection_l->socket().local_endpoint(ignored_ec);
        if(!ec_)
        {//success
          if(!sh_deadline->cancel())
          {
            cb(conn_context, boost::asio::error::operation_aborted);//this mean that deadline timer already queued callback with cancel operation, rare situation
          }else
          {
            MTRACE("[sock " << new_connection_l->socket().native_handle() << "] Connected success to " << adr << ':' << port <<
              " from " << lep.address().to_string() << ':' << lep.port());

            // start adds the connection to the config object's list, so we don't need to have it locally anymore
            connections_mutex.lock();
            connections_.erase(new_connection_l);
            connections_mutex.unlock();
            bool r = new_connection_l->start(false, 1 < m_threads_count);
            if (r)
            {
              new_connection_l->get_context(conn_context);
              cb(conn_context, ec_);
            }
            else
            {
              MTRACE("[sock " << new_connection_l->socket().native_handle() << "] Failed to start connection to " << adr << ':' << port);
              cb(conn_context, boost::asio::error::fault);
            }
          }
        }else
        {
          MTRACE("[sock " << new_connection_l->socket().native_handle() << "] Failed to connect to " << adr << ':' << port <<
            " from " << lep.address().to_string() << ':' << lep.port() << ": " << ec_.message() << ':' << ec_.value());
          cb(conn_context, ec_);
        }
      });
    return true;
    CATCH_ENTRY_L0("boosted_tcp_server<t_protocol_handler>::connect_async", false);
  }
  
} // namespace
} // namespace
PRAGMA_WARNING_POP
