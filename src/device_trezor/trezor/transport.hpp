// Copyright (c) 2017-2019, The Monero Project
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

#ifndef MONERO_TRANSPORT_H
#define MONERO_TRANSPORT_H


#include <boost/asio.hpp>
#include <boost/asio/steady_timer.hpp>

#include <string_view>
#include <type_traits>
#include <chrono>

#include <cpr/session.h>

#include "wipeable_string.h"
#include "misc_log_ex.h"

#include "rapidjson/document.h"
#include "rapidjson/writer.h"
#include "rapidjson/stringbuffer.h"

#include "exceptions.hpp"
#include "trezor_defs.hpp"
#include "messages_map.hpp"

#include "common/loki.h"

#include "messages/messages.pb.h"
#include "messages/messages-common.pb.h"
#include "messages/messages-management.pb.h"
#include "messages/messages-monero.pb.h"

namespace hw {
namespace trezor {
  using namespace std::literals;

  using json = rapidjson::Document;
  using json_val = rapidjson::Value;

  constexpr const char* DEFAULT_BRIDGE = "http://127.0.0.1:21325";
  constexpr std::chrono::milliseconds HTTP_TIMEOUT = 180s;

  uint64_t pack_version(uint32_t major, uint32_t minor=0, uint32_t patch=0);

  // Base HTTP comm serialization.
  bool t_serialize(const std::string & in, std::string & out);
  bool t_serialize(const epee::wipeable_string & in, std::string & out);
  bool t_serialize(const json_val & in, std::string & out);
  std::string t_serialize(const json_val & in);

  bool t_deserialize(const std::string & in, std::string & out);
  bool t_deserialize(std::string & in, epee::wipeable_string & out);
  bool t_deserialize(const std::string & in, json & out);

  // Forward decl
  class Transport;
  class Protocol;

  // Communication protocol
  class Protocol {
  public:
    Protocol() = default;
    virtual ~Protocol() = default;
    virtual void session_begin(Transport & transport){ };
    virtual void session_end(Transport & transport){ };
    virtual void write(Transport & transport, const google::protobuf::Message & req)= 0;
    virtual void read(Transport & transport, std::shared_ptr<google::protobuf::Message> & msg, messages::MessageType * msg_type=nullptr)= 0;
  };

  class ProtocolV1 : public Protocol {
  public:
    ProtocolV1() = default;
    virtual ~ProtocolV1() = default;

    void write(Transport & transport, const google::protobuf::Message & req) override;
    void read(Transport & transport, std::shared_ptr<google::protobuf::Message> & msg, messages::MessageType * msg_type=nullptr) override;
  };


  // Base transport
  typedef std::vector<std::shared_ptr<Transport>> t_transport_vect;

  class Transport {
  public:
    Transport();
    virtual ~Transport() = default;

    virtual bool ping() { return false; };
    virtual std::string get_path() const { return ""; };
    virtual void enumerate(t_transport_vect & res){};
    virtual void open(){};
    virtual void close(){};
    virtual void write(const google::protobuf::Message & req) =0;
    virtual void read(std::shared_ptr<google::protobuf::Message> & msg, messages::MessageType * msg_type=nullptr) =0;
    virtual std::shared_ptr<Transport> find_debug() { return nullptr; };

    virtual void write_chunk(const void * buff, size_t size) { };
    virtual size_t read_chunk(void * buff, size_t size) { return 0; };
    virtual std::ostream& dump(std::ostream& o) const { return o << "Transport<>"; }
  protected:
    long m_open_counter;

    virtual bool pre_open();
    virtual bool pre_close();
  };

  // Bridge transport
  class BridgeTransport : public Transport {
  public:
    BridgeTransport(
        std::optional<std::string> device_path = std::nullopt,
        std::optional<std::string> bridge_host = std::nullopt);

    virtual ~BridgeTransport() = default;

    static const char * PATH_PREFIX;

    std::string get_path() const override;
    void enumerate(t_transport_vect & res) override;

    void open() override;
    void close() override;

    void write(const google::protobuf::Message &req) override;
    void read(std::shared_ptr<google::protobuf::Message> & msg, messages::MessageType * msg_type=nullptr) override;

    const std::optional<json> & device_info() const;
    std::ostream& dump(std::ostream& o) const override;

    // posts a json request with the given body to the bridge.  Returns the body on success, throws
    // on error.
    std::string post_json(std::string_view uri, std::string json);

    // Flexible json serialization. HTTP client tailored for bridge API
    template<class t_req, class t_res>
    bool invoke_bridge_http(std::string_view uri, const t_req & request, t_res & result)
    {
      std::string req;
      t_serialize(request, req);

      std::string res;
      LOKI_DEFER { if (!res.empty()) memwipe(res.data(), res.size()); };

      try {
        res = post_json(uri, std::move(req));
      } catch (const std::exception& e) {
        MERROR(e.what() << " while requesting " << uri);
      }

      return t_deserialize(res, result);
    }

  private:
    cpr::Session m_http_session;
    std::string m_bridge_url;
    std::optional<std::string> m_device_path;
    std::optional<std::string> m_session;
    std::optional<epee::wipeable_string> m_response;
    std::optional<json> m_device_info;
  };

  // UdpTransport transport
  using boost::asio::ip::udp;

  class UdpTransport : public Transport {
  public:

    explicit UdpTransport(
        std::optional<std::string> device_path=std::nullopt,
        std::optional<std::shared_ptr<Protocol>> proto=std::nullopt);

    virtual ~UdpTransport() = default;

    static constexpr const char* PATH_PREFIX = "udp:";
    static constexpr const char* DEFAULT_HOST = "127.0.0.1";
    static constexpr int DEFAULT_PORT = 21324;

    bool ping() override;
    std::string get_path() const override;
    void enumerate(t_transport_vect & res) override;

    void open() override;
    void close() override;
    std::shared_ptr<Transport> find_debug() override;

    void write(const google::protobuf::Message &req) override;
    void read(std::shared_ptr<google::protobuf::Message> & msg, messages::MessageType * msg_type=nullptr) override;

    void write_chunk(const void * buff, size_t size) override;
    size_t read_chunk(void * buff, size_t size) override;

    std::ostream& dump(std::ostream& o) const override;

  private:
    void require_socket();
    ssize_t receive(void * buff, size_t size, boost::system::error_code * error_code=nullptr, bool no_throw=false, std::chrono::milliseconds timeout = 10s);
    void check_deadline();
    bool ping_int(std::chrono::milliseconds timeout = 1500ms);

    std::shared_ptr<Protocol> m_proto;
    std::string m_device_host;
    int m_device_port;

    std::unique_ptr<udp::socket> m_socket;
    boost::asio::io_service m_io_service;
    boost::asio::steady_timer m_deadline;
    udp::endpoint m_endpoint;
  };

#ifdef WITH_DEVICE_TREZOR_WEBUSB
#include <libusb.h>

  class WebUsbTransport : public Transport {
  public:

    explicit WebUsbTransport(
        std::optional<libusb_device_descriptor*> descriptor = std::nullopt,
        std::optional<std::shared_ptr<Protocol>> proto = std::nullopt
    );

    virtual ~WebUsbTransport();

    static const char * PATH_PREFIX;

    std::string get_path() const override;
    void enumerate(t_transport_vect & res) override;

    void open() override;
    void close() override;
    std::shared_ptr<Transport> find_debug() override;

    void write(const google::protobuf::Message &req) override;
    void read(std::shared_ptr<google::protobuf::Message> & msg, messages::MessageType * msg_type=nullptr) override;

    void write_chunk(const void * buff, size_t size) override;
    size_t read_chunk(void * buff, size_t size) override;

    std::ostream& dump(std::ostream& o) const override;

  private:
    void require_device() const;
    void require_connected() const;
    int get_interface() const;
    unsigned char get_endpoint() const;

    std::shared_ptr<Protocol> m_proto;

    libusb_context        *m_usb_session;
    libusb_device         *m_usb_device;
    libusb_device_handle  *m_usb_device_handle;
    std::unique_ptr<libusb_device_descriptor> m_usb_device_desc;
    std::vector<uint8_t> m_port_numbers;
    int m_bus_id;
    int m_device_addr;

#ifdef WITH_TREZOR_DEBUGGING
    bool m_debug_mode;
#endif
  };

#endif

  //
  // General helpers
  //

  /**
   * Enumerates all transports
   */
  void enumerate(t_transport_vect & res);

  /**
   * Sorts found transports by TREZOR_PATH environment variable.
   */
  void sort_transports_by_env(t_transport_vect & res);

  /**
   * Transforms path to the transport
   */
  std::shared_ptr<Transport> transport(const std::string & path);

  /**
   * Transforms path to the particular transport
   */
  template<class t_transport=Transport>
  std::shared_ptr<t_transport> transport_typed(const std::string & path){
    auto t = transport(path);
    if (!t){
      return nullptr;
    }

    return std::dynamic_pointer_cast<t_transport>(t);
  }

  // Exception carries unexpected message being received
  namespace exc {
    class UnexpectedMessageException: public ProtocolException {
    protected:
      hw::trezor::messages::MessageType recvType;
      std::shared_ptr<google::protobuf::Message> recvMsg;

    public:
      using ProtocolException::ProtocolException;
      UnexpectedMessageException(): ProtocolException("Trezor returned unexpected message") {};
      UnexpectedMessageException(hw::trezor::messages::MessageType recvType,
                                 const std::shared_ptr<google::protobuf::Message> & recvMsg)
          : recvType(recvType), recvMsg(recvMsg) {
        reason = std::string("Trezor returned unexpected message: ") + std::to_string(recvType);
      }
    };
  }

  /**
   * Throws corresponding failure exception.
   */
  [[ noreturn ]] void throw_failure_exception(const messages::common::Failure * failure);

  /**
   * Generic message holder, type + obj
   */
  class GenericMessage {
  public:
    GenericMessage(): m_empty(true) {}
    GenericMessage(messages::MessageType m_type, const std::shared_ptr<google::protobuf::Message> &m_msg);
    bool empty() const { return m_empty; }

    hw::trezor::messages::MessageType m_type;
    std::shared_ptr<google::protobuf::Message> m_msg;
    bool m_empty;
  };

  /**
   * Simple wrapper for write-read message exchange with expected message response type.
   *
   * @throws UnexpectedMessageException if the response message type is different than expected.
   * Exception contains message type and the message itself.
   */
  template<class t_message=google::protobuf::Message>
  std::shared_ptr<t_message>
      exchange_message(Transport & transport, const google::protobuf::Message & req,
                       std::optional<messages::MessageType> resp_type = std::nullopt)
  {
    // Require strictly protocol buffers response in the template.
    static_assert(std::is_base_of_v<google::protobuf::Message, t_message>);

    // Write the request
    transport.write(req);

    // Read the response
    std::shared_ptr<google::protobuf::Message> msg_resp;
    hw::trezor::messages::MessageType msg_resp_type;
    transport.read(msg_resp, &msg_resp_type);

    // Determine type of expected message response
    messages::MessageType required_type = resp_type ? *resp_type : MessageMapper::get_message_wire_number<t_message>();

    if (msg_resp_type == required_type) {
      return message_ptr_retype<t_message>(msg_resp);
    } else if (msg_resp_type == messages::MessageType_Failure){
      throw_failure_exception(dynamic_cast<messages::common::Failure*>(msg_resp.get()));
    } else {
      throw exc::UnexpectedMessageException(msg_resp_type, msg_resp);
    }
  }

  std::ostream& operator<<(std::ostream& o, hw::trezor::Transport const& t);
  std::ostream& operator<<(std::ostream& o, std::shared_ptr<hw::trezor::Transport> const& t);
}}


#endif //MONERO_TRANSPORT_H
