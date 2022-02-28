#pragma once

#include <memory>

namespace oxenmq { class OxenMQ; }

namespace wallet::rpc
{

class RequestHandler;

class OmqServer
{
  std::shared_ptr<oxenmq::OxenMQ> omq;
  RequestHandler& request_handler;

public:

  OmqServer(RequestHandler& request_handler) :
    omq(nullptr), request_handler(request_handler)
  {}

  void
  set_omq(std::shared_ptr<oxenmq::OxenMQ> omq);
};




} // namespace wallet::rpc
