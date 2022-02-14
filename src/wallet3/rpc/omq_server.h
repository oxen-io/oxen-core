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

  OmqServer(std::shared_ptr<oxenmq::OxenMQ> omq, RequestHandler& request_handler);
};




} // namespace wallet::rpc
