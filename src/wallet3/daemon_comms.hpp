#pragma once

#include "block.hpp"
#include "decoy.hpp"

#include <functional>

namespace wallet
{

  // should capture weak pointer to objects in callbacks so those objects can
  // be deallocated even if there are outstanding requests
  class DaemonComms
  {
  public:

    virtual void GetHeight(std::function<void(uint64_t height)> cb) = 0;

    virtual void GetBlocks(uint64_t start_height, uint64_t end_height, std::function<void(std::vector<Block>)> cb) = 0;
    void GetBlock(uint64_t height, std::function<void(std::vector<Block>)> cb) { GetBlocks(height, height, cb); }

    virtual void SetNewBlockCallback(std::function<void(Block)> cb) = 0;

    virtual void GetDecoyOutputs( /*TODO: args */ std::function<void(std::vector<Decoy>)> cb);

    virtual void SubmitTransaction(PendingTransaction tx, std::function<void(bool success)> cb) = 0;
  };

} // namespace wallet
