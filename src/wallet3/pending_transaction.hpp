#pragma once

#include "db.hpp"

#include <vector>
#include <string>

namespace wallet
{

  struct address; // XXX: placeholder type
  struct verison; // XXX: placeholder type

  struct PendingTransaction
  {
    version txVersion;

    std::vector<std::pair<address, uint64_t> > recipients; // does not include change

    std::pair<address, uint64_t> change;

    std::string memo;

    cryptonote::transaction tx;

    std::vector<Output> chosenOutputs;
  };

} // namespace wallet
