#pragma once

#include <cryptonote_basic/cryptonote_basic.h>
#include "address.hpp"
#include "db.hpp"
#include "output.hpp"

#include <vector>
#include <string>

namespace wallet
{
  struct version {}; // XXX: placeholder type

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
