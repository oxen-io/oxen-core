#pragma once

#include <ethyl/provider.hpp>
#include <memory>
#include <string>
#include <vector>

struct RewardRateResponse {
    uint64_t timestamp;
    uint64_t reward;
};

class PoolContract {
  public:
    PoolContract(std::string _contractAddress, ethyl::Provider& _provider);
    RewardRateResponse RewardRate(uint64_t timestamp, uint64_t ethereum_block_height);

  private:
    std::string contractAddress;
    ethyl::Provider& provider;
};
