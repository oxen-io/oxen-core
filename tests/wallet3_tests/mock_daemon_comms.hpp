#pragma once

#include <wallet3/default_daemon_comms.hpp>

namespace wallet
{

class MockDaemonComms: public DefaultDaemonComms
{
  public:

    MockDaemonComms() : DefaultDaemonComms(get_omq()){};

    std::vector<Decoy> predetermined_decoys;

    std::shared_ptr<oxenmq::OxenMQ> get_omq() {
      return std::make_shared<oxenmq::OxenMQ>();
    }

    std::future<std::vector<Decoy>>
    fetch_decoys(const std::vector<int64_t>& indexes) override {
      auto p = std::promise<std::vector<Decoy>>();
      auto fut = p.get_future();

      std::vector<Decoy> returned_decoys;
      for (auto index : indexes)
      {
        auto it = std::find_if(predetermined_decoys.begin(), predetermined_decoys.end(), [index](const auto& decoy) { return decoy.global_index == index; });
        if (it != predetermined_decoys.end())
          returned_decoys.push_back(*it);
        else
          returned_decoys.push_back(Decoy{0, "","","",true, index});
      }

      p.set_value(returned_decoys);
      return fut;
    }

    void
    add_decoy(uint64_t global_index, std::string_view public_key, std::string_view mask)
    {
      predetermined_decoys.push_back(wallet::Decoy{});
      wallet::Decoy& decoy = predetermined_decoys.back();
      tools::hex_to_type(public_key, decoy.key);
      tools::hex_to_type(mask, decoy.mask);
      decoy.global_index = global_index;
    }

};


} // namespace wallet
