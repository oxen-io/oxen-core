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

    std::pair<int64_t, int64_t>
    get_fee_parameters() override { 
      return std::make_pair(0,0);
    }

    std::future<std::vector<Decoy>>
    fetch_decoys(const std::vector<int64_t>& indexes) override {
      auto p = std::promise<std::vector<Decoy>>();
      auto fut = p.get_future();

      std::vector<Decoy> returned_decoys;
      for (auto index : indexes)
      {
        //std::cout << __FILE__ << ":" << __LINE__ << " (" << __func__ << ") TODO sean remove this - index: " << index << " - debug\n";
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
    add_decoy(std::string_view public_key, uint64_t global_index)
    {
      wallet::Decoy decoy{};
      tools::hex_to_type(public_key, decoy.key);
      decoy.global_index = global_index;
    }

};


} // namespace wallet
