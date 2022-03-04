#pragma once

#include <wallet3/decoy_selection/decoy_selection.hpp>

namespace wallet
{
  class MockDecoySelector: public DecoySelector
  {

  public:
    MockDecoySelector() : DecoySelector(0,0) {}

    std::vector<int64_t> predetermined_indexes;
    int64_t last_index = 0;

    virtual std::vector<int64_t>
    operator()(const Output& selected_output) override
    {
      const size_t n_decoys = 10;
      std::vector<int64_t> decoy_indexes;
      for (size_t i = 0; i < n_decoys; ++i)
      {
        decoy_indexes.push_back(predetermined_indexes[last_index]);
        if (last_index + 1 == static_cast<int64_t>(predetermined_indexes.size()))
          last_index = 0;
        else
          last_index++;
      }
      return decoy_indexes;
    }

    void
    add_index(const std::vector<int64_t>& indices)
    {
      predetermined_indexes.insert(predetermined_indexes.end(), indices.begin(), indices.end());
    }

  };
}  // namespace wallet
