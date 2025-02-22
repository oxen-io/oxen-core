#pragma once

#include <vector>

#include "../decoy.hpp"
#include "../output.hpp"

namespace wallet {
// DecoySelector will choose some a subset of outputs from the provided list of outputs according
// to the decoy selection algorithm. The decoys selected should hide the selected output within a
// ring signature and requires careful selection to avoid privacy decreasing analysis

class DecoySelector {
  public:
    virtual std::vector<int64_t> operator()(const Output& selected_output);

    DecoySelector(int64_t min, int64_t max) : min_output_index(min), max_output_index(max){};

    int64_t min_output_index = 0;
    int64_t max_output_index = 0;
};
}  // namespace wallet
