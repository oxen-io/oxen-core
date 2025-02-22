#pragma once

#include <vector>

#include "../output.hpp"

namespace wallet {
// OutputSelector will choose some a subset of outputs from the provided list of outputs according
// to the output selection algorithm. The sum of the amounts in the returned outputs will be
// greater than the amount passed as the second parameter.

class OutputSelector {
  public:
    std::vector<Output> operator()(
            const std::vector<Output>& available_outputs, int64_t amount) const;

    void push_fee(int64_t input_count, int64_t fee) { fee_map[input_count] = fee; };

    void clear_fees() { fee_map.clear(); };

  private:
    // Keeps track of the fees that need to be paid on top of the amount passed in
    // key represents the number of outputs and value represents the fee that needs
    // to be included if that many outputs are chosen
    std::map<int64_t, int64_t> fee_map;
};
}  // namespace wallet
