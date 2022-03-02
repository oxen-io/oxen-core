#include "decoy_selection.hpp"

namespace wallet
{
  std::vector<int64_t>
  DecoySelector::operator()(const Output& selected_output)
  {
    const size_t n_decoys = 13;

    // Select some random outputs according to gamma distribution
    std::random_device rd;
    std::default_random_engine rng(rd());

    constexpr int ALPHA = 1;
    constexpr int BETA = 2;
    std::gamma_distribution<double> distribution{ALPHA, BETA};

    std::vector<int64_t> decoy_indexes;
    for (size_t i = 0; i < n_decoys; ++i)
    {
      int64_t output_height_from_distribution = max_output_index - std::round(distribution(rng) * (max_output_index - min_output_index)/10);
      decoy_indexes.push_back(output_height_from_distribution);
    }

    // TODO(sean): uncomment this line and figure out how to remove the real index
    // We need to request the chosen output to ensure the daemon cant guess which output is real by elimination
    //decoy_indexes.push_back(selected_output.global_index);

    return decoy_indexes;

  }
}  // namespace wallet
