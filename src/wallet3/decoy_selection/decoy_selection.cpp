#include "decoy_selection.hpp"

#include <cryptonote_config.h>  // for ring size (cryptonote::TX_OUTPUT_DECOYS)

namespace wallet {
std::vector<int64_t> DecoySelector::operator()(const Output& selected_output) {
    const size_t n_decoys = cryptonote::TX_OUTPUT_DECOYS;

    // Select some random outputs according to gamma distribution
    std::random_device rd;
    std::default_random_engine rng(rd());

    // TODO: better distribution
    /*
    constexpr int ALPHA = 1;
    constexpr int BETA = 2;
    std::gamma_distribution<double> distribution{ALPHA, BETA};
    */

    std::uniform_int_distribution<> distribution(min_output_index, max_output_index);
    std::vector<int64_t> decoy_indexes;

    // TODO(sean): figure out how to remove the real index
    // We need to request the chosen output to ensure the daemon cant guess which output is real by
    // elimination
    decoy_indexes.push_back(selected_output.global_index);

    for (size_t i = 0; i < n_decoys; ++i) {
        // int64_t output_height_from_distribution = max_output_index - std::round(distribution(rng)
        // * (max_output_index - min_output_index)/10);
        decoy_indexes.push_back(distribution(rng));
    }

    return decoy_indexes;
}
}  // namespace wallet
