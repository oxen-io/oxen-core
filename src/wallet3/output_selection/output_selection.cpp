#include "output_selection.hpp"

namespace wallet {
std::vector<Output> OutputSelector::operator()(
        const std::vector<Output>& available_outputs, int64_t amount) const {
    // Check that we actually have enough in the outputs to build this transaction. Fail early
    int64_t wallet_balance = std::accumulate(
            available_outputs.begin(),
            available_outputs.end(),
            int64_t{0},
            [](const int64_t& accumulator, const auto& x) { return accumulator + x.amount; });
    int64_t fee = 0;
    auto pos = fee_map.find(1);
    if (pos == fee_map.end()) {
        throw std::runtime_error("Missing fee amount");
    } else {
        fee = pos->second;
    }
    if (wallet_balance < amount + fee) {
        throw std::runtime_error("Insufficient Wallet Balance");
    }

    // Prefer a single output if suitable
    std::vector<Output> outputs_bigger_than_amount{};
    std::copy_if(
            available_outputs.begin(),
            available_outputs.end(),
            std::back_inserter(outputs_bigger_than_amount),
            [amount, fee](const auto& x) { return static_cast<int64_t>(x.amount) > amount + fee; });

    if (outputs_bigger_than_amount.size() > 0) {
        std::random_device rd;
        std::default_random_engine rng(rd());
        auto start = outputs_bigger_than_amount.begin();
        std::uniform_int_distribution<> dis(
                0, std::distance(start, outputs_bigger_than_amount.end()) - 1);
        std::advance(start, dis(rng));
        std::vector<Output> single_output(start, start + 1);
        return single_output;
    }

    // Else select some random outputs according to gamma distribution
    std::vector<double> scores;
    scores.reserve(available_outputs.size());
    std::random_device rd;
    std::default_random_engine rng(rd());
    auto output_cmp = [](const Output& lhs, const Output& rhs) {
        return lhs.block_height < rhs.block_height;
    };

    int64_t min_output_height =
            std::min_element(available_outputs.begin(), available_outputs.end(), output_cmp)
                    ->block_height;
    int64_t max_output_height =
            std::max_element(available_outputs.begin(), available_outputs.end(), output_cmp)
                    ->block_height;
    std::gamma_distribution<double> distribution(min_output_height, max_output_height);

    // Build a distribution and apply a score to each element of available outputs depending
    // on distance from the number chosen. Lower score is better.
    const int nrolls = 1000;  // number of experiments
    for (size_t i = 0; i < nrolls; ++i) {
        double number = distribution(rng);
        for (size_t j = 0; j < available_outputs.size(); ++j) {
            scores[j] += std::abs(number - available_outputs[j].block_height);
        }
    }

    // Build a list of indexes based on score
    std::vector<int> indices(available_outputs.size());
    std::iota(indices.begin(), indices.end(), 0);
    std::sort(indices.begin(), indices.end(), [&](int A, int B) -> bool {
        return scores[A] < scores[B];
    });

    // Iterate through the list until we have sufficient return value
    std::vector<Output> multiple_outputs{};
    int i = 0;
    while (amount + fee > 0) {
        auto pos = fee_map.find(i + 1);
        if (pos == fee_map.end()) {
            throw std::runtime_error("Missing fee amount");
        } else {
            fee = pos->second;
        }
        multiple_outputs.push_back(available_outputs[indices[i]]);
        amount = amount - available_outputs[indices[i]].amount;
        i++;
    }
    return multiple_outputs;
}
}  // namespace wallet
