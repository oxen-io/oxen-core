#include <fmt/format.h>

#include <array>
#include <cassert>
#include <random>
#include <thread>
#include <vector>

constexpr int Q = 12;                     // total quorum size, including proposer
constexpr int V = Q - 1;                  // num validators
constexpr int V_req = 7;                  // required validator signatures

constexpr double p = 1.0 / 3;  // Probability of getting selected
constexpr double pn = 1 - p;   // Probability of *not* getting selected

constexpr uint64_t factorial(uint64_t n) {
    assert(n <= 20);
    if (n <= 1)
        return 1;
    return n * factorial(n - 1);
}

// Probability of >= x successes from N draws with success probability p of each draw
double p_win(int x, const int N, const double p) {
    const double np = 1 - p;
    double result = 0;
    const auto fN = factorial(N);
    for (; x <= N; x++) {
        const auto bc = fN / (factorial(x) * factorial(N - x));
        result += std::pow(p, x) * std::pow(np, N - x) * bc;
    }
    return result;
}

thread_local std::mt19937_64 rng{std::random_device{}()};

// returns success, rejected, failed-by-limit
std::array<int64_t, 3> run_sims(int64_t n) {
    std::array<int64_t, 3> result{0, 0, 0};
    auto& [successes, failures, limit_fails] = result;
    std::bernoulli_distribution leader_draw{p};
    std::binomial_distribution<int> validators_draw{V, p};
    for (int i = 0; i < n; i++) {
        // Start from a compromised quorum, i.e. we waited until we got a favourable quorum before
        // starting the attack
        double confirm = 1, deny = 0;
        int b_num = 1, b_round = 0;

        while (b_num <= 30 and
               (std::abs(confirm - deny) < 5 or (confirm < 2 * deny and deny < 2 * confirm))) {
            bool leader = leader_draw(rng);
            int validators = validators_draw(rng);

            if (leader && validators >= V_req) {
                // Leader and 7+ validators agree on +
                confirm += 1.0 / (1 + b_round);
                b_num++;
                b_round = 0;
            } else if (!leader && V - validators >= V_req) {
                // Leader and 7+ validators agree on -
                deny += 1.0 / (1 + b_round);
                b_num++;
                b_round = 0;
            } else {
                // Leader and validators did not agree, so fail to produce a block
                b_round++;
            }
        }

        (b_num > 30 ? limit_fails : confirm > deny ? successes : failures)++;
    }

    return result;
}

int main() {

    const auto p_own = p * p_win(V_req, V, p);

    fmt::print(
            "p = {:.4f}; P(own quorum) = {:.10f}\n",
            p,
            p_own);

    std::vector<std::thread> threads;
    threads.resize(32);

    std::vector<std::array<int64_t, 3>> results;
    results.resize(threads.size());
    for (size_t i = 0; i < threads.size(); i++) {
        threads[i] = std::thread{[i, &results] { results[i] = run_sims(100000000); }};
    }
    for (auto& th : threads)
        th.join();

    int64_t S = 0, F = 0, L = 0;
    for (auto& [s, f, l] : results) {
        S += s;
        F += f;
        L += l;
    }

    fmt::print("{} success, {} failures, {} fail-by-limit\n", S, F, L);
}
