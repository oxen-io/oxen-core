#include <fmt/format.h>

#include <cassert>
#include <random>
#include <thread>
#include <vector>

constexpr int Q = 12;                     // total quorum size, including proposer
constexpr int V = Q - 1;                  // num validators
constexpr int V_req = 7;                  // required validator signatures
constexpr int V_disrupt = V - V_req + 1;  // number of validators needed to block a quorum

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

std::pair<int64_t, int64_t> run_sims(int64_t n) {
    std::pair<int64_t, int64_t> result{0, 0};
    auto& [successes, failures] = result;
    std::bernoulli_distribution leader_draw{p};
    std::binomial_distribution<int> validators_draw{V, p};
    for (int i = 0; i < n; i++) {
        // Start from a compromised quorum, i.e. we waited until we got a favourable quorum before
        // starting the attack
        double confirm = 1, deny = 0;
        int b_round = 0;

        while (std::abs(confirm - deny) < 5 or (confirm < 2 * deny and deny < 2 * confirm)) {
            bool leader = leader_draw(rng);
            int validators = validators_draw(rng);

            if (leader and validators >= V_req) {
                // We own the quorum, so add the confirm score (diminished, if not round 0) and move
                // on to the next block:
                confirm += 1.0;// / (1 + b_round);
                b_round = 0;
            } else if (validators >= V_disrupt) {
                // We didn't own, but we do have enough to disrupt the quorum to try for a backup
                // quorum
                b_round++;
            } else {
                // We neither owned nor disrupted, so the honest nodes put in a vote against
                deny += 1.0;// / (1 + b_round);
                b_round = 0;
            }
        }

        if (confirm > deny)
            successes++;
        else
            failures++;
    }

    return result;
}

int main() {

    const auto p_own = p * p_win(V_req, V, p);
    const auto p_disrupt = p + pn * p_win(V_disrupt, V, p);

    fmt::print(
            "p = {:.4f}; P(own quorum) = {:.10f}, P(disrupt quorum) = {:.10f}\n",
            p,
            p_own,
            p_disrupt);

    std::vector<std::thread> threads;
    threads.resize(32);

    std::vector<std::pair<int64_t, int64_t>> results;
    results.resize(threads.size());
    for (size_t i = 0; i < threads.size(); i++) {
        threads[i] = std::thread{[i, &results] { results[i] = run_sims(100000000); }};
    }
    for (auto& th : threads)
        th.join();

    int64_t S = 0, F = 0;
    for (auto& [s, f] : results) {
        S += s;
        F += f;
    }

    fmt::print("{} success, {} failures\n", S, F);
}
