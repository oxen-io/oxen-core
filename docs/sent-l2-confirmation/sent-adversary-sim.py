from math import factorial
import random
import os
import threading

p = 0.5

Q = 12  # total quorum size, including proposer
V = Q - 1  # num validators
Q_req = 7  # required validator signatures
Q_disrupt = V - Q_req + 1  # number of validators needed to block a quorum

pn = 1 - p  # probability of *not* getting selected

p_own = p * (
    sum(
        p**x * pn ** (V - x) * factorial(V) / (factorial(x) * factorial(V - x))
        for x in range(Q_req, Q)
    )
)
p_disrupt = p + pn * (
    sum(
        p**x * pn ** (V - x) * factorial(V) / (factorial(x) * factorial(V - x))
        for x in range(Q_disrupt, Q)
    )
)


print(f"p = {p}; P(own quorum) = {p_own}, P(disrupt quorum) = {p_disrupt}")


def run_sims(n):
    successes, failures = 0, 0
    for sims in range(n):
        # Start from a compromised quorum, i.e. we waited until we got a favourable quorum before
        # starting the attack
        confirm, deny = 1, 0

        b_round = 0
        while -5 < confirm - deny < 5 or (confirm < 2 * deny and deny < 2 * confirm):
            leader = random.random() <= p
            validators = random.binomialvariate(V, p)

            if leader and validators >= Q_req:
                # We own the quorum, so add the confirm score (diminished, if not round 0) and move on to
                # the next block:
                confirm += 1 / (1 + b_round)
                b_round = 0
            elif validators >= Q_disrupt:
                # We didn't own, but we do have enough to disrupt the quorum to try for a backup quorum
                b_round += 1
            else:
                # We neither owned nor disrupted, so the honest nodes put in a vote against
                deny += 1 / (1 + b_round)
                b_round = 0

        if confirm > deny:
            successes += 1
        else:
            failures += 1

    return successes, failures


s, f = run_sims(100000)
print(f"{s} success, {f} failures")
