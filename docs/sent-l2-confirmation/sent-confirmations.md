# SENT (L2 chain) -> Oxen chain interaction

Oxen 11, as has been widely discussed for some time, moves the fundamental registration, staking,
and rewards to an Ethereum L2 chain (Arbitrum), but still persists the Oxen chain at the service
node layer for two main purposes:

- retaining support for Oxen currency transactions.  Although we expect the majority of OXEN to be
  converted to SENT during the Session network upgrade, we will retain support for OXEN transactions
  for the near future to allow held OXEN to still be swapped for SENT.

- Using the oxen chain as the back end "state chain" for the oxen service node network.  This allows
  Oxen nodes to manage earned rewards amounts, to self-police the network (decomms, recomms,
  deregs), and to precisely control when information from the L2 network starts applying to the Oxen
  chain without needing to add wallets (with live funds) to Service Nodes.

The complication of such a mechanism is that, unlike when dealing with just one chain, the
interactions can get complicated in various ways:

- An L2 RPC provider might be lagging behind, in which case the  registrataions and other activity
  that it learns about would lag the rest of the Oxen network, causing it to fall behind.

- A malicious L2 provider who provides a significant amount of the Oxen network could provide false
  information regarding registration activity.

- A malicious Oxen pulse quorum could lie about L2 activity that it has observed (for example:
  adding fake registrations, or changing the manipulating the contributor list or fees of actual
  registrations).

Although these problems could be dealt at the blockchain concensus level (i.e. not accepting new
blocks that don't look right), in the case of innocent failures such as a lagging L2 provider that
means some portion of the network would lag behind the network state.  That in turn destabilises the
Session network because it means these nodes could potentially disagree on the current state of
network swarms, pulse quorums, deregistrations, and so on (at least until the problem is resolved
and they can catch up).

To avoid this, the Oxen service nodes are used to track the L2 chain but with a delay and
confirmation mechanism built in so that malicious or innocent mistakes can be overcome without
affecting the state.

## Pulse construction

The first step of the confirmation process is collecting recent L2 state; each Oxen service node
regularly queries its L2 provider to request any relevant events from SENT staking smart contract.
New registrations, unlock requests, and removing nodes from the smart contract all trigger different
events that oxend watches for.

As soon as such an event is observed, each oxend adds an L2 service node transaction recording the
information into its mempool of pending transactions so that, in general, it knows about the
transactions that should be occuring.

When a pulse quorum activates to produce the next block, the pulse quorum leader builds a block
containing metadata transactions detailing the event: for example, for a registration, the
transaction would include the service node pubkeys, operator address, fee, and contributor addresses
and stakes.

The pulse quorum validators that help create the block then sign off on the block if (and only if)
they agree that all included transactions in the block belong there.  If one does not (for example,
because a validator has not seen the event yet) then that validator declines to sign.  If enough
validators decline, the pulse block fails and a backup quorum kicks in (after a minute without the
previous block arriving) to attempt to produce a pulse block.

Once a pulse quorum signs off on such a block, however, the rest of the network will accept it
(assuming it follows the basic blockchain rules, isn't a duplicate, has the required signatures, and
so on) *without* checking whether it agrees with the (potentially unreliable) L2 state changes in
the block.  Instead it is the pulse quorum's job to validate those and, if a pulse quorums signs
off, that is all the validation needed for the service node network to accept such a block.

## Pulse confirmations

While the above approach avoids the network disagreeing as to the current state, it introduces a new
problem: pulse quorums in oxend are relatively small, and thus are vulnerable to compromise by a
malicious entity who controls a significant portion of the network.

The basic structure of a pulse quorum consists of 12 service nodes: 1 "leader" which creates the
block and coordinates the pulse quorum messages; and up to 11 validators who (through multiple
stages) contribute signatures and entropy to the block.  A final pulse block is valid and sent to
the network once seven (of the possible eleven) signatures are accumulated.  (All participating
nodes are recorded, but only the first seven signatures are broadcast to the network so as to
slightly reduce block size).

This leader + 7/11 mechanism is enough for the current Oxen chain because there are various other
signatures involved in what can be put into a block in the first place (for instance: you can't
manipulate registration details because the registration signature produced by the old
`prepare_registration` command completely signs all registration details, and service node stakes
and unlocks similarly include proof that they were constructed by the staker.  Pretty much the only
thing a malicious pulse quorum could do is delay a transaction for a block or two, or reorder
existing transactions.

With the ethereum transition, however, the pulse quorum's role takes on considerably more weight: it
is the one that signs off on observed registration details, stakes, unlocks, and so on.  While there
*are* protections against who can initiate such requests on the smart contract, there is a layer of
trust introduced between the Oxen node and the L2 RPC provider that feeds oxend the information
about what has happened in the smart contract.  Thus both the L2 provider and the pulse quorum
itself become a source of possible error (intentional or otherwise).

In particular, a single entity controlling 25% of 2000 network nodes (*either* an L2 provider RPC
supplying those nodes, or a malicious operator) would have about a 0.189% chance of controlling a
single pulse quorum (i.e. controlling both the block leader and at least 7/11 validators).  When
considering the 720 blocks produced per day, each with independent quorums, it's not at all
unreasonable that larger holders (even ones much smaller than 25% of the network) would have control
of a quorum from time to time.

To mitigate this, we require multiple consecutive pulse quorums to add votes to confirm or deny
pending state changes until a consensus is reached, at which point the state change (registration,
unlock, etc.) takes effect.

### Confirmation rules

- Pulse quorum blocks include state change transactions for newly observed L2 state changes.  This
  inclusion of a new state change counts as the first confirmation of the state change.
- Each pulse block must include a confirm or deny flag for each currently pending L2 state change,
  and by signing off on the block, the validators express agreement with the confirm/deny flags the
  block leader specified in the block.
- Each state change is assigned a + (confirm) and - (deny) score: each confirmation adds to the
  confirm score while each deny flag adds to the deny score.
- The score weight of the +/- flags in a block is determined by its pulse round: each flag in a
  first-round pulse block accumulates a full + or - point.  Backup quorums contribute 1/N points,
  where N is the quorum round: so flags in the first backup round (the second overall quorum round
  for a block) contribute 0.5 points; flags in the 4th backup round would contribute 0.2 points, and
  99th backup quorum would contribute 0.01 points.
- A state change is finalized once the dominant + or - score is at least 5 points larger than the
  lesser score, *and* at least double the lesser score; or when 30 blocks (1 hour, typically) have
  passed since its inclusion without otherwise finalizing it (and in such a case, it is resolved as
  denied).

Thus, when all quorums are in agreement (which will be the typical case), it takes 5 Oxen blocks to
achieve consensus: first the pulse quorum mines it, then the next 4 pulse quorums confirm it, and
upon this third confirmation the state change has +5, -0 and so the registration/unlock/etc.  takes
effect on the Oxen network, adding a new service node, initiating an unlock, etc.

The reason for reducing the score of backup quorums is that it takes fewer nodes to disrupt a quorum
than it does to compromise a quorum (a compromised quorum able to produce a block requires the
leader role and 7 validators, while preventing a quorum from consensus operating requires either the
leader or 5+ validators).  A malicious operator has a relatively small chance of owning a quorum,
but if he can disrupt quorums he gains more "rolls of the dice" that might give him a compromised
quorum.  The reduced score is designed to mitigate this by reducing the voting benefit of backup
quorums.

Reduction mechanics other than 1/N are possible (such as (1/2)^N), but don't make much difference in
practice; the 1/N rule, however, unifies confirmation voting values with the blockchain weight of
backup quorum pulse blocks which use the same 1/N backup quorum score mechanism to decide on which
of two competing pulse alt chains wins if pulse quorums produce competing chains.

The 30 block vote limit has a couple of purposes: first it suggests that the inclusion is highly
contentious, and thus suspect; secondly service nodes typically do not indefinitely retain L2
tracking data beyond an hour or so and thus are unlikely to be able to confirm a state change once
hours have passed since its inclusion.

#### Service Node adversary example

Supposing an adversary with control of an enormous one-third of the network's service nodes seeks to
fabricate an L2 network event.

The adversary's chance of owning any random pulse quorum is:

    p = 0.3333333

    p × (p⁷(1-p)⁴11!/(7!4!) + p⁸(1-p)³11!/(8!3!) + p⁹(1-p)²11!/(9!2!) + p¹⁰(1-p)11 + p^11)
        = 0.3333333 × 0.0386289354
        = 0.01287631

where the leading p term is the probability of being the quorum leader (and thus block proposer) and
the remaining term is the probability of getting 7 or more of the 11 validators.

(Note that there is a slight simplication here that we are calculating a probability *with*
replacement, while actual quorum selection is *without* replacement.  With thousands of service
nodes and a quorum size of 12, however, this difference will be negligible).

His chance of being able to disrput a quorum (i.e. to roll it over into a backup round) is:

    p + (1-p) × (p⁵(1-p)⁶11!/(6!5!) + (p⁶(1-p)⁵11!/(5!6!) + ... + p¹⁰(1-p)11 + p^11)
        = 0.3333333 + 0.1926648
        ≈ 0.526

where the first `p` term is the probability of being the block leader (in which case he can simply
not lead the quorum at all to disrupt it), and the second term is the probability of not being the
block leader but still getting 5+ of the 11 quorum validators slots.

His probability of owning the next 4 quorums in a row to get it through uncontested is miniscule:

    0.01287631⁴ = 0.00000002748944

(which is already conditional on compromising the initial quorum, so for any random block would be ≈
0.01287⁵ ≈ 0.000000000354).

So instead let's assume he pursues a strategy of attempting to disrupt quorums he doesn't control,
and voting in favour of the faked state in quorums he does control.  The probabilities here get
complicated and so for this I simulated a quorum process (Python and C++ versions of the simulation
code are available in the same directory as this document) that follows this strategy, measuring how
often the adversary was able to get a confirmed success versus how often the rest of the network got
a confirmed denial.

Out of 32 billion simulations starting after a successfully compromised initial pulse block, only
1002 simulations resulted in a compromised state getting through (0.0000000313125 -- only *slightly*
higher than the 0.000000027489 probability of the won-the-next-four-first-round-quorums-in-a-row
value).  This makes some intuitive sense: you can only disrupt a quorum about half the time, but
even if you succeed there's only a 0.013 chance of owning the next quorum, and so you most likely
need to be able to disrupt a block quorum many times before you get lucky with a backup quorum:
making it both low probability, and low value (since backup quorums also reduce the point value).
But even then, the vast majority of the time the next block will end up at an honest quorum that
will vote against you and it requires an extradorinary amount of luck for anything else to happen.

*Without* the reduction in backup quorum voting power, this probability is about 3 times higher
(≈0.00000011 in simulations) -- still small overall, but the reduction makes a compromise 3x more
difficult with minimal cost in normal circumstances.

For an adversary that controls 25% of the network and pursues this strategy, the possibility of
compromise is significantly smaller than the 33% example above (0.00189 of winning a pulse quorum,
and, once won, ≈0.0000000000128 probability of winning the next 4 in a row, and only a negligible
increase from attempting to disrupt into backup quorum votes).

It is worth pointing out that even 25% ownership of the service node network is already an enormous
investment and that attempting to carry out an attack is both difficult (because of the
probabilities above) and self-damaging in that it would likely significantly undermine the value of
the attacker's staked tokens.

#### RPC provider adversary example

An RPC adversary is a similar, but different threat model in that we assume the adversary can lie to
service nodes using its RPC endpoint, but doesn't directly control service nodes.  Thus we assume in
such a case that service nodes are acting honestly given the information they have.

Here we assume a single adversary that is supplying data to 33.3% of the service nodes, and wishes
to put a fake transaction onto the chain.  Unlike the previous example, this 33.3% number is not as
extreme as there is no staked investment component required on the part of the operator, and so
could simply reflect a popular provider.  There is, on the other hand, a reputational disincentive
of being found out and publicly called for lying in provided results, and so the 33% number seems
like a reasonable "err on the high side" value for working out an example.

Because the dishonest actor here is not a service node, we do not worry about disrupting to backup
quorums; instead a backup quorum happens whenever the primary quorum doesn't reach consensus as to
the inclusion (or denial).

Simulation results for the 33% case show a very low success rate of 125 in 3.2 billion simulations,
with 1660 simulations hitting the 30-block limit, and the rest being rejected by the network.

So while as much as 33% seems safe, the numbers get worse above that: at 50% half the network would
think something should belong and half would think it shouldn't; it ends up with better than even
chances that such an adversary could successfully introduce fake transactions into the network.
Mitigations for such a threat cannot be reasonably performed at the consensus level (because when a
majority of the network thinks something belongs then the two choices are either to have the network
break (i.e. by desyncing a large minority), or to accept the contentious transactions.  Our strategy
instead should be to steer operators towards a more diverse set of RPC providers rather than all
piling onto the same one.

## Block rewards

Unlike Oxen's simple, fixed per-block payout, in the SENT era contributors earn a small portion of
the L2 staking pool (enough so that a continual, compounding removal would result in 14% of the pool
getting paid out over a 1-year period, assuming no replenishment; see details in the staking
contracts for more info).

Rewards, however, are computed entirely on the OXEN side, and thus being able to advance the chain
requires an exact consensus of what the reward is at any given time.

Oxen nodes thus record the *current* L2 reward rate (queried from the contract) in each block, and
verifying this value is part of the duties of pulse quorum validators.  For all the same reasons
discussed above, however, this means that it could be a target of abuse by a malicious pulse
quorum.

For example, just after launch, the per-block SENT reward (distributed across all service nodes) to
be a little bit less than 23 SENT per 2-minutes (i.e. per Oxen block).  An adversary controlling a
large number of service nodes (either directly, or via L2 control) could simply lie about the state
of the contract and set an Oxen block's reward rate to 40 million SENT per block, then racing to be
the first to unstake and cash out.

To mitigate this, the Oxen 11 design uses two mechanisms:

### Smallest recent reward rate

The first mitigation is that the reward rate that is applied to calculating earned rewards is
computed by taking the *smallest* published reward rate of the last 15 blocks (i.e. the last 30
minutes, typically).  Thus it would take 15 consecutive compromised quorums to increase the payout
rate.

### Cap on relative changes

The second mitigation is that the recorded reward in a block is prevented from increasing more than
0.002% from one block to the next, or from decreasing more than 0.004%.  Thus block reward changes
can only change very slowly, with many small steps approved by many quorums.  Although the smallest
reward solution largely mitigates *upward* changes, it does not prevent a large actor (or even an
innocent bug) from deliberately harming the network by setting the reward to 0 and thus simply
stopping all payments for an hour.  This movement cap mitigates that.

The asymmetry in the cap is a reflection of the incentives involved: while there are substantial
gains to be had from (falsely) increasing the reward, decreasing it has no direct benefits to
anyone.  By allowing decreases to be twice as large as increases it means that it would take a
sustained majority of more than 2/3 of the network for an extended period to move the reward level
at all (without the rest of the network acting honestly to undo the change).

The asymmetry does mean that it would take only 1/3 of the network to (dishonestly) reduce the rate
below its appropriate value, but as there are few immediately obvious incentives to do so, this
trade off appears worthwhile.

### Effect on legitimate pool changes

It is also worth noting how these changes affect actual movements in the staking reward pool.

First, the pool withdrawal rate is limited by design to release approximately 0.000057% per 2-minute
interval, which is well below the 0.004% threshold, and so to very slow release of pool funds is
easily accommodated by these approaches.

Increases, on the other hand, are more predictable: they can come from payments for Session short
names, Pro features, Lokinet access, and other future network monetization.  There is no limit
imposed on a payment increase on the contract side: if someone were to instantly add 20M SENT into a
pool already containing 40M SENT then, in theory, per-block payments should increase by 50%.

The 0.002% increase cap above does allow for slow increases: it can accommodate a daily increase of
about 1.45% of the pool (that is about 560k per day being added to a 40M pool).

Sudden, large increases, however, take more time to adjust.  The instant 20M increase discussed
above, for instance, would require about 28 days to be fully reflected in the reward rate earned by
Oxen nodes (although rewards would be continually increasing over this period at the maximum
increase rate) starting from a 40M pool.  Albeit slow, this is an exponential process, and so as the
pool becomes larger, increases of the same size can be adjusted to more quickly.  For instance, a
60M pool would fully accommodate a 20M increase in 20 days, and a 100M pool would fully accommodate
the increase in 13 days.  A severely withdrawn 1M pool (which would take nearly 25 years of
withdrawals with no replenishment with the SENT launch parameters) would take around 7 months to
fully respond to the sudden 21x size increase of the pool with these caps.
