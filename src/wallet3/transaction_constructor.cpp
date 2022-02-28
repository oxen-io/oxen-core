#include "transaction_constructor.hpp"
#include "pending_transaction.hpp"
#include "decoy.hpp"
#include "output_selection/output_selection.hpp"
#include "decoy_selection/decoy_selection.hpp"
#include "db_schema.hpp"

namespace wallet
{
  // create_transaction will create a vanilla spend transaction without any special features.
  PendingTransaction
  TransactionConstructor::create_transaction(
      const std::vector<cryptonote::tx_destination_entry>& recipients) const
  {
    PendingTransaction new_tx(recipients);
    new_tx.fee_per_byte = fee_per_byte;
    new_tx.fee_per_output = fee_per_output;
    select_inputs_and_finalise(new_tx);
    return new_tx;
  }


  // SelectInputs will choose some available unspent outputs from the database and allocate to the
  // transaction can be called multiple times and will add until enough is sufficient
  void
  TransactionConstructor::select_inputs(PendingTransaction& ptx) const
  {
    const int64_t single_input_size = ptx.get_fee(1);
    const int64_t double_input_size = ptx.get_fee(2);
    const int64_t additional_input = double_input_size - single_input_size;
    const int64_t dust_amount = single_input_size * ptx.fee_per_byte;

    OutputSelector select_outputs{};
    const int noutputs_estimate = 300;  // number of outputs to precompute fee for
    for (int64_t output_count = 1; output_count < noutputs_estimate; ++output_count)
    {
      select_outputs.push_fee(output_count, ptx.get_fee(output_count));
    }
    int64_t transaction_total = ptx.sum_outputs();

    // Check that we actually have enough in the outputs to build this transaction. Fail early. We
    // then increase the transaction_total to include an amount sufficient to cover a reasonable
    // change amount. Transaction fee is high for the first input because there is overhead to cover
    // and prefer that the change amount is enough to cover that overhead, but if we dont have enough
    // in the wallet then try to ensure there is enough to cover the fee
    // as an additional (2nd+) input. Finally if the wallet balance is not sufficient
    // allow the change to be dust but this will only occur if the wallet has enough to cover the
    // transaction but not enough to also cover the dust which should be extremely unlikely.
    int64_t wallet_balance = db->available_balance(additional_input * static_cast<int64_t>(ptx.fee_per_byte));
    if (wallet_balance < transaction_total)
      throw std::runtime_error("Insufficient Wallet Balance");
    else if (wallet_balance > transaction_total + single_input_size * static_cast<int64_t>(ptx.fee_per_byte))
      transaction_total += single_input_size * ptx.fee_per_byte;
    else if (wallet_balance > transaction_total + additional_input * static_cast<int64_t>(ptx.fee_per_byte))
      transaction_total += additional_input * ptx.fee_per_byte;

    // Selects all outputs where the amount is greater than the estimated fee for an ADDITIONAL input.
    auto available_outputs = db->available_outputs(additional_input * static_cast<int64_t>(ptx.fee_per_byte));
    ptx.chosen_outputs = select_outputs(available_outputs, transaction_total);
    ptx.fee = ptx.get_fee();
    ptx.update_change();
  }

  // select_and_fetch_decoys will choose some available outputs from the database, fetch the
  // details necessary for a ring signature from teh daemon and add them to the
  // transaction ready to sign at a later point in time.
  void
  TransactionConstructor::select_and_fetch_decoys(PendingTransaction& ptx) const
  {
    ptx.decoys = {};
    // This initialises the decoys to be selected from global_output_index= 0 to global_output_index = highest_output_index
    int64_t max_output_index = db->chain_output_count();
    DecoySelector decoy_selection(0, max_output_index);
    std::vector<int64_t> indexes;
    for (const auto& output : ptx.chosen_outputs)
    {
      indexes = decoy_selection(output);
      auto decoy_promise = daemon->fetch_decoys(indexes);
      decoy_promise.wait();
      ptx.decoys.emplace_back(decoy_promise.get());
    }
  }

  void
  TransactionConstructor::select_inputs_and_finalise(PendingTransaction& ptx) const
  {
    while (true)
    {
      if (ptx.finalise())
        break;
      else
        select_inputs(ptx);
    }
    select_and_fetch_decoys(ptx);
  }
}  // namespace wallet
