#ifndef LOKI_MINER_HANDLER_H
#define LOKI_MINER_HANDLER_H

#include "verification_context.h"
#include "cryptonote_basic.h"
#include "cryptonote_format_utils.h"
#include "difficulty.h"

namespace cryptonote {
	struct i_miner_handler
	{
		virtual bool handle_block_found(block& b, block_verification_context &bvc) = 0;
		virtual bool get_block_template(
			block& b,
			const account_public_address& adr,
			difficulty_type& diffic,
			uint64_t& height,
			uint64_t& expected_reward,
			const blobdata& ex_nonce
		) = 0;
	protected:
		~i_miner_handler() = default;
	};

	typedef std::function<bool(const cryptonote::block&, uint64_t, unsigned int, crypto::hash&)> get_block_hash_t;
}

#endif //LOKI_MINER_HANDLER_H
