#include "bls_omq.h"

#include "blockchain_db/sqlite/db_sqlite.h"
#include "bls/bls_signer.h"
#include "bls/bls_utils.h"
#include "common/util.h"
#include "ethyl/utils.hpp"
#include "fmt/format.h"
#include "logging/oxen_logger.h"
#include "oxenmq/message.h"

static auto logcat = oxen::log::Cat("bls_omq");

namespace oxen::bls {
GetRewardBalanceSignatureParts get_reward_balance_request_message(BLSSigner* signer, const crypto::eth_address& eth_address, uint64_t amount)
{
    // NOTE: Reconstruct the C++ equivalent of Solidity's `abi.encodePacked(rewardTag, address, amount)`
    GetRewardBalanceSignatureParts result = {};
    if (signer) {
        result.message_to_hash = fmt::format(
                "0x{}{}{}",
                signer->buildTag(signer->rewardTag),
                oxenc::type_to_hex(eth_address),
                ethyl::utils::padTo32Bytes(
                        ethyl::utils::decimalToHex(amount), ethyl::utils::PaddingDirection::LEFT));

        result.hash_to_sign = BLSSigner::hashHex(result.message_to_hash);
    }
    return result;
}

static std::string write_and_3_dot_truncate(std::string_view data, size_t threshold_for_3_dots) {
    fmt::memory_buffer buffer;
    if (data.size() > threshold_for_3_dots) {
        fmt::format_to_n(std::back_inserter(buffer), threshold_for_3_dots, "{}", data);
        fmt::format_to(std::back_inserter(buffer), "...");
    } else {
        fmt::format_to(std::back_inserter(buffer), "{}", data);
    }
    std::string result = fmt::to_string(buffer);
    return result;
}

struct VerifyDataResult
{
    bool good;
    std::string error;
};

/// Verify that the `payload` is valid and has the expected size. On failure a
/// descriptive message is failure message is written to the result.
static VerifyDataResult payload_is_hex(
        std::string_view payload_description,
        std::string_view payload,
        size_t required_hex_size) {
    VerifyDataResult result = {};
    payload = oxenc::trim_prefix(payload, "0x");
    payload = oxenc::trim_prefix(payload, "0x");

    if (payload.size() != required_hex_size) {
        result.error = fmt::format(
                "Specified an {} '{}' with length {} which does not have the "
                "correct length ({}) to be an {}",
                payload_description,
                write_and_3_dot_truncate(payload, 256),
                payload.size(),
                required_hex_size,
                payload_description);
        return result;
    }

    if (!oxenc::is_hex(payload)) {
        result.error = fmt::format(
                "Specified a {} '{}' which contains non-hex characters",
                payload_description,
                write_and_3_dot_truncate(payload, 256),
                payload.size());
        return result;
    }

    result.good = true;
    return result;
}

/// Verify that the `payload` is a number that can be parsed in base 10. On
/// failure a descriptive message is failure message is written to the result.
static VerifyDataResult payload_to_number(
        std::string_view payload_description,
        std::string_view payload,
        uint64_t& number) {

    VerifyDataResult result = {};
    if (!tools::parse_int(payload, number)) {
        result.error = fmt::format(
                "Specified {} '{}' that is not a valid number",
                payload_description,
                write_and_3_dot_truncate(payload, 64));
        return result;
    }

    result.good = true;
    return result;
}

template <typename T>
static VerifyDataResult data_parts_count_is_valid(std::span<const T> data, size_t expected_size)
    requires std::is_same_v<T, std::string> || std::is_same_v<T, std::string_view>
{
    VerifyDataResult result = {};
    if (data.size() == expected_size) {
        result.good = true;
    } else {
        auto fmt_buffer = fmt::memory_buffer();
        fmt::format_to(
                std::back_inserter(fmt_buffer),
                "Command should have {} data part(s), we received {}. The data was:\n",
                expected_size,
                data.size());

        // NOTE: Dump the data
        for (size_t index = 0; index < data.size(); index++) {
            std::string_view part = data[index];
            fmt::format_to(std::back_inserter(fmt_buffer), "{}{} - {}", index ? "\n" : "", index, write_and_3_dot_truncate(part, 256));
        }
        result.error = fmt::to_string(fmt_buffer);
    }

    return result;
}

enum class GetRewardBalanceRequestField
{
    Address,
    Amount,
    _count,
};

struct GetRewardBalanceRequest {
    crypto::eth_address address;
    uint64_t amount;
};

GetRewardBalanceResponse create_reward_balance_request(
        const oxenmq::Message& m, BLSSigner* signer, cryptonote::BlockchainSQLite* sql_db) {

    GetRewardBalanceResponse result = {};
    oxen::log::trace(logcat, "Received omq rewards signature request");

    // NOTE: Validate arguments
    if (!sql_db) {
        result.error = "Service node does not have a SQL DB setup to handle BLS OMQ requests";
        return result;
    }

    if (!signer) {
        result.error = "Service node does not have a SQL signer setup to handle BLS OMQ requests";
        return result;
    }

    // NOTE: Verify the data-segment count
    size_t field_count = tools::enum_count<GetRewardBalanceRequestField>;
    VerifyDataResult data_parts_check = data_parts_count_is_valid(std::span(m.data.data(), m.data.size()), field_count);
    if (!data_parts_check.good) {
        result.error = std::move(data_parts_check.error);
        return result;
    }

    // NOTE: Validate and parse the received data
    const std::string_view cmd = oxen::bls::BLS_OMQ_REWARD_BALANCE_CMD;
    GetRewardBalanceRequest request = {};

    for (size_t field_index = 0; field_index < field_count; field_index++) {
        auto field_value = static_cast<GetRewardBalanceRequestField>(field_index);
        std::string_view payload = m.data[field_index];
        switch (field_value) {
            case GetRewardBalanceRequestField::Address: {
                size_t required_hex_size = sizeof(crypto::eth_address) * 2;
                VerifyDataResult to_result = payload_is_hex("Ethereum address", payload, required_hex_size);
                if (!to_result.good) {
                    result.error = std::move(to_result.error);
                    return result;
                }

                switch (auto convert_result = oxenc::hex_to_type(payload, request.address)) {
                    case oxenc::hex_to_type_result::ok: break;

                    case oxenc::hex_to_type_result::non_hex_chars: {
                        result.error = fmt::format("Bad ethereum address '{}', address had non-hex characters", payload);
                    } break;

                    case oxenc::hex_to_type_result::invalid_size: {
                        result.error = fmt::format(
                                "Bad ethereum address '{}', address had wrong size {}, expected {}",
                                payload,
                                request.address.size(),
                                sizeof(crypto::eth_address) * 2);
                    } break;
                }
            } break;

            case GetRewardBalanceRequestField::Amount: {
                VerifyDataResult to_result = payload_to_number("rewards amount", payload, request.amount);
                if (!to_result.good) {
                    result.error = std::move(to_result.error);
                    return result;
                }
            } break;

            case GetRewardBalanceRequestField::_count: {
                assert(!"Invalid code path");
            } break;
        }
    }

    // NOTE: Get the rewards amount from the DB
    auto [batchdb_height, amount] = sql_db->get_accrued_earnings_eth(request.address);
    if (amount == 0) {
        result.error = fmt::format(
                "OMQ command '{}' requested an address '{}' that has a zero balance in the "
                "database",
                cmd,
                request.address);
        return result;
    }

    // NOTE: Verify the amount matches what the invoker requested
    if (request.amount != amount) {
        result.error = fmt::format(
                "OMQ command '{}' requested a reward amount {} for '{}' that does not match the rewards "
                "amount ({}) from this node's database",
                cmd,
                request.amount,
                request.address,
                amount);
        return result;
    }

    // NOTE: Prepare the signature
    GetRewardBalanceSignatureParts const signature_parts = get_reward_balance_request_message(signer, request.address, amount);

    // NOTE: Fill a response
    assert(result.error.empty());
    result.success                = true;
    result.status                 = "200";
    result.address                = request.address;
    result.amount                 = amount;
    result.height                 = batchdb_height;
    result.bls_pkey               = signer->getPublicKey();
    result.message_hash_signature = signer->signHash(signature_parts.hash_to_sign);

    oxen::log::trace(
            logcat,
            "Response generated for BLS reward request:\n"
            "  - status:                 {}\n"
            "  - address:                {}\n"
            "  - amount:                 {}\n"
            "  - height:                 {}\n"
            "  - bls_pkey:               {}\n"
            "  - message_hash_signature: {}\n"
            ,
            result.status,
            result.address,
            result.amount,
            result.height,
            result.bls_pkey.getStr(),
            result.message_hash_signature.getStr());
    return result;
}

GetRewardBalanceResponse parse_get_reward_balance_response(std::span<const std::string> data) {
    GetRewardBalanceResponse result = {};
    size_t const field_count = tools::enum_count<GetRewardBalanceResponseField>;
    VerifyDataResult data_parts_check = data_parts_count_is_valid(data, field_count);
    if (!data_parts_check.good) {
        result.error = std::move(data_parts_check.error);
        return result;
    }

    // NOTE: Validate and parse the received data
    for (size_t enum_index = 0; enum_index < field_count; enum_index++) {
        std::string_view payload = data[enum_index];
        auto enum_value          = static_cast<oxen::bls::GetRewardBalanceResponseField>(enum_index);
        switch (enum_value) {
            case oxen::bls::GetRewardBalanceResponseField::Status: {
                if (payload != "200") {
                    result.error = fmt::format(
                            "Command status ({}) indicates an error that cannot be handled has "
                            "occurred",
                            payload);
                    return result;
                }
                result.status = payload;
            } break;

            case oxen::bls::GetRewardBalanceResponseField::Address: {
                size_t required_hex_size = sizeof(crypto::eth_address) * 2;
                VerifyDataResult to_result = payload_is_hex("Ethereum address", payload, required_hex_size);
                if (!to_result.good) {
                    result.error = std::move(to_result.error);
                    return result;
                }

                switch (auto convert_result = oxenc::hex_to_type(payload, result.address)) {
                    case oxenc::hex_to_type_result::ok: break;

                    case oxenc::hex_to_type_result::non_hex_chars: {
                        result.error = fmt::format("Bad ethereum address '{}', address had non-hex characters", payload);
                    } break;

                    case oxenc::hex_to_type_result::invalid_size: {
                        result.error = fmt::format(
                                "Bad ethereum address '{}', address had wrong size {}, expected {}",
                                payload,
                                result.address.size(),
                                sizeof(crypto::eth_address) * 2);
                    } break;
                }
            } break;

            case oxen::bls::GetRewardBalanceResponseField::Amount: {
                VerifyDataResult to_result = payload_to_number("rewards amount", payload, result.amount);
                if (!to_result.good) {
                    result.error = std::move(to_result.error);
                    return result;
                }
            } break;

            case oxen::bls::GetRewardBalanceResponseField::Height: {
                VerifyDataResult to_result = payload_to_number("height", payload, result.height);
                if (!to_result.good) {
                    result.error = std::move(to_result.error);
                    return result;
                }
            } break;

            case oxen::bls::GetRewardBalanceResponseField::BLSPKeyHex: {
                size_t required_hex_size = sizeof(crypto::bls_public_key) * 2;
                VerifyDataResult to_result = payload_is_hex("BLS public key", payload, required_hex_size);
                if (!to_result.good) {
                    result.error = std::move(to_result.error);
                    return result;
                }
                result.bls_pkey = bls_utils::HexToPublicKey(payload);
            } break;

            case oxen::bls::GetRewardBalanceResponseField::MessageHashSignature: {
                // NOTE: Deserializing the hex will produce a fixed sized signature. Any errors here
                // will be thrown.
                try {
                    result.message_hash_signature = bls_utils::HexToSignature(payload);
                } catch ([[maybe_unused]] const std::exception &e) {
                    // NOTE: herumi/bls throws a generic setStr failed error which we ignore. We
                    // will emit a better error.
                    result.error = fmt::format(
                            "Specified a BLS signature '{}' with length {} which could not be "
                            "validly deserialised into a signature",
                            write_and_3_dot_truncate(payload, 512),
                            payload.size());
                }
            } break;

            case oxen::bls::GetRewardBalanceResponseField::_count: {
                assert(!"Invalid code path");
            } break;
        }
    }

    result.success = true;
    return result;
}
}  // namespace oxenbls
