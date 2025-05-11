#if defined(WITH_MOCKNET)
#include "mocknet.h"

#include <boost/program_options/options_description.hpp>
#include <string_view>

#include "bls/bls_crypto.h"
#include "common/command_line.h"
#include "common/guts.h"
#include "common/oxen.h"
#include "crypto/crypto.h"
#include "crypto/eth.h"
#include "cryptonote_basic/verification_context.h"
#include "cryptonote_core/cryptonote_core.h"
#include "cryptonote_core/service_node_list.h"
#include "cryptonote_core/service_node_quorum_cop.h"
#include "cryptonote_core/service_node_rules.h"
#include "cryptonote_core/sesh_transition/sesh_transition.h"
#include "cryptonote_protocol/cryptonote_protocol_handler.h"
#include "logging/oxen_logger.h"

static auto logcat = oxen::log::Cat("mocknet");

// NOTE: On mocknet when the forking height is met, we inject a list of
// SNs into the network that we control (by using pre-defined SN keys).
//
// At the mocknet forking height and onwards, the daemon hijacks the
// quorum generating process and replaces all participants with the keys
// of the SNs we control.
//
// This means that when it's time to generate blocks, we control all
// the necessary keys to create and sign blocks fit for appending to
// the blockchain.

using namespace std::literals;

static const command_line::arg_descriptor<uint64_t> MOCKNET_FORK_AT_HEIGHT_ARG{
        "fork-to-mocknet",
        "Fork the current chain at the specified height into mocknet where Pulse quorums are "
        "hardcoded"};

struct mocknet_global_data {
    // If specified on the command line, forking to mocknet at `fork_at_height`
    // will occur.
    bool fork_enabled;
    uint64_t fork_at_height;  // The chain height to fork at from the current chain
    bool protocol_is_disabled;
    oxen::sesh::addrmap_t transition_addr_map;
    oxen::sesh::bonus_map_t transition_bonus_map;
    oxen::sesh::bls_keys_t transition_bls_keys;
};
static mocknet_global_data globals;

struct mocknet_key {
    eth::bls_secret_key bls;
    eth::bls_public_key bls_pubkey;
    crypto::ed25519_secret_key ed25519;
    crypto::ed25519_public_key ed25519_pubkey;
};

const eth::address MOCK_ETH_ADDRESS = tools::make_from_hex_guts<eth::address>(
        "4444444444444444444444444444444444444444"sv, false);

// NOTE: Ed25519 public key is stuffed in the last 32 bytes of the secret key
// but it's useful to have the pubkey separated to visually grok instantly for
// debugging quorums and Pulse.
//
// clang-format off
const static inline mocknet_key MOCKNET_KEYS[] = {
 {
   .bls            = tools::make_from_hex_guts<eth::bls_secret_key>("1cf322c2171b84dc5b4afa1ebd2a5d581512037d0f6daa7bd5d0d0519d29ad60"sv, false),
   .bls_pubkey     = tools::make_from_hex_guts<eth::bls_public_key>("2af1895f38996ec43ec1cecd708663e5d8cb1991d9d32c0d4666e7f92ecd527e26ee711043833557831888fb39f695268f613557f25b488ef6bd12ada7f51852"sv, false),
   .ed25519        = tools::make_from_hex_guts<crypto::ed25519_secret_key>("7e09c986f6a295cea55e0df47c36aaa6f624eb10d4981e3581794348ef997d03e5dee5316c70e841131c042626affe127d83cf844efd9d331b471e263b1a85eb"sv, false),
   .ed25519_pubkey = tools::make_from_hex_guts<crypto::ed25519_public_key>("e5dee5316c70e841131c042626affe127d83cf844efd9d331b471e263b1a85eb"sv, false),
 },
 {
   .bls            = tools::make_from_hex_guts<eth::bls_secret_key>("113501ce0f0186aa1c16e7319cc5a12b22d74658a01a5fff69f8f4a1a46e2793"sv, false),
   .bls_pubkey     = tools::make_from_hex_guts<eth::bls_public_key>("27b745a6dc4c154e68749c3efef7ee436725368bd4d3b7c8391f9030a24968f7065db954d2f27098abdf2fe2e438e1a31cc288cc7dd0b88736464d635c65bf25"sv, false),
   .ed25519        = tools::make_from_hex_guts<crypto::ed25519_secret_key>("5dc85359f29df9fc9f367995c1de3211caf2fdda7a9fd0f3ee35d6727652eb15f8524a42d96e4e9280bcc3b1b8a321f16fae298c6adb95b101c99c2a1cede9e8"sv, false),
   .ed25519_pubkey = tools::make_from_hex_guts<crypto::ed25519_public_key>("f8524a42d96e4e9280bcc3b1b8a321f16fae298c6adb95b101c99c2a1cede9e8"sv, false),
 },
 {
   .bls            = tools::make_from_hex_guts<eth::bls_secret_key>("2d7adf122ca8c0893daabb4e90318123a507e7483aada9972ce1289c567e64e1"sv, false),
   .bls_pubkey     = tools::make_from_hex_guts<eth::bls_public_key>("1943fb88138e87130ac4e1745b8cf4a0df131753d93b87ec97a61f14111cc67c03ab16d6f25f40c3e288802ae1cf0f73aaaddece0c9257f8ccf6972ba95bd91a"sv, false),
   .ed25519        = tools::make_from_hex_guts<crypto::ed25519_secret_key>("f3e1b9849c41a6aec3814c31cbaba76dd65b50e9da9810ac46e5859a210aa26186ff74b3af6923e7cd6ee8f96e2fcd2b43d76b47e738fc507f6d4a6f0f667f24"sv, false),
   .ed25519_pubkey = tools::make_from_hex_guts<crypto::ed25519_public_key>("86ff74b3af6923e7cd6ee8f96e2fcd2b43d76b47e738fc507f6d4a6f0f667f24"sv, false),
 },
 {
   .bls            = tools::make_from_hex_guts<eth::bls_secret_key>("01165522d68d103da824419e8fa100261bed82239b0eb0bda27f7a6ad0e036af"sv, false),
   .bls_pubkey     = tools::make_from_hex_guts<eth::bls_public_key>("1ec858c9221661872b24c3704675f7a3ce0a6ce6b654a8dce8f38210958b2ba5279f738198d899198f6bcc9f6c6cc18c02697f03fa561c7c1bc75585f079a0e9"sv, false),
   .ed25519        = tools::make_from_hex_guts<crypto::ed25519_secret_key>("59074fff43f5ce2df8043c963f4139d69e18b2a237aaa2ad6f9498621f62c4ee18b0f9210939d0aba9e95ef370c4cc6d45ebe71d88874363e4483aa8733c6141"sv, false),
   .ed25519_pubkey = tools::make_from_hex_guts<crypto::ed25519_public_key>("18b0f9210939d0aba9e95ef370c4cc6d45ebe71d88874363e4483aa8733c6141"sv, false),
 },
 {
   .bls            = tools::make_from_hex_guts<eth::bls_secret_key>("26de79eeb6c8ef1d39662055b9fb92eae41775f3180bb2ee4b8ce16c71405281"sv, false),
   .bls_pubkey     = tools::make_from_hex_guts<eth::bls_public_key>("1fe342416c04ca0c1e70e4186bcb6c5fc6012bbf5b836d77851f677a148ceb702315004d1f11c00eb8987eb48ab587faf9ca1baf6d2a9c065c3c0d1b82ca38ff"sv, false),
   .ed25519        = tools::make_from_hex_guts<crypto::ed25519_secret_key>("db100ee4a55312bf8ab709ffa5c2e8b1e75cca306993f83c2a757c1e8a0aceaa6320373990b24a67a2a74f86552445500470783e94f3e1305fa1ba50dfb14b96"sv, false),
   .ed25519_pubkey = tools::make_from_hex_guts<crypto::ed25519_public_key>("6320373990b24a67a2a74f86552445500470783e94f3e1305fa1ba50dfb14b96"sv, false),
 },
 {
   .bls            = tools::make_from_hex_guts<eth::bls_secret_key>("125996c879a7ebef0b60f9e89549ee9d2f3485b04d2770a2ff34dc6bf072a010"sv, false),
   .bls_pubkey     = tools::make_from_hex_guts<eth::bls_public_key>("17061be18c39151051cb50571b8bc8b3d4c8ea0fae6e95d52324fdf9fe6791d029a34c767e152414c96037466fd34a0c85d814ade1daa8ca9282e5a65386a066"sv, false),
   .ed25519        = tools::make_from_hex_guts<crypto::ed25519_secret_key>("e1056f9e37fa964ad8bb1af98f190d0401e57658421800504eb27e846083df06f9ac7a21001f4c456bc3faccf1e4b90a8fdb10a340c47a663d1a6e7cb8fafff1"sv, false),
   .ed25519_pubkey = tools::make_from_hex_guts<crypto::ed25519_public_key>("f9ac7a21001f4c456bc3faccf1e4b90a8fdb10a340c47a663d1a6e7cb8fafff1"sv, false),
 },
 {
   .bls            = tools::make_from_hex_guts<eth::bls_secret_key>("2dfacf11558bd0efeeb272f7601bb631f8126e27cbe3bdabdd596ec6364581b6"sv, false),
   .bls_pubkey     = tools::make_from_hex_guts<eth::bls_public_key>("2012b63f81df7fecdcb8f9abe70825b35cac985781cf26f419d23c82181a52ef08a8a524bc9acff0933d35ffc1677a37e398d8458b99b602aee566c4a81c8a79"sv, false),
   .ed25519        = tools::make_from_hex_guts<crypto::ed25519_secret_key>("dbc3ddece543e56134cba6a034bc63aca26de2b7ce9b6ea90f97d08ccb8429acfcef63a41b837066ca3348d9ca9583fa6d105c1e853f63eb19403f8c1132aec7"sv, false),
   .ed25519_pubkey = tools::make_from_hex_guts<crypto::ed25519_public_key>("fcef63a41b837066ca3348d9ca9583fa6d105c1e853f63eb19403f8c1132aec7"sv, false),
 },
 {
   .bls            = tools::make_from_hex_guts<eth::bls_secret_key>("0db93b9aa21b27a7836bca15d6c02ff2859f97df87f416075f26944908fe9785"sv, false),
   .bls_pubkey     = tools::make_from_hex_guts<eth::bls_public_key>("212d793ffd416c20458350c7827dbae551b1c5e1388668082308bee95c0e1404016bb5110e46b463e1eb61fe7ae88f5489907a71c3a950d370a5b8d8a63b0fff"sv, false),
   .ed25519        = tools::make_from_hex_guts<crypto::ed25519_secret_key>("c97d6c95a1f5da27550586c4ecfbb6e08229b1685a44beba803c9f5f29b051944233a563748f37cdad6b0bff64bdfb7cca8520b0e52c60bdc487f76795c3f6a5"sv, false),
   .ed25519_pubkey = tools::make_from_hex_guts<crypto::ed25519_public_key>("4233a563748f37cdad6b0bff64bdfb7cca8520b0e52c60bdc487f76795c3f6a5"sv, false),
 },
 {
   .bls            = tools::make_from_hex_guts<eth::bls_secret_key>("1a2b3bde6a04c35af2b556e9112046a58eae5914ff27dca1bce7a86f408c8d68"sv, false),
   .bls_pubkey     = tools::make_from_hex_guts<eth::bls_public_key>("302c7cf9f10a82b842a4ec4a33491e3c2b7991f30212c2855307e2abc7394ecf03d6b8e86376718bbe7779c6a3b2409729d3e1a0a0d3330bf509ca86ae51d6c7"sv, false),
   .ed25519        = tools::make_from_hex_guts<crypto::ed25519_secret_key>("3386d44ba497425cf78c50908b5b9aa7e0fbae3ca58e14db1dae60e48abece7b58f6bc7a87cba310e14138ce5ca73472c4b8ff2e762ee8aebc1264bd20b077b0"sv, false),
   .ed25519_pubkey = tools::make_from_hex_guts<crypto::ed25519_public_key>("58f6bc7a87cba310e14138ce5ca73472c4b8ff2e762ee8aebc1264bd20b077b0"sv, false),
 },
 {
   .bls            = tools::make_from_hex_guts<eth::bls_secret_key>("17df0bf20183db292be8675bbd1033a52a76e5840a34769e5b4b7a6261b5d554"sv, false),
   .bls_pubkey     = tools::make_from_hex_guts<eth::bls_public_key>("0e19dd7504c2ac59cc56feb0c0e604105ec3ec6af3cd734ce134658ed73dbba32964837b2414b56c286814a96c0bd01a39411f17ffb6d98dee7c836133aacc1c"sv, false),
   .ed25519        = tools::make_from_hex_guts<crypto::ed25519_secret_key>("0e33805260ab33aa3d8318a5602fb370f1a1f63ec9f5902d42910bdc5d39d1155436c13d55076b160e8840381cf597a6a36b0db09b3782d575a0759ec5d44f90"sv, false),
   .ed25519_pubkey = tools::make_from_hex_guts<crypto::ed25519_public_key>("5436c13d55076b160e8840381cf597a6a36b0db09b3782d575a0759ec5d44f90"sv, false),
 },
 {
   .bls            = tools::make_from_hex_guts<eth::bls_secret_key>("010ae37cd6db5cfd6c3bdaa2038a6c6ad17f92d6e0ccf861fb21bf26b0cd00c3"sv, false),
   .bls_pubkey     = tools::make_from_hex_guts<eth::bls_public_key>("1ab996803ab1f20d375f708ebb86fab164d071646fe1f34cb1c6f813a28c40b91e1eef20aa3060291edc85fe795d189c1f1b048ffa495338a9584fce9bbe63b7"sv, false),
   .ed25519        = tools::make_from_hex_guts<crypto::ed25519_secret_key>("f7955c0752fb20ba20ad3d3e0c720ec8a599d90dddb6c55deb69980c2bfb305217c0988c25165b9e0fb227cb3b81c9e530d2d7113585251782235b15a260b63c"sv, false),
   .ed25519_pubkey = tools::make_from_hex_guts<crypto::ed25519_public_key>("17c0988c25165b9e0fb227cb3b81c9e530d2d7113585251782235b15a260b63c"sv, false),
 },
 {
   .bls            = tools::make_from_hex_guts<eth::bls_secret_key>("281d19c9add51d7804687a85f0addbb3312f7b9d44f2ff59cdcb2ce8e1d048f5"sv, false),
   .bls_pubkey     = tools::make_from_hex_guts<eth::bls_public_key>("2ad19c51493553d6e0ab87ac384b10b42fe94b76d1e31fe8667104eeca05228e0fe9a621766977bf627b330f45cfb4ee1b9ef429b0a2dcf2468df1f89860d8ba"sv, false),
   .ed25519        = tools::make_from_hex_guts<crypto::ed25519_secret_key>("a054293fb8a0a1640adc1e8fe879b30e6b40056fe0777d3cb667b0b0ceb4cea9e6b3f9ddf6f4646a16c52309da7092aef2728de8296ec5f82a9d8f61fc1985ba"sv, false),
   .ed25519_pubkey = tools::make_from_hex_guts<crypto::ed25519_public_key>("e6b3f9ddf6f4646a16c52309da7092aef2728de8296ec5f82a9d8f61fc1985ba"sv, false),
 },
 {
   .bls            = tools::make_from_hex_guts<eth::bls_secret_key>("1eb53ec1f7169ee9dce15bfa0a2bfaae26d7f296a4bc331745e27b8cf902a9c9"sv, false),
   .bls_pubkey     = tools::make_from_hex_guts<eth::bls_public_key>("0552e55bdecf1effdcdf3c2a3907d12da083b9ce05ce795adf0d9d0c1ec8167a20640b793eb5810999f389d4069dd668b650e0ac2d636a35870db07e35a0da88"sv, false),
   .ed25519        = tools::make_from_hex_guts<crypto::ed25519_secret_key>("9c93544afa7b17d22d784060b990aa30faf87281ec86e7cd29fa97f089bca5e2eb87bc542c036ffb4167f950e229fc48009960a7ee6547f27e81c882a3e9e624"sv, false),
   .ed25519_pubkey = tools::make_from_hex_guts<crypto::ed25519_public_key>("eb87bc542c036ffb4167f950e229fc48009960a7ee6547f27e81c882a3e9e624"sv, false),
 },
 {
   .bls            = tools::make_from_hex_guts<eth::bls_secret_key>("6a735e8952ecc1e4ffe9be75408148ac1da075eba2b30067c85694f7fed07e2e"sv, false),
   .bls_pubkey     = tools::make_from_hex_guts<eth::bls_public_key>("1c10193d274f489dd5f8d7bbf2e67f1afdb12cd30997974eeadbd081e352d92922b03da2289d8b346aa257c9d4c429581e8dec5f1ceb6d36b416231c623b3d46"sv, false),
   .ed25519        = tools::make_from_hex_guts<crypto::ed25519_secret_key>("b5014b2b4c67cbfa4a33837e24d2ed0cf052e7000fd468001c0ac1462f8e96621b9d2a6fa0ac84f86bfabe95f291c17f4662dbbd1e91f4f7c5ea606c1f78c006"sv, false),
   .ed25519_pubkey = tools::make_from_hex_guts<crypto::ed25519_public_key>("1b9d2a6fa0ac84f86bfabe95f291c17f4662dbbd1e91f4f7c5ea606c1f78c006"sv, false),
 },
 {
   .bls            = tools::make_from_hex_guts<eth::bls_secret_key>("1ec23b2cb939a6512c66f1dc61ad775f8ff5395de44ee4354fba249b97f92446"sv, false),
   .bls_pubkey     = tools::make_from_hex_guts<eth::bls_public_key>("1e4ab84357d6418943b3c60d4c1aed8e027d03e54205fd72e0fcb2a0d1c3b049059f5d1739f240b880532f4ad9dab5b38c3e20618ee6337e2560a7737d05cdee"sv, false),
   .ed25519        = tools::make_from_hex_guts<crypto::ed25519_secret_key>("2e68f03d878a3d1af3cbcd4180b638fb2a985ae631858d3ca53794ee9028de84c5dc55b6a87249e3cab17ee64801de9f6923159cb9c688c7c6614e4a5c2678be"sv, false),
   .ed25519_pubkey = tools::make_from_hex_guts<crypto::ed25519_public_key>("c5dc55b6a87249e3cab17ee64801de9f6923159cb9c688c7c6614e4a5c2678be"sv, false),
 },
};
// clang-format on

void mocknet_add_cli_arg(boost::program_options::options_description& desc) {
    command_line::add_arg(desc, MOCKNET_FORK_AT_HEIGHT_ARG);
}

bool mocknet_read_cli_for_mocknet_arg(
        const boost::program_options::variables_map& vm, bool is_service_node) {
    if (!is_arg_defaulted(vm, MOCKNET_FORK_AT_HEIGHT_ARG)) {
        globals.fork_enabled = true;
        globals.fork_at_height = get_arg(vm, MOCKNET_FORK_AT_HEIGHT_ARG);
    }

    if (globals.fork_enabled && !is_service_node) {
        oxen::log::error(logcat, "Node must be running in service node to enable the mocknet flag");
        return false;
    }

    return true;
}

bool mocknet_is_forking(uint64_t top_block_height) {
    bool result = globals.fork_enabled && (top_block_height + 1) == globals.fork_at_height;
    return result;
}

bool mocknet_has_forked(uint64_t top_block_height) {
    bool result = globals.fork_enabled && (top_block_height + 1) > globals.fork_at_height;
    return result;
}

crypto::public_key mocknet_get_deterministic_block_leader() {
    crypto::public_key result;
    const crypto::ed25519_secret_key& ed25519_skey = MOCKNET_KEYS[0].ed25519;
    const crypto::secret_key& skey = crypto::ed25519_to_monero_secret_key(ed25519_skey);
    crypto::secret_key_to_public_key(skey, result);
    return result;
}

void mocknet_replace_quorum_with_mock_nodes(
        service_nodes::quorum& quorum, uint64_t top_block_height) {
    // NOTE: Replace each node in the quorum with the mock keys sequentially
    assert(quorum.workers.size() + quorum.validators.size() < oxen::array_count(MOCKNET_KEYS));

    size_t key_index = 0;
    for (size_t index = 0; index < quorum.workers.size(); index++) {
        const crypto::ed25519_secret_key& ed25519_skey = MOCKNET_KEYS[key_index++].ed25519;
        const crypto::secret_key& skey = crypto::ed25519_to_monero_secret_key(ed25519_skey);
        crypto::secret_key_to_public_key(skey, quorum.workers[index]);
    }

    for (size_t index = 0; index < quorum.validators.size(); index++) {
        const crypto::ed25519_secret_key& ed25519_skey = MOCKNET_KEYS[key_index++].ed25519;
        const crypto::secret_key& skey = crypto::ed25519_to_monero_secret_key(ed25519_skey);
        crypto::secret_key_to_public_key(skey, quorum.validators[index]);
    }
}

void mocknet_inject_nodes(uint8_t nettype_u8, void* snl_state_ptr, uint8_t hf_version) {
    auto* state = reinterpret_cast<service_nodes::service_node_list::state_t*>(snl_state_ptr);
    auto nettype = static_cast<cryptonote::network_type>(nettype_u8);

    // NOTE: Inject mock service nodes
    for (const auto& key : MOCKNET_KEYS) {
        auto info = std::make_shared<service_nodes::service_node_info>();
        info->registration_height = state->height;
        info->recommission_credit = cryptonote::get_config(nettype).BLOCKS_IN(
                service_nodes::DECOMMISSION_INITIAL_CREDIT);
        info->staking_requirement = state->get_staking_requirement(nettype);
        info->active_since_height = state->height;
        info->total_contributed = info->staking_requirement;
        if (hf_version >= static_cast<uint8_t>(cryptonote::feature::ETH_BLS))
            info->operator_ethereum_address = MOCK_ETH_ADDRESS;
        info->bls_public_key = eth::get_pubkey(key.bls);
        assert(info->bls_public_key == key.bls_pubkey);
        info->registration_hf_version = static_cast<cryptonote::hf>(hf_version);

        // NOTE: Add contributor
        {
            service_nodes::service_node_info::contributor_t contributor = {};
            contributor.amount = state->get_staking_requirement(nettype);
            if (hf_version >= static_cast<uint8_t>(cryptonote::feature::ETH_BLS)) {
                contributor.ethereum_address = MOCK_ETH_ADDRESS;
                contributor.ethereum_beneficiary = MOCK_ETH_ADDRESS;
            } else {
                service_nodes::service_node_info::contribution_t contribution = {};
                contribution.amount = contributor.amount;
                contributor.locked_contributions.push_back(contribution);
            }

            info->contributors.push_back(contributor);
        }

        crypto::secret_key skey = crypto::ed25519_to_monero_secret_key(key.ed25519);
        crypto::public_key pkey;
        crypto::secret_key_to_public_key(skey, pkey);
        assert(std::memcmp(pkey.data(), key.ed25519_pubkey.data(), pkey.size()) == 0);
        state->insert_info(pkey, std::move(info));
    }

    // NOTE: Log that we hit the mocknet pre-conditions
    cryptonote::account_public_address zero_cn_address = {};
    std::string zero_cn_address_str =
            cryptonote::get_account_address_as_str(nettype, false, zero_cn_address);

    fmt::memory_buffer debug_log;
    fmt::format_to(
            std::back_inserter(debug_log),
            "Registering {} mock nodes (w/ ETH and CN wallets {}, {}):\n",
            sizeof(MOCKNET_KEYS) / sizeof(MOCKNET_KEYS[0]),
            MOCK_ETH_ADDRESS,
            zero_cn_address_str);

    for (const auto& key : MOCKNET_KEYS) {
        crypto::secret_key skey = crypto::ed25519_to_monero_secret_key(key.ed25519);
        crypto::public_key pkey;
        crypto::secret_key_to_public_key(skey, pkey);
        fmt::format_to(
                std::back_inserter(debug_log),
                "  PKEY: {} BLS: {}\n",
                pkey,
                eth::get_pubkey(key.bls));
    }

    oxen::log::info(
            globallogcat,
            fg(fmt::terminal_color::magenta) | fmt::emphasis::bold,
            "Mocknet activated at block {}, hardfork is {}, quorums and blocks will be generated "
            "by mock nodes",
            state->height,
            static_cast<uint8_t>(hf_version));

    oxen::log::debug(logcat, "{}", fmt::to_string(debug_log));
}

void mocknet_push_mock_pulse_block(cryptonote::core& core) {
    cryptonote::block top_block = core.blockchain.db().get_top_block();
    crypto::hash top_hash = cryptonote::get_block_hash(top_block);
    if (!globals.fork_enabled || (top_block.get_height() + 1) < globals.fork_at_height)
        return;

    auto* protocol = reinterpret_cast<cryptonote::t_cryptonote_protocol_handler<cryptonote::core>*>(
            core.get_protocol());
    if (!globals.protocol_is_disabled && protocol) {
        globals.protocol_is_disabled = true;
        protocol->set_no_sync(true);
        protocol->set_max_out_peers(0);
        protocol->set_p2p_endpoint(nullptr);
    }

    constexpr bool adhere_to_pulse_timings = false;
    const int64_t now = time(nullptr);
    if (adhere_to_pulse_timings) {
        pulse::timings timings = {};
        pulse::get_round_timings(
                core.blockchain, top_block.get_height() + 1, top_block.timestamp, timings);
        int64_t r0_unix_ts = std::chrono::duration_cast<std::chrono::seconds>(
                                     timings.r0_timestamp.time_since_epoch())
                                     .count();
        if (now < r0_unix_ts)
            return;  // NOTE: Too early to generate a block
    } else {
        int64_t time_since_last_block_s = now - top_block.timestamp;
        if (time_since_last_block_s < 10)
            return;
    }

    // NOTE: Cruft to generate a pulse block
    std::vector<crypto::hash> const entropy = service_nodes::get_pulse_entropy_for_next_block(
            core.blockchain.db(),
            top_hash,
            /*block round*/ 0);

    const crypto::public_key& block_leader =
            core.blockchain.service_node_list.get_next_block_leader().key;

    cryptonote::network_type net = core.get_nettype();
    service_nodes::quorum quorum = service_nodes::generate_pulse_quorum(
            net,
            block_leader,
            core.blockchain.get_network_version(),
            core.blockchain.service_node_list.active_service_nodes_infos(),
            entropy,
            /*block round*/ 0,
            top_block.get_height() + 1);

    crypto::public_key mock_producer;
    std::memcpy(mock_producer.data(), MOCKNET_KEYS[0].ed25519_pubkey.data(), sizeof(mock_producer));

    [[maybe_unused]] crypto::public_key mock_validator0;
    std::memcpy(
            mock_validator0.data(), MOCKNET_KEYS[1].ed25519_pubkey.data(), sizeof(mock_validator0));

    assert(quorum.workers.size());
    assert(mock_producer == quorum.workers[0]);
    assert(mock_validator0 == quorum.validators[0]);
    assert(mock_producer);

    std::vector<service_nodes::service_node_pubkey_info> list_state =
            core.blockchain.service_node_list.get_service_node_list_state({mock_producer});
    assert(list_state.size() == 1);

    cryptonote::block block = {};
    service_nodes::payout block_producer_payouts =
            service_nodes::service_node_payout_portions(mock_producer, *list_state[0].info);

    // NOTE: Generate the next block. The random value in the block is skipped and
    // set to all 0s
    uint64_t generated_height = 0;
    bool generated = false;
    try {
        generated = core.blockchain.create_next_pulse_block_template(
                block,
                block_producer_payouts,
                /*pulse round*/ 0,
                /*validator handshake bitset*/ 0b0111'1111'1111,  // Full participation
                generated_height);
    } catch (const std::exception& e) {
        oxen::log::error(logcat, "Failed to generate block: {}", e.what());
    }

    // NOTE: This can fail if the L2 tracker has not yet initialised or retrieved the rewards yet
    if (!generated)
        return;

    assert(generated_height == top_block.get_height() + 1);
    crypto::hash hash = cryptonote::get_block_hash(block);
    oxen::log::info(
            globallogcat,
            fg(fmt::terminal_color::magenta) | fmt::emphasis::bold,
            "Generating mocknet block {} ({}) signed by mock validators",
            generated_height,
            hash);

    fmt::memory_buffer debug_log;
    fmt::format_to(std::back_inserter(debug_log), "Block {} signed by:\n", generated_height);

    // NOTE: Generate the signatures from each member of the quorum
    assert(quorum.validators.size() >= service_nodes::PULSE_BLOCK_REQUIRED_SIGNATURES);
    for (size_t index = 0; index < service_nodes::PULSE_BLOCK_REQUIRED_SIGNATURES; index++) {

        // NOTE: Generate the monero pub/sec key from the Ed25519 key
        const crypto::public_key& validator = quorum.validators[index];
        crypto::public_key mock_pkey;
        crypto::secret_key mock_skey =
                crypto::ed25519_to_monero_secret_key(MOCKNET_KEYS[index + 1].ed25519);
        bool converted = crypto::secret_key_to_public_key(mock_skey, mock_pkey);
        assert(converted);

        // The 0th index MOCKNET_KEY is always the block leader, the 1st index
        // is the first validator.
        assert(validator == mock_pkey);

        // NOTE: Generate the signature
        service_nodes::quorum_signature mock_signature = {};
        mock_signature.voter_index = index;
        crypto::generate_signature(hash, mock_pkey, mock_skey, mock_signature.signature);
        fmt::format_to(
                std::back_inserter(debug_log),
                "  {:02d} PKEY: {} SIG: {}\n",
                index,
                mock_pkey,
                mock_signature.signature);

        // NOTE: Add it to the block
        block.signatures.push_back(mock_signature);
    }

    oxen::log::debug(logcat, "{}", fmt::to_string(debug_log));

    // NOTE: Submit the block to core
    assert(block.signatures.size() == service_nodes::PULSE_BLOCK_REQUIRED_SIGNATURES);
    cryptonote::block_verification_context bvc = {};
    bool core_handled_block = core.handle_block_found(block, bvc);
    assert(core_handled_block);

    // NOTE: Generate SESH transition data if needed
    auto hf20_begins =
            cryptonote::hard_fork_begins(net, cryptonote::hf::hf20_eth_transition).value_or(0);
    if (block.get_height() == hf20_begins) {
        std::vector<service_nodes::service_node_pubkey_info> snl_list =
                core.service_node_list.get_service_node_list_state();

        oxen::log::info(
                globallogcat,
                fg(fmt::terminal_color::yellow) | fmt::emphasis::bold,
                "Mocknet generating mock transition data to the sesh network");

        // NOTE: Assume all the SN's have submitted their BLS key by mocking it in
        uint64_t next_bls_key = 0;
        for (auto it : snl_list) {
            std::shared_ptr<const service_nodes::service_node_info> sn_info = it.info;
            eth::bls_public_key bls_key = {};
            std::memcpy(bls_key.data(), &next_bls_key, sizeof(next_bls_key));
            next_bls_key++;
            globals.transition_bls_keys[crypto::ed25519_public_key{it.pubkey}] = bls_key;
        }

        // NOTE: Construct the addresses and the shares of the bonus tokens here!
    }
}

bool mocknet_is_mock_ethereum_address(const eth::address& addr) {
    bool result = addr == MOCK_ETH_ADDRESS;
    return result;
}

void mocknet_get_transition_context(oxen::sesh::transition_context& context) {
    context.conv_ratio = {1, 120};  // X SESH per Y OXEN
    context.addresses = &globals.transition_addr_map;
    context.bls_keys = &globals.transition_bls_keys;
    context.transition_bonus = &globals.transition_bonus_map;
}
#endif
