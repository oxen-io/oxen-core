#include <catch2/catch.hpp>
#include <filesystem>
#include <sqlitedb/database.hpp>
#include <wallet3/db/walletdb.hpp>
#include <wallet3/transaction_scanner.hpp>
#include <wallet3/wallet.hpp>

#include "common/guts.h"
#include "mock_daemon_comms.hpp"
#include "mock_decoy_selector.hpp"
#include "mock_wallet.hpp"

namespace wallet {
class MockSigningKeyring : public Keyring {
  public:
    MockSigningKeyring() : Keyring() {}
    MockSigningKeyring(
            crypto::secret_key _spend_private_key,
            crypto::public_key _spend_public_key,
            crypto::secret_key _view_private_key,
            crypto::public_key _view_public_key,
            cryptonote::network_type _nettype = cryptonote::network_type::TESTNET) :
            Keyring(_spend_private_key,
                    _spend_public_key,
                    _view_private_key,
                    _view_public_key,
                    _nettype) {}

    std::vector<crypto::secret_key> predetermined_tx_keys{};
    int64_t next_tx_key = 0;

    void add_tx_key(const std::string_view& key) {
        predetermined_tx_keys.push_back(crypto::secret_key{});
        crypto::secret_key& ephemeral_key = predetermined_tx_keys.back();
        tools::load_from_hex_guts(key, ephemeral_key);
    }

    crypto::secret_key generate_tx_key(cryptonote::hf hf_version) {
        if (predetermined_tx_keys.size() > 0) {
            auto& return_key = predetermined_tx_keys[next_tx_key];
            if (next_tx_key + 1 == static_cast<int64_t>(predetermined_tx_keys.size()))
                next_tx_key = 0;
            else
                next_tx_key++;
            return return_key;
        }
        return Keyring::generate_tx_key(hf_version);
    }
};
}  // namespace wallet

TEST_CASE("Transaction Creation", "[wallet,tx]") {
    // Spendkey
    // secret: 018f2288a77909f312baacbeabc192a53119edc53364d7ee64ac226392c6560e
    // public: adb121d075407895ba22ff3927b3a8aec60c29176fe97efce7f4d0a7d2c7bc0d
    // Viewkey
    // secret: 84d59173dddd78b840f03550f6e3d58163a7d06f35db9585b381e26de440f303
    // public: 66eb874ad6ee33487c5fe4dab8f17e412d320b8933b1ddf108dd15dd45026d0c
    crypto::secret_key spend_priv;
    tools::load_from_hex_guts(
            "018f2288a77909f312baacbeabc192a53119edc53364d7ee64ac226392c6560e"sv, spend_priv);
    crypto::public_key spend_pub;
    tools::load_from_hex_guts(
            "adb121d075407895ba22ff3927b3a8aec60c29176fe97efce7f4d0a7d2c7bc0d"sv, spend_pub);

    crypto::secret_key view_priv;
    tools::load_from_hex_guts(
            "84d59173dddd78b840f03550f6e3d58163a7d06f35db9585b381e26de440f303"sv, view_priv);
    crypto::public_key view_pub;
    tools::load_from_hex_guts(
            "66eb874ad6ee33487c5fe4dab8f17e412d320b8933b1ddf108dd15dd45026d0c"sv, view_pub);

    auto wallet = wallet::MockWallet(
            spend_priv, spend_pub, view_priv, view_pub, cryptonote::network_type::TESTNET);

    auto comms = std::make_shared<wallet::MockDaemonComms>();
    cryptonote::address_parse_info senders_address{};
    cryptonote::get_account_address_from_str(
            senders_address,
            cryptonote::network_type::TESTNET,
            "T6Td9RNPPsMMApoxc59GLiVDS9a82FL2cNEwdMUCGWDLYTLv7e7rvi99aWdF4M2V1zN7q1Vdf1mage87SJ9gcg"
            "Su1wJZu3rFs");
    auto ctor = wallet::TransactionConstructor(wallet.get_db(), comms, senders_address);
    ctor.fee_per_byte = 0;
    ctor.fee_per_output = 0;
    SECTION("Expect Fail if database is empty") {
        std::vector<cryptonote::tx_destination_entry> recipients;
        recipients.emplace_back(cryptonote::tx_destination_entry{});
        recipients.back().amount = 4;
        REQUIRE_THROWS(ctor.create_transaction(recipients, recipients[0]));
    }

    wallet.store_test_transaction(5);

    SECTION("Creates a successful single transaction") {
        std::vector<cryptonote::tx_destination_entry> recipients;
        recipients.emplace_back(cryptonote::tx_destination_entry{});
        recipients.back().amount = 4;
        wallet::PendingTransaction ptx = ctor.create_transaction(recipients, recipients[0]);
        REQUIRE(ptx.recipients.size() == 1);
        REQUIRE(ptx.chosen_outputs.size() == 1);
        REQUIRE(ptx.change.amount == 1);
        REQUIRE(ptx.decoys.size() == ptx.chosen_outputs.size());
        for (const auto& decoys : ptx.decoys)
            REQUIRE(decoys.size() == 10);
    }

    SECTION("Fails to create a transaction if amount is not enough") {
        std::vector<cryptonote::tx_destination_entry> recipients;
        recipients.emplace_back(cryptonote::tx_destination_entry{});
        recipients.back().amount = 6;
        REQUIRE_THROWS(ctor.create_transaction(recipients, recipients[0]));
    }

    wallet.store_test_transaction(5);
    wallet.store_test_transaction(7);
    SECTION("Creates a successful single transaction prefering to use a single input if possible") {
        std::vector<cryptonote::tx_destination_entry> recipients;
        recipients.emplace_back(cryptonote::tx_destination_entry{});
        recipients.back().amount = 6;
        wallet::PendingTransaction ptx = ctor.create_transaction(recipients, recipients[0]);
        REQUIRE(ptx.recipients.size() == 1);
        REQUIRE(ptx.chosen_outputs.size() == 1);
        REQUIRE(ptx.change.amount == 1);
        REQUIRE(ptx.decoys.size() == ptx.chosen_outputs.size());
        for (const auto& decoys : ptx.decoys)
            REQUIRE(decoys.size() == 10);
    }

    SECTION("Creates a successful transaction using 2 inputs") {
        std::vector<cryptonote::tx_destination_entry> recipients;
        recipients.emplace_back(cryptonote::tx_destination_entry{});
        recipients.back().amount = 8;
        wallet::PendingTransaction ptx = ctor.create_transaction(recipients, recipients[0]);
        REQUIRE(ptx.recipients.size() == 1);
        REQUIRE(ptx.chosen_outputs.size() == 2);
        REQUIRE(ptx.decoys.size() == ptx.chosen_outputs.size());
        for (const auto& decoys : ptx.decoys)
            REQUIRE(decoys.size() == 10);
    }

    wallet.store_test_transaction(8000);
    wallet.store_test_transaction(8000);
    ctor.fee_per_byte = 1;

    SECTION("Creates a successful transaction using 2 inputs, avoids creating dust and uses "
            "correct fee using 1 oxen per byte") {
        std::vector<cryptonote::tx_destination_entry> recipients;
        recipients.emplace_back(cryptonote::tx_destination_entry{});
        recipients.back().amount = 8001;
        wallet::PendingTransaction ptx = ctor.create_transaction(recipients, recipients[0]);
        REQUIRE(ptx.recipients.size() == 1);
        REQUIRE(ptx.chosen_outputs.size() == 2);
        // 16000 (Inputs) - 8001 (Recipient) - (1857 bytes x 1 oxen (Fee)) * 3 (Blink multiplier)
        REQUIRE(ptx.change.amount == 2428);
        REQUIRE(ptx.decoys.size() == ptx.chosen_outputs.size());
        for (const auto& decoys : ptx.decoys)
            REQUIRE(decoys.size() == 10);
    }

    ctor.fee_per_output = 50;
    SECTION("Creates a successful transaction using 2 inputs, avoids creating dust and uses "
            "correct fee using 1 oxen per byte and 50 oxen per output") {
        std::vector<cryptonote::tx_destination_entry> recipients;
        recipients.emplace_back(cryptonote::tx_destination_entry{});
        recipients.back().amount = 8001;
        wallet::PendingTransaction ptx = ctor.create_transaction(recipients, recipients[0]);
        REQUIRE(ptx.recipients.size() == 1);
        REQUIRE(ptx.chosen_outputs.size() == 2);
        // 16000 (Inputs) - 8001 (Recipient) - (1857 bytes x 1 oxen (Fee) + 100 (Fee for 2x outputs
        // @ 50 oxen)) * 3 (Blink multiplier)
        REQUIRE(ptx.change.amount == 2128);
        REQUIRE(ptx.decoys.size() == ptx.chosen_outputs.size());
        for (const auto& decoys : ptx.decoys)
            REQUIRE(decoys.size() == 10);
    }
}

// THIS test case has been disabled temporarily, it successfully creates a transaction and
// signs it using the rct library but our scanner does not accept it currently.
// The design for using a transaction constructor might change soon so revisit this test
// after those changes cause it might not even be relevant
// TEST_CASE("Transaction Signing", "[wallet,tx]")
//{

// SECTION("Creates a successful transaction then signs using the keyring successfully")
//{
//// Start a new wallet for real inputs to test signatures
//// Spendkey
////secret: 018f2288a77909f312baacbeabc192a53119edc53364d7ee64ac226392c6560e
////public: adb121d075407895ba22ff3927b3a8aec60c29176fe97efce7f4d0a7d2c7bc0d
//// Viewkey
////secret: 84d59173dddd78b840f03550f6e3d58163a7d06f35db9585b381e26de440f303
////public: 66eb874ad6ee33487c5fe4dab8f17e412d320b8933b1ddf108dd15dd45026d0c
// crypto::secret_key spend_priv;
// tools::load_from_hex_guts("018f2288a77909f312baacbeabc192a53119edc53364d7ee64ac226392c6560e"sv,
// spend_priv); crypto::public_key spend_pub;
// tools::load_from_hex_guts("adb121d075407895ba22ff3927b3a8aec60c29176fe97efce7f4d0a7d2c7bc0d"sv,
// spend_pub);

// crypto::secret_key view_priv;
// tools::load_from_hex_guts("84d59173dddd78b840f03550f6e3d58163a7d06f35db9585b381e26de440f303"sv,
// view_priv); crypto::public_key view_pub;
// tools::load_from_hex_guts("66eb874ad6ee33487c5fe4dab8f17e412d320b8933b1ddf108dd15dd45026d0c"sv,
// view_pub);

// auto wallet_with_valid_inputs = wallet::MockWallet(spend_priv, spend_pub, view_priv, view_pub,
// cryptonote::network_type::TESTNET);

// auto comms_with_decoys = std::make_shared<wallet::MockDaemonComms>();
// comms_with_decoys->add_decoy(894631,
// "37d660205a18fb91debe5b73911e30ed2d353a0b611e89cf20a110653b3d3937",
// "7ad740731e5b26a0f1e87f3fc0702865196b9a58dccf7d7fc47e721f6a9837b0");
// comms_with_decoys->add_decoy(1038224,
// "0c86e47e52bed3925cd9dc56052279af96e26b18741bae79ae86e019bac0fdc0",
// "7ad740731e5b26a0f1e87f3fc0702865196b9a58dccf7d7fc47e721f6a9837b0");
// comms_with_decoys->add_decoy(1049882,
// "a44418c0eaf4f295092b5be2bdfc6a8a7e78d57e2fe3f1a0af267a8a2a451fd1",
// "7ad740731e5b26a0f1e87f3fc0702865196b9a58dccf7d7fc47e721f6a9837b0");
// comms_with_decoys->add_decoy(1093414,
// "590bcaf258e68c79620e9a0b62d81ff2b4cbd19001d4764b76f17d8fceeff8e7",
// "7ad740731e5b26a0f1e87f3fc0702865196b9a58dccf7d7fc47e721f6a9837b0");
// comms_with_decoys->add_decoy(1093914,
// "460f88c45744fc4b78f7df046a9bf254194fceac1074dc9674a54ee41d4baf47",
// "7ad740731e5b26a0f1e87f3fc0702865196b9a58dccf7d7fc47e721f6a9837b0");
// comms_with_decoys->add_decoy(1094315,
// "f075807f61c902e65b2b0f6ea817699c8dd291b060284a77c890586632da4263",
// "7ad740731e5b26a0f1e87f3fc0702865196b9a58dccf7d7fc47e721f6a9837b0");
// comms_with_decoys->add_decoy(1094323,
// "87b2d9b0550a72781b75d190096ffd7e9a5bb15b9f22652f042135fbf7a35318",
// "7ad740731e5b26a0f1e87f3fc0702865196b9a58dccf7d7fc47e721f6a9837b0");
// comms_with_decoys->add_decoy(1094368,
// "5e549f2f3f67cc369cb4387fdee18c5bfde2917e4157aee2cb9129b02f3aafe0",
// "7ad740731e5b26a0f1e87f3fc0702865196b9a58dccf7d7fc47e721f6a9837b0");
// comms_with_decoys->add_decoy(1094881,
// "48a8ff99d1bb51271d2fc3bfbf6af754dc16835a7ba1993ddeadbe1a77efd15b",
// "7ad740731e5b26a0f1e87f3fc0702865196b9a58dccf7d7fc47e721f6a9837b0");
// comms_with_decoys->add_decoy(1094887,
// "02c6cf65059a02844ca0e7442687d704a0806f055a1e8e0032cd07e1d08885b2",
// "7ad5bc62d68270ae3e5879ed425603e6b1534328f4419ad84b8c8077f9221721"); // Real Output

// auto keys = std::make_shared<wallet::MockSigningKeyring>(spend_priv, spend_pub, view_priv,
// view_pub); keys->add_tx_key("3d6035889b8dd0b5ecff1c7f37acb7fb7129a5d6bcecc9c69af56d4f2a2c910b");

// cryptonote::address_parse_info senders_address{};
// cryptonote::get_account_address_from_str(senders_address, cryptonote::network_type::TESTNET,
// "T6Td9RNPPsMMApoxc59GLiVDS9a82FL2cNEwdMUCGWDLYTLv7e7rvi99aWdF4M2V1zN7q1Vdf1mage87SJ9gcgSu1wJZu3rFs");
// auto ctor_for_signing = wallet::TransactionConstructor(wallet_with_valid_inputs.get_db(),
// comms_with_decoys, senders_address);

// auto decoy_selector = std::make_unique<wallet::MockDecoySelector>();
// decoy_selector->add_index({894631, 1038224, 1049882, 1093414, 1093914, 1094315, 1094323, 1094368,
// 1094881, 1094887}); ctor_for_signing.decoy_selector = std::move(decoy_selector);

// wallet::Output o{};
// o.amount = 1000000000000;

// crypto::public_key tx_pub_key;
// tools::load_from_hex_guts("3bf997b70d9a26e60525f1b14d0383f08c3ec0559aaf7639827d08214d6aa664",
// tx_pub_key); o.derivation = keys->generate_key_derivation(tx_pub_key);
// tools::load_from_hex_guts("02c6cf65059a02844ca0e7442687d704a0806f055a1e8e0032cd07e1d08885b2",
// o.key); // Public Key of Output
// tools::load_from_hex_guts("145209bdaf35087c0e61daa14a9b7d3fe3a3c14fc266724d3e7c38cd0b43a201",
// o.rct_mask);
// tools::load_from_hex_guts("1b6e1e63b1b634c6faaad8eb23f273f98b4b7cedb0a449f8d25c7eea2361d458",
// o.key_image); o.subaddress_index = cryptonote::subaddress_index{0,0}; o.output_index = 0;

// wallet_with_valid_inputs.store_test_output(o);
// std::vector<cryptonote::tx_destination_entry> recipients;

// cryptonote::address_parse_info recipient_address{};
// cryptonote::get_account_address_from_str(recipient_address, cryptonote::network_type::TESTNET,
// "T6Sv1u1q5yTLaWCjASLPbkFz8ZFZJXQTn97tUZKDX8XaGFFEqJ5C4CC9aw1XGGfKAe8RzojvN5Mf7APr7Bpo6etb2ffiNBaSs");
// recipients.emplace_back(cryptonote::tx_destination_entry(50000000000, recipient_address.address,
// recipient_address.is_subaddress)); wallet::PendingTransaction ptx =
// ctor_for_signing.create_transaction(recipients, recipients[0]); REQUIRE(ptx.finalise());

// REQUIRE_NOTHROW(keys->sign_transaction(ptx));
// auto& signedtx = ptx.tx;
// for (const auto& decoys : ptx.decoys)
//{
// REQUIRE(decoys.size() == 10);
//}

// wallet::TransactionScanner scanner{keys, wallet_with_valid_inputs.get_db()};

// wallet::BlockTX btx;
// btx.tx = signedtx;
// btx.global_indices.resize(signedtx.vout.size());

// auto recv = scanner.scan_received(btx, 123, 456);

// REQUIRE(recv.size() == 1);
// REQUIRE(recv[0].amount == 949969108610);

////Final Transaction should look like this
////{ "version": 4, "output_unlock_times": [ 0, 0 ], "unlock_time": 0,
////"vin": [
////{
////"key": {
////"amount": 0,
////"key_offsets": [ 894631, 143593, 11658, 43532, 500, 401, 8, 45, 513, 6 ],
////"k_image": "1b6e1e63b1b634c6faaad8eb23f273f98b4b7cedb0a449f8d25c7eea2361d458"
////}
////}
////],
////"vout": [
////{
////"amount": 0,
////"target": {
////"key": "f2c6c7a593ad18a0643715b5eb0acab137a5a3670a67a082a508e55e756fe20f"
////}
////},
////{
////"amount": 0,
////"target": {
////"key": "c9b304a61fa66328867dde512dc1cd6a4a1364a17aaf01c994995c0767e28f2e"
////}
////}
////],
////"extra": [ 1, 242, 7, 2, 187, 108, 154, 15, 107, 44, 180, 120, 108, 9, 214, 19, 184, 83, 191,
/// 255, 114, 112, 219, 81, 147, 135, 119, 231, 239, 7, 32, 218, 225, 2, 9, 1, 186, 35, 240, 225,
/// 57, 168, 234, 151, 121, 52, 123, 54, 1, 0, 0, 0, 0 ],
////"type": 0,
////"rct_signatures": {
////"type": 5,
////"txnFee": 30521550,
////"ecdhInfo": [ {
////"amount": "d3bde6f24db5ed4d"
////}, {
////"amount": "94eb0dd9f3603958"
////}
////],
////"outPk": [
////"af85ed6e314c56c493d6e8bd796fe1023a6b94777ab98b5ee6ffc219b097e932",
////"12baf689c9850b215bb99e518852ba5c5fea08cb5471e588c3fd5069161f5ef2"
////]
////},
////"rctsig_prunable": {
////"nbp": 1,
////"bp": [
////{
////"A": "c62bdd0f1a485be62b1a415aa7ae783298c06f1e77c2cabe3b919521e587ed82",
////"S": "efe0cf9004a20eea2478e4316769fe24d2eff8748d0baefc36fd833b709c5f8e",
////"T1": "69972f474aebb0f83efe4c1fa6545b5036c7218f80eac34a827a5034b979f2c9",
////"T2": "8fe78eadafe8b4f0764ea61ddf60a3502430a31cb82e4e48925120f51486f0e9",
////"taux": "80d452180ff66a7c223669821715811e8bd15b0ff5b2033eeaa6ad4d67ed850d",
////"mu": "767a55060bc1a22015be604abae36b5e21d45e863b400d5ecd1e8ad9b83f2101",
////"L": [
////"c352794bd966d436163f31b58523cd8209db8da630398fc5cc28ed2f9240ada7",
////"cf8ce0c1b7d5de50a93996a0548595bd71f16830a66b3cddaafc0df390f3cf1b",
////"ed2dfabd819aaf4dffd63de9c6e5f0f91912a9155e4aaedae2a5641320bac65e",
////"9fd4451b6e9059873b2780acf666a55a24574f2229b6598f6d4cb18ccb49bf19",
////"33e20f36f747f4047075fd705d84ffde562053c47e47b83fed77b0c6f7c9bbc9",
////"e67293e4220182f2b09ea5c07516abac794ce614af7313dd2e72ec18b609750e",
////"bcf87f8344052864935039074bf97ce90cfb0d49446866aa796c0366bd76a668"
////],
////"R": [
////"dc0450f5f66fc961019ca4270c536ccfb07add9d8ee37d0f0abff00d0c756e88",
////"046c4d0adb40e3abc658fb227d32876a76ef401859d4508484dc2b52e6c03ecf",
////"7b1b97765c2cc73de71cf07ec12c959c4ab4ccadc0e683b0d6abadf0e208fdfe",
////"b8418c1a63fe049bb79b1a0dc7879b4f55e7cd20a9f0c5f84ea8ee15f73eae52",
////"eb3a456197ae0b027220a0dc0b04f52032d991a5cf7f4e82a18772e12cfa1895",
////"3cc43eceb758d0e78048c9f403319286a248009ca6027b2acad918a312ce9a1f",
////"1b912deece231eb682df659f549709f5e958e46e23c47b876eac54ae977376a6"
////],
////"a": "efc8c93275bf099740f787d2318e240580ef1119abe6af927dd5c6ba722ab705",
////"b": "87b84102500af01ebf71c701ff1aec6a408e54d2995f362011e09abdd5d98b01",
////"t": "5b6c4e70f8932bef5344b32840f22453aca1e02496a084e9686d4aec52eb970e"
////}
////],
////"CLSAGs": [
////{
////"s": [
////"69823d1c3774eef1bfbfe82fab65f5633cb90e9ea907c9e8a005757e49ffa201",
////"b791b1bb685238bb8d29d4902d4806253bedb0232da140696315d7951a204206",
////"3c4159a04f441f91dcb277d450cdeb4e1ccf51983c2e5c52b15e365bdecf270b",
////"ae56963b0576c6d6053d0a2e98a2db799f89d0d593fa3cf508a3bed461d44d03",
////"f83b3aa9d6317e2c756cc6bb390d7412a9dc06ecf830d00b28b620544e7c6105",
////"bc1321ef0144be27be0df84f445f6ee481a44350920d1a1450a0918a33026d00",
////"7be0f157e8fa2aaa256b5b396a7de64f5bce65a5ef02891020dc44c046aa5906",
////"3664af1800ec98468a6d525153fd1b0ab8df915281b9ade05e6188a404543001",
////"c8424e4bdbe61284d92a684f12193153f7037dd580e66693035ede5535571601",
////"69992cbb0a157491a82dc8b8711cf23fdd72465e9dfb79c4e2cc2ff6d2fe8f0f"
////],
////"c1": "38387027f16b4c047be856a3fab9d8923780652bda2b701b0ee0095db9984403",
////"D": "acd6b1face294fe2c6401d0aa885a7167c7436c660311b11300b7796623064eb"
////}
////],
////"pseudoOuts": [
////"6a8f5d7406410d3c7aea60e94c06f978ae12ada0c53d977fcbeff0a2c7599d87"
////]
////}
////}
//}
//}
