#include <oxenc/hex.h>

#include <cstdint>
#include <string>
#include <unordered_map>

#include "common/guts.h"
#include "crypto/crypto.h"
#include "crypto/eth.h"
#include "detail.h"

namespace oxen::sent::testnet {

using namespace std::literals;

const std::unordered_map<std::string, eth::address> addresses{
        {"T6TSSZFiy74HzC41GNtXP4RLECdbV2YFsQ3fDbZGyF3mgHh5FoEia593CYAmsfzRsub2nXsB1xK7rFbWgW7dTmgf1eFvt7Mya"s,
         tools::make_from_hex_guts<eth::address>("0xB0CefD61ddB88176Fb972955341adC6c1d05230e"s)},
        {"T6Sc6yPqH75FX8R7ENGiksMA2oJkEzH985i4gQVeoUpw4ERTG3yuzpghGRbjZ8REh1bpqq4qE8Nut25bAcd9npJL283WQ3o9d"s,
         tools::make_from_hex_guts<eth::address>("0xB0CefD61ddB88176Fb972955341adC6c1d05230e"s)},
        {"T6SzmUAGfmaJQMtX8jxTLaGJgzXD6YLiePgGmg9PS3YMCcfvEmWUt8sadoZQkDhtamiEFX4t6tdjh2rKcSc3Hugr2zV9EvdeB"s,
         tools::make_from_hex_guts<eth::address>("0xB0CefD61ddB88176Fb972955341adC6c1d05230e"s)},
        {"T6TXLNZL3Hjg8VK3NfaGPqAH38a6T7BRKMNTKQ8ZaVUGPaNNG9m3MKs7DVC29VMdZMWD1EQrVSqkUGamyjmb5ZRj2h5D6mEac"s,
         tools::make_from_hex_guts<eth::address>("0xb82Cd271CE0E498e4203AC4db801698Bd720f6AF"s)},
        {"T6TxKpWqmokjGRf2wvX9cMegXcywCA8aiFq9UEHeFjpBiHLiKr2q3xnR1RsE5ky6UDNhRpWm7Vd1hZYEpeLofA5P1fAxML1eD"s,
         tools::make_from_hex_guts<eth::address>("0xB0CefD61ddB88176Fb972955341adC6c1d05230e"s)},
        {"T6TwBFTzXcQe4qG3PNZTv54s9cC9ber4zEcjaTK4Z2ty36wiA5cPCNW5HvZE4wt2i97B417MmRLQ6gRSShNGj4J72aHRb9CL2"s,
         tools::make_from_hex_guts<eth::address>("0xB0CefD61ddB88176Fb972955341adC6c1d05230e"s)},
        {"T6Swaxm6LGsgSgXJSMwf5pEbCk7adnMbeTs3z9PNoj98LLxZaUNKEtyYF3hKaHrJY9U4XBP1UnsfuVBu87zL5gXr21qq6eKKj"s,
         tools::make_from_hex_guts<eth::address>("0xB0CefD61ddB88176Fb972955341adC6c1d05230e"s)},
        {"T6THE6fvpP3aozo7DbH6uu86cfwHPQKUxUcRwSYWD8HX5ygcRefFkyti2n9kDMJEoUNafEnPTNVsiQARCjno8MqG1mu2eCFQG"s,
         tools::make_from_hex_guts<eth::address>("0xb82Cd271CE0E498e4203AC4db801698Bd720f6AF"s)},
        {"T6SRX3ZRd9V8EAtfycowxMCrtLeEVt5vxe4cCyfcofAkGHcTnbQbyZzHjJ4syqAaiR4ZhuhBynubQQJ2gMQFAAxg1ByvT6KRu"s,
         tools::make_from_hex_guts<eth::address>("0xB0CefD61ddB88176Fb972955341adC6c1d05230e"s)},
        {"T6U7YGUcPJffbaF5p8NLC3VidwJyHSdMaGmSxTBV645v33CmLq2ZvMqBdY9AVB2z8uhbHPCZSuZbv68hE6NBXBc51Gg9MGUGr"s,
         tools::make_from_hex_guts<eth::address>("0xB0CefD61ddB88176Fb972955341adC6c1d05230e"s)},
        {"T6UAgQc8sfR5aDXbcuX5fDetbLQpzfaaDVkz6C87ST9HZ35V9gpnwQ5JVVX5AAe9QhBYzEnqBZcHQhqPwrYHyuoV39DmpNvyJ"s,
         tools::make_from_hex_guts<eth::address>("0xB7649B5A5DfABAA0713ACFB3040945035b0bBD9e"s)},
        {"T6TgN5JWZYP8bzvju2sPnHZi79xT3z3UZQb1EZ7jnV8HSME5jCCn74LZZWtaKHtxqK8Sd8xXnVBxg9t9vgZL1muK35iWjZQei"s,
         tools::make_from_hex_guts<eth::address>("0xB7649B5A5DfABAA0713ACFB3040945035b0bBD9e"s)},
        {"T6TQtW85azZD4aZYE7yjUsbPCH6FCP2G35sT3xUJSckjeTWvqzex7PRHxg8QzFRfTKV3EVLEmUtQWavsV7rLCwdJ1vHiwtE9r"s,
         tools::make_from_hex_guts<eth::address>("0xB7649B5A5DfABAA0713ACFB3040945035b0bBD9e"s)},
        {"T6SDxPqij1SCVuQngE1gcvTB5hewtHaGfX3N7S8fq3bfNCx3VuKhgbQcwJC2d4euWc5HcgFfFD2Kb575YDMQej7p2XgzC7n5R"s,
         tools::make_from_hex_guts<eth::address>("0xB7649B5A5DfABAA0713ACFB3040945035b0bBD9e"s)},
        {"T6SzBDzFwNxf81jjc3fB7nhFKSRr8ZJ5pCNtEsxz1vYNSGrmpBMxNZGYZKYpajvmRwbDj2ciHUnG49K3RHb3UCRS1FHukhN9H"s,
         tools::make_from_hex_guts<eth::address>("0xB7649B5A5DfABAA0713ACFB3040945035b0bBD9e"s)},
        {"T6TRcVzjAXiF4VBpxq5Yfk7mNJ7nPSVYFGR3zR7afdPBY63yKSzSm1Ca9NP4Q2suJUSF2pxhMeqKuJcbphVuCUDD1wsasYWpL"s,
         tools::make_from_hex_guts<eth::address>("0xB7649B5A5DfABAA0713ACFB3040945035b0bBD9e"s)},
        {"T6SgE3UwuB773QHVq7NDQ4QRNRyezGSBFTnPGZRz6H1T2XogQEG3pQ4b83AD1savr42r3j56UP16k58XmP3GWq8o2evtxsDHY"s,
         tools::make_from_hex_guts<eth::address>("0xB7649B5A5DfABAA0713ACFB3040945035b0bBD9e"s)},
        {"T6SMzKQ5S9KBwdB7ehu43PWMQDhcZjKGcfqBbaCCvzmgCTHPuPxLc9BNAccsnHKguiHYkBb8VwwxYPnBy5pN29Q42tadfBTQL"s,
         tools::make_from_hex_guts<eth::address>("0xB7649B5A5DfABAA0713ACFB3040945035b0bBD9e"s)},
        {"T6UCruB8Zovcyrbk8g3PMDPJEs6fC3XZwZ2RUY4iKjoChL5FZNEht953nYCxyeP5VmcZXSHXnN3Yi7sXLw6aRgCc14hzzqZ1a"s,
         tools::make_from_hex_guts<eth::address>("0xB7649B5A5DfABAA0713ACFB3040945035b0bBD9e"s)},
        {"T6SJdAiu1RUejh1XNgPH3yGE2pXBin3iQJcMFxAi6BrbC9fhNSBUpcGgZ1JZnacn7fKTJhom3wspHJtSwWspX1bM2sj92ZFkx"s,
         tools::make_from_hex_guts<eth::address>("0xb82Cd271CE0E498e4203AC4db801698Bd720f6AF"s)},
        {"T6Si1Nx6W1Wd9PMYZmJUzBBzzehhiqAmoSmotUbzoiaQTyhSYQNsmP1LsDGofwRyiUVrLPgTZTgkQVF52uMjNCq32huT1aVAJ"s,
         tools::make_from_hex_guts<eth::address>("0xb82Cd271CE0E498e4203AC4db801698Bd720f6AF"s)},
        {"T6SoZfYnck8id92aLQP3DBbp8ugBXnMCvaiBbD5dbqkp9n4DW1zZFjfGSKPbfpAXQ8H9bskNQgrcAFm81qhy2dSs2UBVrvJ7g"s,
         tools::make_from_hex_guts<eth::address>("0xb82Cd271CE0E498e4203AC4db801698Bd720f6AF"s)},
};

const std::unordered_map<crypto::public_key, crypto::ed25519_public_key> proper_ed_keys{};

const std::unordered_map<crypto::ed25519_public_key, eth::bls_public_key> bls_keys{
        {tools::make_from_hex_guts<crypto::ed25519_public_key>(
                 "decaf02e5e491524214975ea6be8cc68d10ee00c28169a74db51459d593f38bd"s),
         tools::make_from_hex_guts<eth::bls_public_key>(
                 "0f56737ebeca51a3595f1b8296b39bc591043f8265bc63a2c208f3da8dcc6886008dd4abab25f0c21fa6d70bad64441851dc195b2644f077401d7c2d69a83457"s)},
        {tools::make_from_hex_guts<crypto::ed25519_public_key>(
                 "decaf09c9bdf36b8ab1311fd08d1f72b9a08531fd2fd1dbc392e0d3a39616c14"s),
         tools::make_from_hex_guts<eth::bls_public_key>(
                 "13fa55785c52af4095c3a1fb9490f1addbf64b57bd313ec0cd2228a4766530ce202cb16f7acd6c03f02cd7fb029c357e5b028ff80fe00cda3e3ad1f5b1872815"s)},
        {tools::make_from_hex_guts<crypto::ed25519_public_key>(
                 "decaf05befd9df412b26811b4021bae83ea1334c90e5b41534bf0018c17d581a"s),
         tools::make_from_hex_guts<eth::bls_public_key>(
                 "261806bf3790ecb1c812bc4eb370747aa67a1bc74c3f7c01d4074c583815b13b078b8a21d197784f438d1a8bf1f43b330552daffcb8f41792f1dbd7408f5ebd2"s)},
        {tools::make_from_hex_guts<crypto::ed25519_public_key>(
                 "decaf131572d20fe7b0cb07a8a4e56611818d22235bcf0c00dc1d0443dfdd8b2"s),
         tools::make_from_hex_guts<eth::bls_public_key>(
                 "0d61af31b345a052b39ddcf2ae70d87a71843ba254d6881cb7b7d04e2bd6928428ae46bde09f9589a9f52715c3f6bd81781146ba9d9f8f8f758d75838289f92a"s)},
        {tools::make_from_hex_guts<crypto::ed25519_public_key>(
                 "decaf04344f4865e0dfd6bf4dddcb84d242515718c6fb9000cd02a5d18ab6182"s),
         tools::make_from_hex_guts<eth::bls_public_key>(
                 "2fc9f0d8311fd17ada08e4dcdc44537263888014a0b84d2c0c39a39b2c425a9c2489db104564126933165710de2631e1a44fbe1871f55950e7f09eed11fbde4a"s)},
        {tools::make_from_hex_guts<crypto::ed25519_public_key>(
                 "decaf20025ca6389d8225bda6a32d7fc4ee5176d21e3b2e9e08c3505a48a811a"s),
         tools::make_from_hex_guts<eth::bls_public_key>(
                 "12f6822ce81ae16e57b9187d39e42df8478412295c560e41bfd237e06e0524b8224a06fbf31baa6473c9353998ece16bd964b753a78be7a8a8732ac2315c24f1"s)},
        {tools::make_from_hex_guts<crypto::ed25519_public_key>(
                 "decaf035871aa9d8e7da429f39711c349f380840ac4a305530b5a19c18793681"s),
         tools::make_from_hex_guts<eth::bls_public_key>(
                 "248f7b166a41930026c28ee0bb32597d35218a6ca5f731eafdee4ef15b9d9cbd285e7661780bbf60195fe65028335a87a9e5ea7345fb623cb7d7398c2dba06a4"s)},
        {tools::make_from_hex_guts<crypto::ed25519_public_key>(
                 "decaf10b793034846d75e7c47c0779be782dda63cc9090701b2b5bc423461319"s),
         tools::make_from_hex_guts<eth::bls_public_key>(
                 "04ec7d59f7c3babb6661aaa0fecd18c1df1e023d39414dc06d30e63667c48bb012dc2015af67b9dc9d40e4d014c691a9f49219d07e2c3276b7ce72996b3fa04f"s)},
        {tools::make_from_hex_guts<crypto::ed25519_public_key>(
                 "decaf11a21280b64bc1288a9e712774afda213fe6a296e8566de059fdebc111f"s),
         tools::make_from_hex_guts<eth::bls_public_key>(
                 "14f52529e7194b62d8747a21be3ea4f0de99cbf71bf6beba45e668680cb1e4fb0b1ea720b1333de5d33354739e1be3259078d27b9c33e4045af5dee976ca5f28"s)},
        {tools::make_from_hex_guts<crypto::ed25519_public_key>(
                 "decaf21071f98ca263e085767305166e259ada567388050ee9c2cca791df9463"s),
         tools::make_from_hex_guts<eth::bls_public_key>(
                 "251046ddca6ab7d29020599c70234441bfb1f4b92b2966ebd78b40cc5da7b8a90fb911bc76d65844ad9b074b964e69a6613a7037c5911a1282a9f7b9fd4e42c8"s)},
        {tools::make_from_hex_guts<crypto::ed25519_public_key>(
                 "decaf08ad1f68cae3ffbc25276beb7ddb47155ff61c9abc16e58912f3a334a1c"s),
         tools::make_from_hex_guts<eth::bls_public_key>(
                 "227214d71e989538c675bf32d2914750ae4a9b1d83a403b120c7fa867845318708c92a3f530500c4045421aa9f448ba7018ee98664341d94632da5dba432cfc5"s)},
        {tools::make_from_hex_guts<crypto::ed25519_public_key>(
                 "decaf19ed14923f378960962fea11606bad4ebbb93d26e5444cabe52bf9aaa01"s),
         tools::make_from_hex_guts<eth::bls_public_key>(
                 "303f9784641b6468a8a901c247073b08cb987e4fd7134ad6a7119b5c1736d70f29d82f576c78ebe1ddb7644307326bbf9a640f1db838157ed38628046706c6a0"s)},
        {tools::make_from_hex_guts<crypto::ed25519_public_key>(
                 "decaf12347f661a26a1c144227c83874da532cdc1d356c5b77089f686b1f1ca0"s),
         tools::make_from_hex_guts<eth::bls_public_key>(
                 "2db616430abd6c9a85d404374f3be20e088bb62158f60d46a6fcdea2720b05e919bbbf37e60926d994934ec4f39612a1da3a8cecd2ddb9e00b4fab4566dc0c0f"s)},
        {tools::make_from_hex_guts<crypto::ed25519_public_key>(
                 "decaf15ebb580ab901a27ee9a66fb2d24d096e2ab6b63317d5b1a71fc0421cdf"s),
         tools::make_from_hex_guts<eth::bls_public_key>(
                 "0075fb3d8a6be6c9eaa8efe3f32f770a3969525eb9b02488f9adedeaed4367a106d70a85599ff707fc29950c9a08970381f08572667cb2ddd7efa43883de9da0"s)},
        {tools::make_from_hex_guts<crypto::ed25519_public_key>(
                 "decaf14f468356ddf5441464e3b2ef84f0bc8cd6e32b0712ca2c74cdd0d7c0d6"s),
         tools::make_from_hex_guts<eth::bls_public_key>(
                 "20cc8fbc39c4a85cf468a5348724a74b0e7987b0b7a39fdd55ec4a8500170005195d5824756044ca204871bbcabf8ebd1418f513a023d0cd5981a552bea519ae"s)},
        {tools::make_from_hex_guts<crypto::ed25519_public_key>(
                 "decaf01cea9acab5d457a7896d1104752b413f7de864322368820b36ea3abfff"s),
         tools::make_from_hex_guts<eth::bls_public_key>(
                 "0e7c88e61ce585592f73750e3942dcdb480ad48c03ae56ba39f3d6ca4fa0594a17c593dd8f28cbd0da7ff3e6e2c0fe357a35b1e3d6bfce38d88bb2e2ba91fa30"s)},
};

const std::pair<std::uint64_t, std::uint64_t> conv_ratio{180, 1};

const std::unordered_map<eth::address, std::uint64_t> transition_bonus{
        {tools::make_from_hex_guts<eth::address>("0xB0CefD61ddB88176Fb972955341adC6c1d05230e"s),
         123451234512},
        {tools::make_from_hex_guts<eth::address>("0xB7649B5A5DfABAA0713ACFB3040945035b0bBD9e"s),
         33334444222},
        {tools::make_from_hex_guts<eth::address>("0xb82Cd271CE0E498e4203AC4db801698Bd720f6AF"s),
         4206900}};

}  // namespace oxen::sent::testnet
