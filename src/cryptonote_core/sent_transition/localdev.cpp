#include <oxenc/hex.h>

#include <cstdint>
#include <string>
#include <unordered_map>

#include "common/guts.h"
#include "crypto/crypto.h"
#include "crypto/eth.h"
#include "detail.h"

namespace oxen::sent::localdev {

using namespace std::literals;

const std::unordered_map<std::string, eth::address> addresses{
        {"dV3ZgwAnkfmWc8YpCXPPRv3t245qpyLURJxnUbEHQT1xbTpaBLoPGFgf7XQMAPMFq4SFkPmWjyEa2YBzwSCAQa642e5Kcsypc"s,
         tools::make_from_hex_guts<eth::address>("0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"s)},
        {"dV2Rd8Tz8PB6G3A3tGyhH2ZKp4PqFV2R15hNjGBPuSq2BjMaJurSwQYQSyD2tK7bPqYgri9JDC3aK6VyMS7h3zce1Rqc5wAEb"s,
         tools::make_from_hex_guts<eth::address>("0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"s)},
        {"dV2CdxciqiR3thA2mzL3zv889pjTL8SpR7AxCe9ufpnrHCYw5qFfgiMMuLyCiRBCG8fUn6MQGzeZCWEqnUVaP8ii1MSWdaL73"s,
         tools::make_from_hex_guts<eth::address>("0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"s)},
        {"dV3NwzJKuE2a3qVeU8zKjdSLrDjb8A8WraJqS9QequnqHQqDGYRXkNr14k6WZqB3zP6Jn31fNSMopTPTVcB6rqVd1mLZbheg3"s,
         tools::make_from_hex_guts<eth::address>("0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"s)},
        {"dV2Wi24fQVYhNUTRHK3kWHUgAXsbWsH2aV5UFSY9HA9X9gy3RNzYKvSWqsqo8dBgmDSD9dCRbNAq7iuW7DyuYwYz1HmGkzUYo"s,
         tools::make_from_hex_guts<eth::address>("0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"s)},
        {"dV3mT32WJtVF5BJdZGJyWSXwPypDe6FHr9hTbnuNBL1eaqAxV4Fhoa3HfJn5jVhAtGCAWcnZRBmk1LML2zQmipZd1r2SAnpSr"s,
         tools::make_from_hex_guts<eth::address>("0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"s)},
        {"dV2iy1Vvw4PZVY4dzJcGxWe9FpKRmJPvBSKUnU4UwiUJ8JGFQCqedtwJ1MBjApt67361XFR7CdwDp2HPUXFhy5ok2dgDLXAnD"s,
         tools::make_from_hex_guts<eth::address>("0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"s)},
        {"dV3P5VFBT3CE3ZfoJ7K6fWRF79ayXbMNfNFzNebouyY3b3e1cyLdTbHJLj1JGPyuu3YFu31gBWT9NfyeJ1UwxFfR26LWQCXGs"s,
         tools::make_from_hex_guts<eth::address>("0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"s)},
        /* commented out for testing block-before-hf21 payout, but leaving here just to note that
        this
         * is one of the staking wallets in the static-startup local-devnet setup
        {"dV2zbppA4YQaDxLyFX19CudHBPyZThzcHLRADpqKLTzpWx6ngtduEk6WXmsxsoEG1p99GzHkqF5oug4g2veWJ47S1mGeDkN9f"s,
                tools::make_from_hex_guts<eth::address>("0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"s)},
        */
        {"dV3corcZMiUJWigoy8yrSGcLYUMQL5qauJwznmxMfeWTAnQMH44C6kqfetXD6dpohCChPnY4tAqBCHGciJjQjipc38AGptqJT"s,
         tools::make_from_hex_guts<eth::address>("0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"s)},
        {"dV1xdJpAVHj4gcp58UFrYaT6KGDG6HLTHBsWbvBvHZ4KTdjcfhjphyf4DWLSmV92AiFP3gqSwwx8Y1C3jVLixcaV1ngahEAih"s,
         tools::make_from_hex_guts<eth::address>("0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"s)},
        {"dV1rcFr6grybrz5V4kPh6BC1FcgYXSoaBaQsaBTK4mY4JkrUzuq2jdC4L18MkgkHzRjWzBg6WyhB7LFPCGu1Kj1f2bPZTuFfq"s,
         tools::make_from_hex_guts<eth::address>("0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"s)},
};

const std::unordered_map<crypto::public_key, crypto::ed25519_public_key> proper_ed_keys{};
const std::unordered_map<crypto::ed25519_public_key, eth::bls_public_key> bls_keys{
        {tools::make_from_hex_guts<crypto::ed25519_public_key>(
                 "eb87bc542c036ffb4167f950e229fc48009960a7ee6547f27e81c882a3e9e624"s),
         tools::make_from_hex_guts<eth::bls_public_key>(
                 "0552e55bdecf1effdcdf3c2a3907d12da083b9ce05ce795adf0d9d0c1ec8167a20640b793eb5810999f389d4069dd668b650e0ac2d636a35870db07e35a0da88"s)},
        {tools::make_from_hex_guts<crypto::ed25519_public_key>(
                 "fcef63a41b837066ca3348d9ca9583fa6d105c1e853f63eb19403f8c1132aec7"s),
         tools::make_from_hex_guts<eth::bls_public_key>(
                 "2012b63f81df7fecdcb8f9abe70825b35cac985781cf26f419d23c82181a52ef08a8a524bc9acff0933d35ffc1677a37e398d8458b99b602aee566c4a81c8a79"s)},
        {tools::make_from_hex_guts<crypto::ed25519_public_key>(
                 "4233a563748f37cdad6b0bff64bdfb7cca8520b0e52c60bdc487f76795c3f6a5"s),
         tools::make_from_hex_guts<eth::bls_public_key>(
                 "212d793ffd416c20458350c7827dbae551b1c5e1388668082308bee95c0e1404016bb5110e46b463e1eb61fe7ae88f5489907a71c3a950d370a5b8d8a63b0fff"s)},
        {tools::make_from_hex_guts<crypto::ed25519_public_key>(
                 "e6b3f9ddf6f4646a16c52309da7092aef2728de8296ec5f82a9d8f61fc1985ba"s),
         tools::make_from_hex_guts<eth::bls_public_key>(
                 "2ad19c51493553d6e0ab87ac384b10b42fe94b76d1e31fe8667104eeca05228e0fe9a621766977bf627b330f45cfb4ee1b9ef429b0a2dcf2468df1f89860d8ba"s)},
        {tools::make_from_hex_guts<crypto::ed25519_public_key>(
                 "58f6bc7a87cba310e14138ce5ca73472c4b8ff2e762ee8aebc1264bd20b077b0"s),
         tools::make_from_hex_guts<eth::bls_public_key>(
                 "302c7cf9f10a82b842a4ec4a33491e3c2b7991f30212c2855307e2abc7394ecf03d6b8e86376718bbe7779c6a3b2409729d3e1a0a0d3330bf509ca86ae51d6c7"s)},
        {tools::make_from_hex_guts<crypto::ed25519_public_key>(
                 "5436c13d55076b160e8840381cf597a6a36b0db09b3782d575a0759ec5d44f90"s),
         tools::make_from_hex_guts<eth::bls_public_key>(
                 "0e19dd7504c2ac59cc56feb0c0e604105ec3ec6af3cd734ce134658ed73dbba32964837b2414b56c286814a96c0bd01a39411f17ffb6d98dee7c836133aacc1c"s)},
        {tools::make_from_hex_guts<crypto::ed25519_public_key>(
                 "17c0988c25165b9e0fb227cb3b81c9e530d2d7113585251782235b15a260b63c"s),
         tools::make_from_hex_guts<eth::bls_public_key>(
                 "1ab996803ab1f20d375f708ebb86fab164d071646fe1f34cb1c6f813a28c40b91e1eef20aa3060291edc85fe795d189c1f1b048ffa495338a9584fce9bbe63b7"s)},

        {tools::make_from_hex_guts<crypto::ed25519_public_key>(
                 "1b9d2a6fa0ac84f86bfabe95f291c17f4662dbbd1e91f4f7c5ea606c1f78c006"s),
         tools::make_from_hex_guts<eth::bls_public_key>(
                 "1c10193d274f489dd5f8d7bbf2e67f1afdb12cd30997974eeadbd081e352d92922b03da2289d8b346aa257c9d4c429581e8dec5f1ceb6d36b416231c623b3d46"s)},
        {tools::make_from_hex_guts<crypto::ed25519_public_key>(
                 "c5dc55b6a87249e3cab17ee64801de9f6923159cb9c688c7c6614e4a5c2678be"s),
         tools::make_from_hex_guts<eth::bls_public_key>(
                 "1e4ab84357d6418943b3c60d4c1aed8e027d03e54205fd72e0fcb2a0d1c3b049059f5d1739f240b880532f4ad9dab5b38c3e20618ee6337e2560a7737d05cdee"s)},
        {tools::make_from_hex_guts<crypto::ed25519_public_key>(
                 "043ec86c4c30e881f03158500f23058651f42cd1a1520f618e83fb631b94d58e"s),
         tools::make_from_hex_guts<eth::bls_public_key>(
                 "19c19f6571eb72b4c95a4429b4aac446b5b45ae17ccb3e44eac52934d170908714c9d69be1a4c69a205e85a1192c758bf5311df2fe4d6a6d187364b1a2bd1abe"s)},
        {tools::make_from_hex_guts<crypto::ed25519_public_key>(
                 "602dceac3af2f25e07bf07d04ff0ad4d1b69e7f7e574a4a34d5f1c4296d71475"s),
         tools::make_from_hex_guts<eth::bls_public_key>(
                 "28672f3186c133f9c68ffb211ee53b7c3e6813424d6210cc72053f18f7db4a960085382d80192032d535e14eaaef09edd7cdd2be81d8042cf895e836c92cc666"s)},
        {tools::make_from_hex_guts<crypto::ed25519_public_key>(
                 "7dbe4019361d7f3e4e5d563ce7ce39f41762f042ebe74583045b278b69834eaa"s),
         tools::make_from_hex_guts<eth::bls_public_key>(
                 "103ab6907d096c0619be78e46119b4d362d65c6e27a9308fd41cc039e4cd74640e655d859353799f74896fe29de484c577757e8d56df7ade3c0622901dcc8a59"s)},
        //        {tools::make_from_hex_guts<crypto::ed25519_public_key>(""s),
        //                tools::make_from_hex_guts<eth::bls_public_key>(""s)},

};

const std::pair<std::uint64_t, std::uint64_t> conv_ratio{
        180, 1};  // worse than 200:1, so bonus required to transition

const std::unordered_map<eth::address, std::uint64_t> transition_bonus{

        {tools::make_from_hex_guts<eth::address>("0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"s),
         12345123450},
        /*
                {"0xB0CefD61ddB88176Fb972955341adC6c1d05230e"s, 292553191489},
                {"0xB7649B5A5DfABAA0713ACFB3040945035b0bBD9e"s, 388297872340},
                {"0xb82Cd271CE0E498e4203AC4db801698Bd720f6AF"s, 319148936170},
        */

};  // Actual bonus total: 999.999999999 of target 1000.000000000

/*
{
  "primary": "decaf02e5e491524214975ea6be8cc68d10ee00c28169a74db51459d593f38bd",
  "ed": "decaf02e5e491524214975ea6be8cc68d10ee00c28169a74db51459d593f38bd",
  "bls":
"2cd44bf26026518cbf26075966c0a23600f295f6e19b5bb575d9e0932e02d3890b63bba12db33d7d4880e2e565507a97d9d334cfbdc246cab017d4b6fb3fd841"
}
{
  "primary": "decaf05befd9df412b26811b4021bae83ea1334c90e5b41534bf0018c17d581a",
  "ed": "decaf05befd9df412b26811b4021bae83ea1334c90e5b41534bf0018c17d581a",
  "bls":
"09a39c32bf3c25bb7644597c230d8902240c636d0d082560198214297cd2b7180d8abb3184f0e48e88a2daac510bb6db7bf21eb5f01175e57951fc3a0ea6839f"
}
{
  "primary": "decaf11a21280b64bc1288a9e712774afda213fe6a296e8566de059fdebc111f",
  "ed": "decaf11a21280b64bc1288a9e712774afda213fe6a296e8566de059fdebc111f",
  "bls":
"190c4a4f5928b5332d64eb58187484722bea2769e3aeeb5b74672eb5f52a906423a85e32726f70ba5866e180e3c4fe8ad405cadd2ead439a21053f451d2073c4"
}
{
  "primary": "decaf16be0059bd818d6203139bc322446baa44195db5cafd0ef6b0ee502eae9",
  "ed": "decaf16be0059bd818d6203139bc322446baa44195db5cafd0ef6b0ee502eae9",
  "bls":
"01aa32391511c50e9e84c0bec59419c6a7d5f1c031074af545afff3840e7d46f0f2a2d885c1a1799f2e309cfb5f6bec28fbf020da2a010cd8939f5c6c933baba"
}
{
  "primary": "decaf21071f98ca263e085767305166e259ada567388050ee9c2cca791df9463",
  "ed": "decaf21071f98ca263e085767305166e259ada567388050ee9c2cca791df9463",
  "bls":
"18be7859ac1ffe1e5869c10516db83cc4484bab5b0b89ce5ff91940449b2380d0f2640e4fe4348a914e827c5143f22eaca1ffa33ef8dc1ca1f274d2231d8c19f"
}
{
  "primary": "decaf10b793034846d75e7c47c0779be782dda63cc9090701b2b5bc423461319",
  "ed": "decaf10b793034846d75e7c47c0779be782dda63cc9090701b2b5bc423461319",
  "bls":
"25f4871dbfd67f6b50faf5ff9ee95caefdcfe286c89511c58223d0001d51e21116c1f0726773f0892c7d13d647ae485dbda7b7bdb9fb24421223b1adfd5c5768"
}
{
  "primary": "decaf035871aa9d8e7da429f39711c349f380840ac4a305530b5a19c18793681",
  "ed": "decaf035871aa9d8e7da429f39711c349f380840ac4a305530b5a19c18793681",
  "bls":
"1e09e44466a15901de17d4e646343345120c6180779215b6ecdacdd05e4e067029844bda2f789facf57a8f86dc4238a409681e65106679f3073242bd9c989670"
}
{
  "primary": "decaf20025ca6389d8225bda6a32d7fc4ee5176d21e3b2e9e08c3505a48a811a",
  "ed": "decaf20025ca6389d8225bda6a32d7fc4ee5176d21e3b2e9e08c3505a48a811a",
  "bls":
"2911d78884aeb97dd0fb7f48273e2bf6c8ed5dc987ae9e318a33b34484db167b092f19aae799efd59e5ff713c802fa13600420b698d7aa505ff7d1c349c42925"
}
{
  "primary": "decaf04344f4865e0dfd6bf4dddcb84d242515718c6fb9000cd02a5d18ab6182",
  "ed": "decaf04344f4865e0dfd6bf4dddcb84d242515718c6fb9000cd02a5d18ab6182",
  "bls":
"1215c1ad0e10c44ab92fd108ef13ae933611cd939457dd1c7079dbda2cef05990e715b6b5f0b22b39bfec2d9e3f4a4917adb3b194d4ef35d8fa98426952e8561"
}
{
  "primary": "decaf06b895d5cf6b26d2e8d7de807d9e43a048d683d10d930949a654f3dd09e",
  "ed": "decaf06b895d5cf6b26d2e8d7de807d9e43a048d683d10d930949a654f3dd09e",
  "bls":
"235ea3af01d7d1c15cc7661ff0ab656de62dd6bbe3c2843d8517dfc0ac9ff7d30412024ee55cb4fc0492c3388e842469857a04dfaa40b72fb79556d27d608cd7"
}
{
  "primary": "decaf12347f661a26a1c144227c83874da532cdc1d356c5b77089f686b1f1ca0",
  "ed": "decaf12347f661a26a1c144227c83874da532cdc1d356c5b77089f686b1f1ca0",
  "bls":
"0c850d2b85820cacf90a777962db26f5bec6859696f7d5ef4bcf503e39ae2e392c97849ba38f2e2c10b9c40718be3db6ecd065c79b996411073d6af3e86965b0"
}
{
  "primary": "decaf18aa6d2008994aaa5a997e7a10f688984127c532c98cca6166e3229b7ed",
  "ed": "decaf18aa6d2008994aaa5a997e7a10f688984127c532c98cca6166e3229b7ed",
  "bls":
"21487b9a6f324bcfd4661968c2af972fc16bae33cbf0b3e90a4f7432c82d2efe079d4b18d3ccf446d410e2a87016efca4df2f612cb7a17602a9d9bb87a6e1248"
}
{
  "primary": "decaf01cea9acab5d457a7896d1104752b413f7de864322368820b36ea3abfff",
  "ed": "decaf01cea9acab5d457a7896d1104752b413f7de864322368820b36ea3abfff",
  "bls":
"242db412539dfe3c2e887322cf72d6a0c98abd891e5e71d568aa1237a9174a7c287367a71bfe0ebf87d2c725b59cedeb061c8ad908b2531be9a219ebcc735913"
}
{
  "primary": "decaf131572d20fe7b0cb07a8a4e56611818d22235bcf0c00dc1d0443dfdd8b2",
  "ed": "decaf131572d20fe7b0cb07a8a4e56611818d22235bcf0c00dc1d0443dfdd8b2",
  "bls":
"0d72b0eee84703ea34db03060d188636d85ef0283ef6a737a26cd98e2f19a64f2a795ee962ed26774d2e85aa066097d0dea3d326368564a85d06539a469acc19"
}
{
  "primary": "decaf07a5acbf52d36b9105a7179bc3ad09ebb5020ca6241f54445cff9590f93",
  "ed": "decaf07a5acbf52d36b9105a7179bc3ad09ebb5020ca6241f54445cff9590f93",
  "bls":
"1f33e3fe8dec061e66fe281914d3f480c48935bb0dfb3a5d7836538a1837fe7600e1b2621993a06a93404e6e77340dbb38f94237b9eec7b7ba657ce000999fcf"
}
{
  "primary": "decaf007f26d3d6f9b845ad031ffdf6d04638c25bb10b8fffbbe99135303c4b9",
  "ed": "decaf007f26d3d6f9b845ad031ffdf6d04638c25bb10b8fffbbe99135303c4b9",
  "bls":
"2ffaab5e208caa4cd35260103aa1b28bdae0e26d7070e4da0cdfc90e50c570ea1bb447210f2657e523394f26fcc001573c299be5aa58ec02d5cffb85476ab92a"
}
{
  "primary": "decaf17f27fc92e4f36742e1c545c0be30904f3d30a482f9a13d26ce5b7b9b6a",
  "ed": "decaf17f27fc92e4f36742e1c545c0be30904f3d30a482f9a13d26ce5b7b9b6a",
  "bls":
"22ac98688d55a7c39c1eb9f87b44d5357d28ef497a7e77d9232e3c49b51d350b13168095044d500aeb95736b16f120a9ad5cfaaf79787939cf18aa80cce70290"
}
{
  "primary": "decaf19ed14923f378960962fea11606bad4ebbb93d26e5444cabe52bf9aaa01",
  "ed": "decaf19ed14923f378960962fea11606bad4ebbb93d26e5444cabe52bf9aaa01",
  "bls":
"295b6b8851e331b2ef973af9ef1b2989ab25b9508d95b9fc48a3b6946b62156b0d8b18be4b067cf7931790fd57d4532efcb3c4d81d0dd32ca862ce90784bf996"
}
 */

}  // namespace oxen::sent::localdev
