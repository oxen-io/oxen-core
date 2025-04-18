#include <oxenc/hex.h>

#include <cstdint>
#include <string>
#include <unordered_map>

#include "common/guts.h"
#include "crypto/crypto.h"
#include "crypto/eth.h"
#include "detail.h"

namespace oxen::sent::devnet {

using namespace std::literals;

const std::unordered_map<std::string, eth::address> addresses{
        {"dV3jKVomABtGr2cB75CvMciVoBsgUukBwQxdX586Q7pPKr3ohPBpH2h6QQDBG5j1D7CJBAWWamTTpbaRyPDTXFPW2nWRkwJg8"s,
         tools::make_from_hex_guts<eth::address>("0xB0CefD61ddB88176Fb972955341adC6c1d05230e"s)},
        {"dV22dkgs6Tgb1YiqwBzq8URRQ8gjzGJMd13bEt3CySkC6AVx6cnH35TSHHtHCnMf68jXHMpW68ZQ93ZxRBbUyAC929rGKPM8n"s,
         tools::make_from_hex_guts<eth::address>("0xb82Cd271CE0E498e4203AC4db801698Bd720f6AF"s)},
        {"dV1ttpi6U815NHxh8QqK5LGNfWKHzhhxoWYAznsfiQtZWuxD44Jrw4uCAXZgPGw96zB7WPsNdcBRdWx7c8ANvzDx15sNugT7G"s,
         tools::make_from_hex_guts<eth::address>("0xB7649B5A5DfABAA0713ACFB3040945035b0bBD9e"s)},
        {"dV33LyGNcFQhqe84oiMUy9SAy1suyHNEJ53prwv18iBt6Kh5cejcHZ9W842SdQZ1izaMubG6Qg7P9fjxLagV8rsj18nfVvc46"s,
         tools::make_from_hex_guts<eth::address>("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"s)},
        {"dV3YWiufwPxKFmpGbyVmQjHCyTTHeQc3ATW8XFNPymYKcoBa9Rbfj4nAaGihf4XJoqdsYnLNLSFWpJC5GJMMHyvs1Q75JiKai"s,
         tools::make_from_hex_guts<eth::address>("0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"s)},
        {"dV2y4ThUjQKdKvCKVbwW5Ni9JBjEuYb7B66Qa6AaReVX6hXKDYsabJZ1xr9w3AKtXZNHZkKsbaN5Bi3dLyrZgyDJ1VnYRqvMS"s,
         tools::make_from_hex_guts<eth::address>("0xcccccccccccccccccccccccccccccccccccccccc"s)},
        {"dV1uNumdfREEvgUhZi91frgBrApRBB7QHeuVmi6eiZSx16LXxFkkxR5DDQYV2f4VkwH19kYLuxr6g7QDd6C7zwBU1pmDCY5mP"s,
         tools::make_from_hex_guts<eth::address>("0xdddddddddddddddddddddddddddddddddddddddd"s)},
        {"dV2pBi3wvr39EH8V9izJAtMDL6J9PS4i8ApRLJWD5LcxGc2uf5ADBJ84d1pTKWu2Kt1bJ5KuaA69ncxiyiS6eaGb35f5HD84P"s,
         tools::make_from_hex_guts<eth::address>("0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"s)},
        {"dV1jxf26zLYZ9B34enQtDnLngpoLqNXxQMSM3RJvDyB4b8N6Mnjw7v4Sc9m13Jf6MfPWNcDEvwbGK93MirdHTnBH2F5Ednii9"s,
         tools::make_from_hex_guts<eth::address>("0xffffffffffffffffffffffffffffffffffffffff"s)},

};

const std::unordered_map<crypto::public_key, crypto::ed25519_public_key> proper_ed_keys{
        {tools::make_from_hex_guts<crypto::public_key>(
                 "badfee145178ace16e6e90a3b2c8cdd4ecb7c8d72daae5c7febab11777834bfb"s),
         tools::make_from_hex_guts<crypto::ed25519_public_key>(
                 "decaf14f468356ddf5441464e3b2ef84f0bc8cd6e32b0712ca2c74cdd0d7c0d6"s)},
        {tools::make_from_hex_guts<crypto::public_key>(
                 "badfee18dfed75970d729ee82a469e79be5cee3d4c3b9ddf3a97e148ddbd8d5c"s),
         tools::make_from_hex_guts<crypto::ed25519_public_key>(
                 "decaf18aa6d2008994aaa5a997e7a10f688984127c532c98cca6166e3229b7ed"s)},
};

const std::unordered_map<crypto::ed25519_public_key, eth::bls_public_key> bls_keys{
        {tools::make_from_hex_guts<crypto::ed25519_public_key>(
                 "decaf05befd9df412b26811b4021bae83ea1334c90e5b41534bf0018c17d581a"s),
         tools::make_from_hex_guts<eth::bls_public_key>(
                 "2d98ce89159f010af03e65d6f632acf01286ba8be782c0a382a361b3845e60fb020620f7edfaf900c8f71e399f54c47498fea7554b8bb5eac0e8f4e103411a71"s)},
        {tools::make_from_hex_guts<crypto::ed25519_public_key>(
                 "decaf02e5e491524214975ea6be8cc68d10ee00c28169a74db51459d593f38bd"s),
         tools::make_from_hex_guts<eth::bls_public_key>(
                 "2e415412bcaf5713a19c803fdc165a1be10209a398c02469e3dc5923c22d3d8d2784c5738c445e09926f231fffa935c5c793d42bab353bc82f4a51de0e769a43"s)},
        {tools::make_from_hex_guts<crypto::ed25519_public_key>(
                 "decaf27dcab0702924a74fe4cfb93191cdedc82ba6fa854114daf3ce91d08ec7"s),
         tools::make_from_hex_guts<eth::bls_public_key>(
                 "19cdac366fdedb95d6178a8e1e6ad7c340ffdad42315e9de0a299e2f1e2fcbc81d2c1e01f9f3bd2aca84080c8d94b5a1054e806b493086327c9e38e959ab8a4b"s)},
        {tools::make_from_hex_guts<crypto::ed25519_public_key>(
                 "decaf09c9bdf36b8ab1311fd08d1f72b9a08531fd2fd1dbc392e0d3a39616c14"s),
         tools::make_from_hex_guts<eth::bls_public_key>(
                 "1d6412899e367fb6d7ad47fa8ecee9a931e9c4691ecccd46108ef742d7000d871e8b543755823475b89e8d7fdf655c7088affecd1ecff5e370719ddec4ce34f2"s)},
        {tools::make_from_hex_guts<crypto::ed25519_public_key>(
                 "decaf01cea9acab5d457a7896d1104752b413f7de864322368820b36ea3abfff"s),
         tools::make_from_hex_guts<eth::bls_public_key>(
                 "2d567852856a3fafcae8e0959916f7575eeef90c57cfa3f091d44d25f46be5df28617917720411f6677721b32b372578ff24e541446b13ce005a1003146f9e5a"s)},
        {tools::make_from_hex_guts<crypto::ed25519_public_key>(
                 "decaf14f468356ddf5441464e3b2ef84f0bc8cd6e32b0712ca2c74cdd0d7c0d6"s),
         tools::make_from_hex_guts<eth::bls_public_key>(
                 "29325901b4ab783782b76a9dfa12c279681ccf9f55e002c6868b8fd2c8dd299b1904f80bea917fdd6fa88a0c0f667905ece8c3df05c9480db1b805bed2e181ea"s)},
        {tools::make_from_hex_guts<crypto::ed25519_public_key>(
                 "decaf26eddf3565c38a4e3c202984a64d1051d3ec1d9e2b2bf8d8f87ae865e21"s),
         tools::make_from_hex_guts<eth::bls_public_key>(
                 "2be9a939de3f6210eddb0dc0dcc2268f526264442ab549dd96e63ff20e665bd12371545393a1bc0d64508dfc96a2b2806b28210fd07f5bbdf08203b0e6d505ba"s)},
        {tools::make_from_hex_guts<crypto::ed25519_public_key>(
                 "decaf21071f98ca263e085767305166e259ada567388050ee9c2cca791df9463"s),
         tools::make_from_hex_guts<eth::bls_public_key>(
                 "2078c18f0a085196d5faf92644bdc0be47a61336f8b739ad44ca2b6fd9b6a04507b1c672c84266a061503416523ba7e820ff3db9c2705700bcab6c79cc721b7d"s)},
        {tools::make_from_hex_guts<crypto::ed25519_public_key>(
                 "decaf240fe6dcaac67c597dd835ed38195e7510a918fc1994fdad0248a56f56d"s),
         tools::make_from_hex_guts<eth::bls_public_key>(
                 "03d38d2459c589f38f8964b083f532fdb3fc69bc3ef73da5af10c8ec5cae2088295be3e7b27553a8be7947f5bf435b531494ce3313a0de9d1f9079fe14444f03"s)},
        {tools::make_from_hex_guts<crypto::ed25519_public_key>(
                 "decaf19ed14923f378960962fea11606bad4ebbb93d26e5444cabe52bf9aaa01"s),
         tools::make_from_hex_guts<eth::bls_public_key>(
                 "0147d92696a40a59a91e1e3f232a1ad2f63ba4af05a0351d3eb66dff3f715d330718cf1d5a275ab6469e388e3eac02880ea8874bf8656d425c5b1533a0576518"s)},
        {tools::make_from_hex_guts<crypto::ed25519_public_key>(
                 "decaf23ea27003819c073781f0c8ed0fc0607583c9358c75e6ca24f8dfd6065c"s),
         tools::make_from_hex_guts<eth::bls_public_key>(
                 "1876289f354a6cf606776dab77d55c6c66816384c7fbc5f1d65fb61b0c7a51601a5243ec9392caf8309f2afd5713a11b1992ca72707c05a5ab0a11d0e393677e"s)},
        {tools::make_from_hex_guts<crypto::ed25519_public_key>(
                 "decaf007f26d3d6f9b845ad031ffdf6d04638c25bb10b8fffbbe99135303c4b9"s),
         tools::make_from_hex_guts<eth::bls_public_key>(
                 "06ae80f8243810a65866117ea5089bc46b5ad757d9eb2642347242df09b86abd2a30ed9fb758960cb6d72af8d66825f1dace7f158d19ef113471e2bac849b231"s)},
        {tools::make_from_hex_guts<crypto::ed25519_public_key>(
                 "decaf18aa6d2008994aaa5a997e7a10f688984127c532c98cca6166e3229b7ed"s),
         tools::make_from_hex_guts<eth::bls_public_key>(
                 "27c81b9879eba3912f3210adb318f3760eb8947e31cd46b954ec6423bd84296f2c570f6e0312425bedf3f3211ca9353238d6fec1e87456a6d56bcbafcafd6026"s)},
        {tools::make_from_hex_guts<crypto::ed25519_public_key>(
                 "decaf15ebb580ab901a27ee9a66fb2d24d096e2ab6b63317d5b1a71fc0421cdf"s),
         tools::make_from_hex_guts<eth::bls_public_key>(
                 "1549b466ce525117b67df730a51f710b94c4373b2ef09a76e711713cfd3f744b076e548123d507451b88ed8ea4bbf161df5d8f8a0b84554fcc46177cfc7b0203"s)},
        {tools::make_from_hex_guts<crypto::ed25519_public_key>(
                 "decaf035871aa9d8e7da429f39711c349f380840ac4a305530b5a19c18793681"s),
         tools::make_from_hex_guts<eth::bls_public_key>(
                 "20fadf257f9de9032224956d1b10439eeab394012260df620e334b19f989ca462112cdedb928f9e802700f56b1c0437fd9fc2b7b095f643476533472973a3413"s)},
        {tools::make_from_hex_guts<crypto::ed25519_public_key>(
                 "decaf29e645574415c4e7418af6bb6c26d63835f814f2d6170723cb106bd4887"s),
         tools::make_from_hex_guts<eth::bls_public_key>(
                 "0bc4439474700c5bce728837e2e8aca0ec247d5d17104e83690581b1d8518e1d083d3eb405b84643733bed733a0b0f9614406787ce575e98b397e75a15cb4117"s)},
        {tools::make_from_hex_guts<crypto::ed25519_public_key>(
                 "decaf22cadf744ceeb6da989bc70442f96b2f99932f10079f0ca4ddc328faa17"s),
         tools::make_from_hex_guts<eth::bls_public_key>(
                 "2f2a7ace2655d5d5b1979910cb97b7f14bab10632a54bc6d41386de13bb5dcef1efd2f1683eaeb4baa2459ce4435149eb588000a7d1c50fbb19b7e02178e25dd"s)},
        {tools::make_from_hex_guts<crypto::ed25519_public_key>(
                 "decaf28b64c483b3ac2db08bb20219acf14aaacc21ec22f839181cf957c9079b"s),
         tools::make_from_hex_guts<eth::bls_public_key>(
                 "2be6cc35a38ad1e1862d032163639ca4c57db6da764a70083f2f94433a3b88120553bafb889af200399049994d261bafa22901a4153ffe2771a84fd53cffef8f"s)},
        {tools::make_from_hex_guts<crypto::ed25519_public_key>(
                 "decaf20025ca6389d8225bda6a32d7fc4ee5176d21e3b2e9e08c3505a48a811a"s),
         tools::make_from_hex_guts<eth::bls_public_key>(
                 "0b8ef919fcdc93249acc43089f0445b88b9994a80c9ca4c8c633db0980700e3124c24e9487f00517a53c11779b056b30e0aa8f89af44428756ad6721c48ef7b8"s)},
};

const std::pair<std::uint64_t, std::uint64_t> conv_ratio{120, 1};

const std::unordered_map<eth::address, std::uint64_t> transition_bonus{
        {tools::make_from_hex_guts<eth::address>("0xB0CefD61ddB88176Fb972955341adC6c1d05230e"s),
         64035886857040},
        {tools::make_from_hex_guts<eth::address>("0xb82Cd271CE0E498e4203AC4db801698Bd720f6AF"s),
         1658571428520},
        {tools::make_from_hex_guts<eth::address>("0xB7649B5A5DfABAA0713ACFB3040945035b0bBD9e"s),
         3577714285680},
        {tools::make_from_hex_guts<eth::address>("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"s), 0},
        {tools::make_from_hex_guts<eth::address>("0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"s), 0},
        {tools::make_from_hex_guts<eth::address>("0xcccccccccccccccccccccccccccccccccccccccc"s),
         6434285714320},
        {tools::make_from_hex_guts<eth::address>("0xdddddddddddddddddddddddddddddddddddddddd"s), 0},
        {tools::make_from_hex_guts<eth::address>("0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"s),
         76368521000000},
        {tools::make_from_hex_guts<eth::address>("0xffffffffffffffffffffffffffffffffffffffff"s),
         12345123450},
};

}  // namespace oxen::sent::devnet
