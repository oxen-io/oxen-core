// Copyright (c)      2018, The Loki Project
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#include "service_node_deregister.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_basic/verification_context.h"
#include "cryptonote_basic/connection_context.h"
#include "cryptonote_protocol/cryptonote_protocol_defs.h"
#include "cryptonote_core/blockchain.h"

#include "misc_log_ex.h"
#include "string_tools.h"

#include <random>
#include <string>
#include <vector>

#undef LOKI_DEFAULT_LOG_CATEGORY
#define LOKI_DEFAULT_LOG_CATEGORY "service_nodes"

namespace loki
{
  namespace xx__service_node
  {
    std::vector<crypto::secret_key> secret_view_keys;
    std::vector<crypto::public_key> public_view_keys;
    std::vector<crypto::secret_key> secret_spend_keys;
    std::vector<crypto::public_key> public_spend_keys;

    const char *deregister_cmd = "xx__deregister_service_node partial 42d0681beffac7e34f85dfc3b8fefd9ffb60854205f6068705c89eef43800903";

    const char *secret_spend_keys_str[] =
    {
      "42d0681beffac7e34f85dfc3b8fefd9ffb60854205f6068705c89eef43800903",
      "51256e8711c7d1ac06ac141f723aef280b98d46012d3a81a18c8dd8ce5f9a304",
      "66cba8ff989c3096fbfeb1dc505c982d4580566a6b22c50dc291906b3647ea04",
      "c4a6129b6846369f0161da99e71c9f39bf50d640aaaa3fe297819f1d269b3a0b",
      "165401ad072f5b2629766870d2de49cda6d09d97ba7bc2f7d820bb7ed8073f00",
      "f5fad9c4e9587826a882bd309aa4f2d1943a6ae916cf4f9971a833578eba360e",
      "e26a4d4386392d9a758e011ef9e29ae8fea5a1ab809a0fd4768674da2e36600e",
      "b5e8af1114fbc006823e6e025b99fe2f25f409d69d8ae74b35103621c00fca0c",
      "fe007f06f5eac4919ffefb45b358475fdfe541837f73d1f76118d44b42b10a01",
      "0da5ef9cf7c85d7d3d0464d0a80e1447a45e90c6664246d91a4691875ad33605",
      "49a57a4709d5cb8fb9fad3f1c4d93087eec78bc8e6a05e257ce50e71d049260b",
      "9aa18f77f49d22bb294cd3d32a652824882e5b71ffe1e13008d8fbe9ba16970c",
      "4a7f7bffd936f5b5dc4f0cdac1da52363a6dbd8d6ee5295f0a991f2592500e07",
      "118b5a3270358532e68bc69d097bd3c46d8c01a2183ee949d130e22f3e4a1604",
      "627cea57ea2215b31477e40b3dbf275b2b8e527b41ad66282321c9c1d34a0c06",
      "70c4ca12d1c12d617e000b2a90def96089497819b3da4a278506285c59c62905",
      "e395f75700e3288ea62b1734bf229ed56f40eb891b6e33a231ac1e1366502208",
      "9e6cd8667ef8f0e2b527678da80af2d34eb942da8877b1d21c3872e8f3e6b605",
      "e86dc61f76023c370feb9d086b3369dce764058ff4523c9c1d1a44957910f809",
      "d17c568d4e6662c67920b618436435a837241a8ccafad6684016f4371b4d6d07",
      "97c416757a07054d505e7ef2ebebc920e19f2a88b05dd0c58d39de5b9bf10405",
      "be5a0079f52509be69afadabd58a969fb439772ddf58ff3fedc3e6d9acbd0807",
      "cf43ebaacecc33591ddbd985ee7a637de665a275099d0777c84b358408a50d00",
      "6aa670f687da3026a836faecaaa2178442414e89dba8559600977ced60bda009",
      "2ad782d57e3d5e500cf9025ec981c4212c76662fb6a98fa1726438246dbb1602",
      "82a3b1d1ce260680a7ffe485f383fbd423d93e3f64232ef1c8ee40f05465540e",
      "627b6b28e2b89d1d28a6084fc8adf1f1859d299fd4507332a0bd410ace67860d",
      "a4092b42c1e8b08c86a7b6ed0719a25715d0fa3119464a7d400a414761d89e08",
      "3f47aee16a97cbfb8129ae211ff28ad89ffc0435545ae036414e52e2fa05060e",
      "691c003ce323c82404ee15405cdbc70e80763685fa5c46eda8c49205d735e60c",
      "df5c271474a07df63e2247f98f425a95136b5aae1fbd610fc1135c803185c503",
      "ad98c0a4ac23c3df8568480d55078970a1db42067f0ee32ac94f030f1df8f601",
      "ca09d289d9b5eff9ae78cdbbc17a374e66481d510bb6b4231466c5237a267a0b",
      "fee16aaeba4145e3dca7f3f8cc617609c16e1312a7c007dbdcec3a597ced5402",
      "238a7696ac0a36391b9910ad7626585fc229af593fa22701c8b4c8b18990b901",
      "9d3d4d20e35b7845df650fba04eb24602e142b89614462a780bc104d7defbd09",
      "729cd68e3b0a8326c2cbd98a1eece2c2af3f9aa92a71f41e2a140a7ffc6d220e",
      "cc99a1d53daaf60f4bec5c211047be10219cf414d7fe78b84a893dc970164d0a",
      "5704870bd6ab0ceff4ef50053396bd539ef1d54fe4e95ad6eec06d272acf360e",
      "0e62022d8f704d4f54f448fe31bcce7c4ea975a7a534b7036af87741f4a29700",
      "eedfff5f46958b1340044c13853d5dcf9cd7bf7f2c0b7fc9bcf507b2b29fdb0d",
      "a2e9c539b646957637897a93b7253e62955815c466474849287cf0b7270e6c00",
      "9627273e472b68e6f8c7a228146e65cc7da97e85a3bf9d0a10306d7ed8da2602",
      "efb04b20f01b9295f8066f84b90a795a0eda9ae714c8ca9be123eac678025d01",
      "6a622ec2c0210357c347b54d2b0fb846ef5894a1f2ae117817ae6effc8b1800d",
      "e31919c7f3596e625a98eb2407108c3760cffb5d0975c5354509752519316d08",
      "5e053ac6e0f7725b1238798f5d5a09047db89f0aaf9c87e6d265bdce97360203",
      "cfe967061830fa5277b8c7432ff9c2ef80159a1c201c63627cb88bf3ecd97f0b",
      "a69c06422128e7ab55f38795b700af760a1bc7d5a08386d0c5f6f7e4a0367606",
      "669b4227c299d9b615af5ea636b062c16fa2b1b12ebfe9a3d21c01ece7cd7207",
      "fd3c1b477688cee1affe423772a5d20c2b6c99f1dc836f082d67f030ddf5330e",
      "739ad42ba90d3f6ad7bf58d6471f9dc3a3a70c335497d27eb84866360396b70f",
      "7ede7663967b311665d0dd4b93bb4eb6e0dbddbc1dd4f45d0d0668fdc1bf9602",
      "eb52bf69cd99e55bf4b6a6c150108a7f9262b96c43e349e429f573bddc3cab03",
      "56374dbe767e0bc5bb36c9b320884bb2b14978903964ca196054c4b63d76ab02",
      "2d3a6bc00151bec3f6802db502c4994eef16df5224fe9004dccedb6542990b04",
      "25291317fb6b7004086036d4c2afb93d17357b8927c05a86abf507c7066a3900",
      "368e6263aec214dfed4f9cda9d61dd6ad5354df89ede955d5bf11aacb608be08",
      "267ebbf081917b31073e4d24cf979db4761c1aab5972bc6f3fc14027b33d220a",
      "f4e1c1221ecb5fe301ed9a6852a8bf32be8a171f4bf4eaf77fea6aa698cf6a08",
      "2f11eab4c3c7625f1102b8af46bec768f70085bb3b358fc5e3d5c124c1a6960a",
      "9e9e42e1a8cdf9329389ea727e091bd33de97bc39fd18d355a0e6c58346b6d07",
      "3ae8b143ff3cb1c06b6623e0d4bb542ed4c777703b07e9c6c69a707297f51708",
      "dd4486a5cc44ca4d1f8fb452f387727682eacd68fdf342fae72af4d7dbd48f06",
      "b16e9260836c8a19b4bc082abbf096f184c24528f213b0cd137897914949ce0b",
      "e139ea1f4d2f86d4b3fc30962769a0bc961205ec6a65bb31117d034561ceee03",
      "fb5c840ad686c9ec2256f75ebbc9fcece5f2dfa8f02bfac587e56b052a687709",
      "e1c199e70a77a7141e5be996ab887b6eaf865166b2d5b77a23581903dd211b0d",
      "9813c6e6ea9a20a0ce9ceb9c3c153471bd54497ca5cf30348b791a7b2fc24f05",
      "d2731a9f2c4406a3ed0507ae5b390ddef234c59f7d0eaa52e7f56e0c43770206",
      "b61c77620ff596a7fa4f7562491bc3a77056acdfbe148507a8ebfab070b3c60a",
      "b44172f3e97b65c55fc8b89dba70d5b1fe4d947e5877cb6fbc402a36500b910d",
      "7566074ceb7da410088d0e40e10314831d2bf2ef2c347605ac00b9b5c1f22d07",
      "aa34be55d15a3e9b8715dfa5dbb09c40beefe21c12eee541893b13998e95a901",
      "13ead1a2c33c1db4814d55f015d177ad64fbf2481bdd24f5a709b92108f26f0b",
      "7082548d52798708301b8b7235950d4c1a92804ae56ae449ca6a88abe30f3707",
      "277f6f333a80796f352c39fba1a5da2e1b1c090c38170aa2d70f3127909dc009",
      "664726ebc833a5bf99057247d067451fe5ceef71b73db8636829a9dcb737fe01",
      "1300421958cfcf97fecccca4293abdc51d1032fadd09c41b84cd0a19615ef205",
      "cd994d117edc22e7eb6cd285681852026423cafcacc52f05d0e1b71f1bf99202",
      "8026fb72b2af35229a84f14badffbdd898d490c0c469d0c445322d2a07ee260d",
      "2b7be54ace38dee69733a5cea14de60de61aa7504ba93d7a4591a53ef7947005",
      "8816aa86e4e4d94f4785ef873810876bec9cba5488be17f653c1384e5d539f04",
      "a92aeb6be2833ba4acc81985df8038da898998c243ad61bd2e91b58468d15708",
      "9c14135fd4f93836b91348f051ce655d89b127dd25f9747fb903f7781c052302",
      "9c85976687edb01c63bfe10b5bd5da5542e3f91484be66969c50aea01d2d2402",
      "3a0aed78125f6a33a6ca342a33b3b0b8bd4f9fa9fed62058ac553af6080eb604",
      "58857677e6619e89e3d7688a83eafdce0a93c9e0b6ff1baaadc7ad2229d2bf01",
      "16c0b921ef146f0edb0a3617a222657ef3dfcaa855de0ff2b20fd35efe210d01",
      "18c7f0a125f35fc2bf9b066ea44a428c7613c05eb08c21f06d151e4d2a0abc03",
      "92f639ea36294071df576a5df3a6477617361543754440f2f036146d2f77130a",
      "d672c81f36f51b20ba2c1fae33a0b10f06615bc1464d84904a3d749a6a9b2c0e",
      "6439873d731d24fc1737e28914ed7b2dd919520699323f3c86a6a94827c13201",
      "52261c788b9dd1982f2615848577f403611563f891400c43c21cfe8534ab2f09",
      "64334da023fbb0cdeaeed9205c5cea14647c37c6d1178c5401795f12e7540708",
      "eb6c797d2a135edf704d03053e71a0b734de22e157806db4726e9a3fa6de9401",
      "3f41c8c2312302deb89669c8d59776173b0265ee058ebbcaa3ef55e82a474f03",
      "fe09c62ed7e4b100a10cf4eb6be1f17acd6b7dbf64d15bb956a48a36f915e704",
      "5b41d546ccd37e0b44bbd2f9cfe093fb3833f2b808c50b18aa8d4015193c5805",
      "ec7a3e53f86bd14c756f852ab4772a6dda38f88b4f2bca702a7c4b2dae857f0c",
    };

    const char *secret_view_keys_str[] =
    {
      "737fec2ac72cf4875ece19bd84b4a86a8657fc8814814503d030432ea35fad07",
      "2792f853846086f6583e71f2a9c1b981714d63e8190639c7d589ecb286250303",
      "f585351851b784413443d56a3d815646b8ca1dbd8a077a132909032a21aba00d",
      "f9d176b0372d2d2593f4e4bcc65add9cc28b8112db470ff47aa9ed841322d80b",
      "c714ce94216173ff9c876b9c82faa4bdac34ea7532282342866aeb97d46e5f01",
      "ad35f5bc4bdb981d98fff19f0f2aae136968236db259ddf90ef0600e9248c101",
      "f96ddb40442d9706eb4f4d7ae3e27ddacf83bbc48db020bba1d1bc38bf453508",
      "28d5d9c3417a4fb37f3ae836475dce828a3678d2e94d210b5451586141759802",
      "e061f3f8556c25d876d346da36f44d0661d9fc4c51c1482c5ce3c282d0c97105",
      "cc1957406f4c883ea1169186f9159ff8fb8c456dd93d541713439171ec81a902",
      "f1d9641750120bc99d4bff33eb4da8653586c36b687944e38af4460471dd7908",
      "74905fa3d930d297b16a9aae486054dbc9d5e123a6294accc823df3ff84db40e",
      "d710e2381bb4edde894ea30ca2f7ba86cd9c4251aa86570d8732290828c5ed0d",
      "a2214f8c4f479f5f70580956997dcf09f9450c3ca95b20b76dd48f8978ffda01",
      "eea89d9c3bbd865ce8fec16dcc9b87274fad4f370240292bc5531ebbde362b0a",
      "78ea92f16f9c13f90924aac5c8c6126ee31d963e59cefa0f27b0facd848a6d05",
      "d3b49336a84da4bbfe1f6265d5e67aa983942df3c3261ba60bd9e821fbbbe40f",
      "748865a870cd74ab20a83dd768875d0e84b2004824251fb4f02314d607ec7b0e",
      "6e8648549d3b923b1c10fba5f1ec4c040a4a84754c9d741211a8f4f144b95005",
      "ee2a42f8e96959fddc035a7b2e1b81d5fc2da9ee91174a61ac3f5c1325e66401",
      "b55166a947bcabc449932f1a3f800deefe11e2a366e8027cd7a5671f8c7e8904",
      "55523954dca5efb6dd8ad5bfbd4ebc49b71bd48360d4f85a00a2c6ab09be4b0c",
      "e493a380eb5fefb05c26e76f432f7c84f9b751caa65db5ddb18cc65ab9ba600a",
      "dc2c956a6fd2edad75a7a939a88743b83ca3fd8d56a46dfc7e86258bdb4b210a",
      "8147bfb94daefe23b9a4c454ce0105c4ae6d274f8232863faae4269dcb62d10c",
      "a9164f89c44dc21bb84ca31b1432e94d25e6cbddfcafb418ef629673fd0cb80a",
      "b24253bee67bbaf550b12de16da51b5de5f2ab830c5dbf1613282601dce44906",
      "e8af7f592123df6c2727c18ba294ffb0a4e26c80b7d126fb54970602b984c703",
      "972e622ed037eb699a4874346efbeed520b46366291ff02fe010168b35ef280f",
      "640c1525b92f3e6b7df68a8394a641dfbd8d11f834baa6ca824b8c09d2376001",
      "9b0ea622c662e0b22c2d4afe293756235dc29e5268a1519444899a98544d7205",
      "757383beab10787379bf01712d75ee83d35f9c3dd332620d9c11b653d349c707",
      "711fe5f95ea7b424c9360af636bea607105e05475cf7eb9c3797ef3db9efb80f",
      "184218af272c033d975f72efa401e5dcee36bb790d7373bad184fa256df78a03",
      "420bb6c6181735e0a36f1f342b38945d76812a18d86d5c3ef65235cc98e1a409",
      "427b3171531e1fb1f43b294ed0a23fc90199be6c1fd777307824ab8c3067930e",
      "e646c5f8e7f204f4cab7ac5bc1ea327c84707a5ba509a87740c549ca4b950a09",
      "9982526e83c827f8ad51d4eb3fe0f2aabb6ca82cdc9493041c0c13e8d267600e",
      "afc855ed0391dfdb3fb182d2a8eb3181e532dc3e8de458cd3672649808ff7208",
      "e6b55c3a1c873ca610dc9eca43089d874f4e3d0cd4bfa029f45ee1171ba52c0c",
      "5110c743aeae5253d480235c0c6fc7118b64158baa74b9d140156da571b32a03",
      "10567eba502edde7630a993e171897a49fc0b1e30264f4e5e76957ad2515e702",
      "d68d48a8fb666dc4424bad90c44f346ec332ba9126208cfb9e23ff2ea281e70f",
      "115e9158f22a58c83a2b39d1d465793c792ed4ae2f4e7cb4997ddba46b959600",
      "989906935f111138ee14b6e056ff12dcddfc25941875357e4544a6a644c9fb05",
      "20194837af099becc39295bbd30a438eb5a046db1d19c4587e81529a91a6260e",
      "900873d956b98a01bfd225b17ca63136478b163fee78c7270afca8ec0381f600",
      "7972e90ff14431f9bf5c977c7eb538290573c84859f03dcfc4cf8a2b9b888a0e",
      "5cd3ccbfc6ad0c10fb2f9929f1fd12663949c30f3ce3001b01625c6a28cf1806",
      "c3951b77f198149fe2d5907a3b437c38efc92cb37c5fe4710ac5965e077be701",
      "7e16b4417a3c06aa579432a9dec94d54d12287fbe2033584f7287a5aae96ec03",
      "18a9d46d27301be4e241ff3453cac976692e654041d5051f6d024c5b3c9a2d0c",
      "5e060e5f9674a97bd08d698dec6214e7c6eb54e761968df417a8a703f0482009",
      "cce9951abe2248010cddaab58f2e97ae12aef68b2997899e371ce4d8528b7804",
      "2f9a63777ddf5b1e7450564345d7a4dca0e1cbc37e6384a822b400785429020e",
      "034a8a81a36dbc998f527f78d6f8c791f71ad1b5960335f3b81193106d3e0b00",
      "2bd238f8170492eba264fc2e1170f862cf716d6b55eb6b9b6d763c15aca9e101",
      "f61c8f7d68dff0bd339629e28a41ea5673027e72635f47cec18a43db61cc5604",
      "9795a613f288a860395ed9e6eb0f9d5a039ca9becc54a6e08717ac05574af20b",
      "bc0830bcba5498cf39ba8ffe3844781e4949df158f16931423a0a61150ea3b04",
      "0a5acd55be2647bdab1242221bd9718ac9a1871a199f5fb111b44e3d96c9b705",
      "0c2cb96ae138c98a4a069dd000238db7e084abcab358d208430896649ff70200",
      "15aea033ce829e18aaba1a8974923ed79b8a8dbc0f801fc6eb5ea76625d8680d",
      "cfca11787b684e1ac00dddf70c8e4bbd8b87d55f4a12f575fb17db0cc132b209",
      "7a4847bda21b408b449ed994d82d9ed7968d18e81b29cf9c42caecf76cb9310d",
      "32edc2b601d4f8c0443c994978634f2500626020906ddab6a3c85e2c9d74ee01",
      "c59bfdf6878473f8c287799c54ac88bd1f92c68de7fc5ed2d2aeef1468489208",
      "d671166394bd14d821118401073b531af65408ac67a1d3f25417db5423279803",
      "902b2660518c0e956e45131f8b9bc2c1f31527456ca93bc86f0ef560aec9aa04",
      "a726955b135626717be1301d08fb507f9b694741c2954b9ba1fccec282608d00",
      "c9afbab8eca0b15b4d6e80722bc3f1baddc312783e32648cdefdf329bc209502",
      "ebf784323ce3dc283b2facb2d8ecbe35154fd0bf3de0d195b902076f8582140a",
      "d4bb8fe6ae4ec3db1f3411291f78e10ffb9bf4b8f0b695b3ee4f63020d4a2a04",
      "65dfdd392df2597ec6ebcbe087ed46668e06a3b437f85de3c965f63644b3370e",
      "73b984b2b569707539d239cbbee6a2544b3a1ea68c98d035d6ba8ca3ec1ba109",
      "4346fa6bc7cc339ad47b0a35b55d8e26e6eec2da557c1866ce5b3ea34a703709",
      "20d6113050f3f80e7f71f81d822de8e16cc537ab0689cd4f831ff6571147dc0d",
      "09b1bc0624a88d6a93c75cb55d5ebf37e4af357bb1e58c7de42d8610515f6b0d",
      "17becb03d791c163019958aef4560c5061d3cd91fbdbfbfbcf5ad74c0150fb0b",
      "957882a64c1c80caf7b1329fb2a0d9cfa939cb960d224feedf6e4df93e4e0f0d",
      "fcc68b580b660cc46dcb216123e80ae82bb2740f4092c30d3d1d8ecb7302dd03",
      "c16ae0301f5828df5d413f8af216597d70f3668b3915678c640edb518dc8730f",
      "5cb1a8dac6d5a3336a792860fad6dc873f4b7b4a2c7aa8e209e1bc49d2c65005",
      "1de37074745e115fb7d75afff1f569f5cd5bb771c622deb818fbc972c3557a0b",
      "228e50d452077d9033547d98ceb86bff91b428fd9f1214ea0a3a4ede2747280f",
      "8c118e2110b8b4cbd2f91c3f3cdec36ccf9dee801c2c4b09a556844e34c9e402",
      "b9717aff09cbe5996f212e01d5d3f4b5eb9254b6e04fd5684d65a92fa14da50f",
      "55da1eaf722d392bebcee4ba95df62955a488066e55057393835e4b27e54a905",
      "4dfe88fa91a98a7a680922b8b47466da9cbfa4e87a5794d6f55397bb78de830a",
      "dc04954929166773bf1049a1d44f90c34ebd16ea6a51de22c1ef50072b96e806",
      "3b254cee6b1210cc96bd4ba8e2aa78fa10f0d3f6a1831e2e1895985c50525400",
      "78b8f1bac64887b8532b18835fb174ce3dd01fc9d9ee7758a7e472609f24fe04",
      "c1a336bf4daa38b7995fbbdb1c14c14fef3d0520ad14d0006b02e5cc2fe7f107",
      "f559c613b7d62cf821cfc055944580e22988443c82fa214bb2cb016dacc2c40a",
      "024ccb288a81dac0fe4822553d0d9fc5496448f5314801fb26c074db3216b808",
      "72e80049a952c641787116b1a7030866248c6f320082aef53960e2b061ada603",
      "ccf1dae026dc42c9605e9bcb8450110fc59cc033cf4f8246760028ebada36d0f",
      "f21c2022617c3dc2f81b0ac64dcc71b93e98ee3af7ad22dac9bcfcbdaa816902",
      "9b49ab72353b2fb4bbf9c7b429fa43005c09be94eed095012cd1f27cad96890e",
      "4836f02569b16b46af093cf867cc977d4f372d263b637a77e4383761a8443d09",
    };

    const char *public_view_keys_str[] =
    {
      "2c630b80fad747a161af10a814b4f9aac058300025da9a6bbfb7a0a634796e52",
      "7b4bc53fdd9ddc61a623d6cea943746047b6d9bfcb806092112cb25ea8960a0a",
      "5e9b9e3ea45176ffea82a03f592a03849842bd04a7d5c8512a7e21557d2db956",
      "a2781a9d29b79de5dd8270b384164bc7fe857c2b3d6fa6b1378f298f6ce57afb",
      "9c54437a9968696f20c338b779af48a58c59e768236fba6365a380e183901572",
      "b1925e24486922062745cf25bd9e84e59d40222ad95ce31ce627dc376d3eb7a1",
      "29eff4d0fea74fb9faa42f7d26f64b55dee30eadc6d3e47a6350ef32e8899db1",
      "87a73dc00d5743726b7b4534a17774785b86c6b8bdfd87693521663857f8e6ad",
      "bc20c7283136482caa2d4711d5e6c503f17f43a6d4bcc395249c1ae086a85127",
      "9bfb49aa2b9e98f7dac8e1d3846b197304d973618623467d6851fb47a021eda4",
      "7e0863456869decbeaf1c1146d5fad2dd3649c73011eb77fe4322ea5f062c0d6",
      "0fa37f21968edd070c9e6114fc606a47832981470f0ea26506545aacce439ae3",
      "f312d09c8cbf9d248b5b534107d3a4836b242843e094bca74b457a5950260e06",
      "129da689cbd4af8f30712f15d334b55708c87f291a5f13fcb7b3856316fae48a",
      "192d734eb917081a51e5de66d191f3561a4a18e79a38133792f109e7d80baa94",
      "925fa20ba0891cc162178389e2aff803398734b3db91996504e7ad26ccf9daa1",
      "c303bd7c1ee139b571d0fce233eec4fe1de1c20c73a8c3a59d7384f5e259b800",
      "49d7dde44c90f3e761229d2200985c027adc58e9c3f95ef7f236b8e527f5d76f",
      "d2d78e19f70fdedfba513e6491a35ab89d0a34c692bd02975114e26e6b73c3d3",
      "f53a7d2629a82c8dcd88fc3cb3d48c402982186beb1c9621d056cdc4f30fc85d",
      "5347c77ed9c8dd61225bbf76865c72f0662c73d8b36cacbb612ae1aafb817dc7",
      "5369a23800d3924281e137569055725c8e350cdbd9ceb08c0abd5d9ff5c63d8a",
      "bc160c1b4a1a8828fb6afeb618d31fa5805cd924f0dd7b9e5b51569b1c7db9a6",
      "60aa7e0699cbb55f564ff130092bc46936fb93716b09b4dfe60cb4a8d113ef1b",
      "65fadf79b26fc6a2b2cbb746a9d0a060c8bb94623cf0d900566ab215014459ba",
      "c88f50cbacc23da423c161946404dab6073731ea6765978a7b4443e912711c98",
      "7bb5b09721e359e91458c814e9c7ca74c824704fa731ee21361ab082fdbbfb06",
      "1d0327ae46205449127fdbd0a97c17b6cdd087a487bc9c5f74dbc2ed5164c31d",
      "728f3379c9478bcdef9314e92e096d290aac6406c3dd2812a6922df0f1b9c954",
      "349e42cd005a5aae52179ca0d20cef252bce3906850afa34a5873b68b6541f77",
      "9a84f8834d9e7ccc88fe80f91d1d87d38a0598073c0445ee2e07ea8069fff92b",
      "be2074edc12b57868ded1ac11b8378d5e82ae889702e86955be65a4cdea37aa8",
      "80da793be3b8aec153f019a3e89d54fafee0d8737f2ea683c5ddf5da53b0b373",
      "eb6e29bb1a2d8d7859bba48a592ceabe2c93ac048ce07e948d95ef37bdbc5b60",
      "261d1b23a6ce42ca2b28bb735a67606c368b086b34e1ebd2e4ada952f7ac5714",
      "b192a074e01ddd287a87e012bac0f227c07739dedcb55d15ce4c669ad542b63c",
      "d6f1bdceb7ba8aec763955093cfdb37011c90e3a36b7cc5adcb318e05cb52457",
      "9d8fceeecbf02a79f0ecda7f3d505227ff298cf5b55d64d37e654afdd4bdc21f",
      "06c2cbf7dda109ce31921d3f9d76f99b0492fedf4fddf3da9dfb0efb0618a51c",
      "d8c6439ffbd9accfc39faea2df62f3540ff5c60c8277597153aaa34c12be4af4",
      "581b9728eed3fcaee3e8d1c6183fa2e880c8ef3d4714ac985e094efa1086b054",
      "035790f51baf5c3c7cd604e27b0e74be467751d283165358adc059e46be20aa6",
      "de8a25950b1c81ed511ad921720eeac4bc9f0d17134be4adb23e8caf41971d6e",
      "92046e6aae34dd600197e004f481423eff7c9693c9f1e2286fd2a656e9ce64bb",
      "36701b256ce965d27e6977e615512dd3ce6956bbf751dae6e465d6b02069717c",
      "0c539f30ba349133e2f376c8f29b2b3689b8f5d36d38ebb8ccda1b8e828173b7",
      "de132fc4548cd2496accae2a7d857ca7114d62de5ae26fada431c048ed245222",
      "a9fd335e2141c4538b466d4a116835af99852d5d610463885d40d3beae26dd8c",
      "1f325e76b320f9abb1445ae4dd39d8103bf4f9fee7b5b1f8b163a80667a2762a",
      "3b7a2246408813846eadaf1553f60c225acfdd90b87a0aa5c9a4c44611b40bef",
      "a7d470d9b36dab58b364c14caad5b046b456998c23ef9dc0eaf103d1da9501fc",
      "54d5858d388e46a3ec92de308ae82451acd1b6d3928c83d10e780726dbc2b371",
      "0fead8295364b90e9fb1d274a51afb8a0b992e3556a2f0fc9958bdb593e36e19",
      "2801206f7ad36ecb3b6e5b582b496745d23c11f972ac64971f9c740699a66dc1",
      "4b4396b22d9f0b585030574f99deed1d0b5f2f69922c79e32697651374cd1179",
      "4e77617debca36df10c4bfbae0915b88f07f0b16b5316658e78e9463b122c73d",
      "6c2ceb393e764c5030b58626364175b9ee89228f5604454004cb4aacd425e651",
      "1adaf92bd1aff090d5846bb56bec502bd1a2eafb18cad5e9bd1d01949573942f",
      "b48be8689517e34098e0a77e9c8a6c1fc060b15fcebfedb49d3d1ac3e7d069ea",
      "0b011358197a66c2fc0585fc833159aa99c461c12c2c3a16a4cb42ad4246d508",
      "233c031787e953dc591db478cf1b82a7f2f5268d48ad7661804804307961754d",
      "9828db88fd0838ed0dcc8d872e7486789d00cf029d3845658cd699f9cf99750b",
      "8e61f39836bd359bdf2c4a1ae679a319b62d4b691beab83e8af67aba9602d731",
      "5860af4708f62db5b24a73212709240bc840dd4293e0ed65b8ab222c4c798225",
      "cb9a8fa987fb06446ef2fd0ff1a05f06400b4436acdf31f76df30127f2bc5291",
      "2e2c1c675762e2864ee93d7ead0b007377e3785d4682aa83f043fb8a4349f33f",
      "d8da4726bd6896c3cfea0e154f1b02ebdaecaa044e023c25c17d4d38da85537b",
      "6cde4dd8727a74e5af5b632c8a91b0c74824ff25b9f42046b7a48597a86e0690",
      "14932b87eb667bfc38d7cdeb46796bcf7adb19db3fc178f55178e2690399d1fc",
      "204b752b60efa2f67712a61d489c34e21d7595646a6386dc18984821e5d322bd",
      "097eabeb75d71a1caddfaf97dd1b9a9ab4da42affbae6874f2f77d23553000cd",
      "530d9f9bff1d74368f272a44f17bfb91b26085db38de15738ad9c86d052074f0",
      "5d34ceac0be957241a0cacbe66a8ba2c312fadc892da65b032d974d80e009400",
      "9c79265573974daa840ef4c91399a1c66b32b774cb76fa5d15e15906b10d81cc",
      "4be5b28a7235d51abeb66faaa5ae2372da1ae1ce55de30866417b74479417cc6",
      "4f78ac9268c4000ff7fa29a00e1153b69bef8039c9d3dfa0bf52029966e54b11",
      "a8906550dd9f70537f3ac28f5100708f7b1d602f280e7570fcfcc344fa339d02",
      "ba19c31f84e363be4f8534d8423e03de41f60d650aaca403e4985ed047f41e24",
      "a017c73465177a707c62a69be0a61ed03c9028d710143fdb8238b2167d833fe2",
      "2d12a117eb93de1b4ca651ccdcb0cb3f4631af2597a76a411167f3d72284b6bd",
      "82cf3b27553335165b974a100d3484a449aabe9fd9059fb7fb4c05fc591e4494",
      "8e7929c14dac7282d622f3f29529811c5924f53401fe60a471e9fece3d32f2e9",
      "fb31dd1215c4527bcc7edd7184112273d0e4de379a9daae2ef537ea532499a7c",
      "631be1e296716f064d7b0f5f7f133728dd55cda06fe798bb892aab191d120b49",
      "5d77438469318b23c5bf26d298e3fff0ac241121bc95e320da92f7fbf2dfbd8b",
      "0fcd2774c95aecc71419ed03f386e7d7ba630ee49ab29d44dd01b8eb71c0b045",
      "5f3292584e7eacfd120d7fda25870bf2c6f95665f9f6d4166a461dfeac913e9b",
      "c636cfc439679e2852751d3781fde3889c812d8b246732477b12362ab5995ee6",
      "fee12d8dc1505520e8dadde1450b17bab96ec61277bcbcfa61c6f15f3a207cd5",
      "243acc241270a8f81fe4f160ea809831be197700f009079c9bda3325e8d92a2a",
      "b3cc931d3d90c42da64e0b2338d86018efacde14f1c284cd7594dc88fd88aaa1",
      "fa5cc591c9cc5e0847d7da82c717f8d59d1798f77c245ad0e5c457a373ef0953",
      "a6f04634b070c422612262e718cbcf1269dcfd12aabd0f1c1ec52630396587cf",
      "6dba976dadf612423dccc272a420da009fb20152ea9ac501e58f5eca227a6ca2",
      "a343b3e4abdf29dc6bf63a57faededf59cf1825ccbcc0a5ffbf68d42a6452e7a",
      "b011870d4ddf0fb0d8bc91ed71f11b0bf85a7102bd0f405ed49ad21474992f81",
      "24375b579071a728b3b72f49588a41a89dbc38a9e7f957182a2dc129c3f6c646",
      "7757accc4647fb219e9e8c211a8e7f6673b7da2b3f8e05cf8ab4c4673bbfeeac",
      "1be0b206ff9aa683f3327c6f6ffb4d6b6fde62704aba9c8e7c3b7fa308c56985",
      "42a2c97ac24d9f4e1275a4d1e5f1504f073552e97631075e20fe185dc4fc27a9",
    };

    const char *public_spend_keys_str[] =
    {
      "8112b90e9964a9061f613481e6f4e2d5cf873af2e7e9d492f0b0959c0223bc66",
      "67fa0148ae72db4ef4f46e6c455ad06b5c366c3f512df9743e73c679f644e1df",
      "051b4e9ac85d5af824b5da3a25e87bc19a1411ed4a3f13517cf3c42452f27b4a",
      "3cd2d156c9a0ec53da9e2e724a50606e0a4597ab28120874598d6a2e5e429e11",
      "642e4586fc8ff9e55c28fc3e80038e0c92fd4f3742606c24febaadabbc26a60b",
      "40cb0e9ebbdf0af949b52f356e4e9de03120400c738da3c6d71e417c20c6ea30",
      "c88d9870357dca73e93c1aad905f3bedba53cc4ff628304bb3f85f96bacad683",
      "12dc36b2385b7d88457d0bb7189b632b4d5493c4d0c29b449858696d89075961",
      "4a7cc216e825ae51bbdb327c7df9813752cff6b95cd9d95f9bcc088ce0ec2809",
      "e6d98067124ab82418343f4c52dff26f5e0ce7ef56f72f219fa041b60dfcf662",
      "5c4ff6ea89259da30778fc8f09640d3b29b0ec8d0363fe30e9919711cc86d136",
      "80776fbf7bbd1adc84e1cc7b42277ac26574b5db80f030ea28abe646ec967c0e",
      "9adec9a2dd79fa29ce32a7b2c3a3e398fe6ee512e77820466b6db5e93d81a547",
      "7244bc075fd999d336f6337b007f3dfc83f0972a94ac3423a262a4bc3654befd",
      "cfb6d881d623112ce74fe871b5719178e6b1aa7cd1b4e37ff7b2bf3d5caee0e0",
      "1c52e02b7c2ec37b151e910cf522777e5efd6d636b648fac289820989d661795",
      "1293e8d0dbd94130b651acdef484bc50ddaa01ee07aad79e8e5d9f08a1e07c13",
      "d3074f9ebf5724cb7da1b23aa8232da5c1f3f0e4cc2e4cf798c88e0b2cf9f148",
      "b52ac252eaa304563a91b7f29d3da6b5a0e4cb0ffa136db7f0705be49cd40e95",
      "d2193ae488a7f90fbef224c2cb2800a5f6bf79a7314eb25a4461d92f7d9b5054",
      "1956c459f08e0078d2295abaa73b33f43a3474e3f95fb8657629e85dd680c2b0",
      "a1a26e5651f329d1434ae906794b219030161df240cea77d3d7ae11c3e91edcb",
      "0b5f5d296cdaca7904f78e4bd88e04085b145c8314b11a752bf4f5a01e20f820",
      "2e861a10517196e7a19ba83e8d2899e28139e3eab4ee6b5d835ae231efcc8643",
      "ed59a8bc43141cfbdcda55c6b2d66a171f3a4168d4ec3fac4cd4a3632c7a94bc",
      "d9efe1d471e9dfea80d881ee716889433a06f76d6aaa3595cae757af94cd4b1a",
      "a101258ceb4cbec028df0170aa2d6b47e76c111c46a4a3fda8cd186c8e73b041",
      "babdb97dbb8d00a43083073630f09eb3e3d1538c603fd08d7aba0c3565d9a965",
      "149a109af884491f4c180b0b81ae95f5c6b3b391e527f9523d490bea93233a0a",
      "11345ead6ccf05c5d4e169ec72e1cb05689410aca17ba1915ecbdbc1f673b540",
      "f21c2d6a2603c438bc9901c6b14adee2badd8231c705c037181f1245bb993566",
      "7f35907dc0c5b1ee069a87cea06abf22137276461054c7ed6f9bb8a25a0d82a7",
      "47ed53900ab92bd7cd6c0800687df2ff6fad4d07a6ba264df1143950dc888247",
      "f5dc6afca3a13a5efc0406d6a463ca8086e3837f2502429eb17dee2220f6c906",
      "8115f7fd2d8b62ea64518e1fbe48ef11e687bd6370e8217478af4567ab3e1879",
      "dd2c3f112172fa9865a7c42ef33031404660e8645ceba9ce7bb2945814a15a8b",
      "f09c90170740c04cf1ee3decd598bac6e262199d456a447727bd9f6dbc8c3dca",
      "dbdae9f19645c55d6e0843350d5b7d5e8eddfc144ab74b0a470f313b380e4f64",
      "3e78c14eccaaf6f98c2ffe3bebbe69ddbad402bae06391aa2ed4b5fd93ec6c43",
      "4602fa2e47280d486cb18d8238f23e30331beceb00c58234189524202c481e2b",
      "cf526fa79e7ed3a1f9814a4d45d10dc2ee75da920542ce777108547ed57afcc0",
      "703d9bb2212f0f6dbdee7599ecbc83eee14858dd41448d0aa9d96d36569a3aad",
      "89d608e2abbab5e4bcaf5787ae9b22b1fb1f617369427362505484bc95a76581",
      "19e3a6327de2c4fd44eb5fe25b2a5c9132d97338b2eeb06e05c7aa2b76d10b8e",
      "8a9a2d98cb8ddead192995b7738b50dbc1478dea1b9c99be3c6367869b4b096a",
      "f1d1490a9cfdccb1b886fe2328421052f976ab397a41a5096caf8792ebd75707",
      "8f5450be0346f7ec18c462d9108e06cca07b888db81c3cdccb31d537c5fdb1d1",
      "032fb106ba4b65c6938b07db47b803e81f14dc3c324ef842c7fed5a5ce12944f",
      "fea9714d230c903b11c75f32d3b4de46429d668e01b442229683380f267f07f3",
      "faa87ff814c3021a2eaf69a24e603931c0c100b2075c3d12c885bbc7dcd5bc85",
      "efbf84ef98c4a8532f075677b58e1100962ba429bb985b01e20fae5d5c2df9cb",
      "ad5040e034502b61234d7e708be9351c6e00d450927c50ec9a32afdf02b36a1c",
      "b6021473975651f96a4d36b7be88e63cbfb2d418d4d69773b6c64452fc9a64c3",
      "fef9be8be517489c55878048cf3403a6d7f9fa43bfce8ee4d24bd0bc559803ca",
      "eeeea05419a9b71a62d395bbe8a2b94c98697593850a944b81bbc8ec752a6d25",
      "18cc025726737d7d1a95c9b500d31d2059c96a267a5a0b53be15425b699b99a3",
      "d43846fb6b532ecde8370d389cb4420b11dbf4a79c18a1bc5783933b3a5952ea",
      "15db8f1935d182446551bdf67a9f2686801430757656073c49f92242b6e3fd4d",
      "955f211e7a7e8c5e02d0cbf5599e0a740659d0899ab66bde0c7aa57eda540f53",
      "1ccf76b6ed8112c211fc9de49d6fe4cebad3459e815482ead997fb6f1f0ec74b",
      "4c32a035f31bba251aba3716d5f985a565c284e9125cced44057c58c37cf073f",
      "746ac173ceb1d055d77ca0ec0256286c743a038528c82f308339a6550afcf6fc",
      "88434c2fcda22f90e601d96da2a2276786a62e4e0b318b5d7cc1542b75a5f60e",
      "fc828de1199f1f763a557967311eaf9791c8f269adc332f2298c98ad325b179e",
      "993044fb5455b4d3d8182c941ee5e21e3fe815cac526db676e8304c8fe367a41",
      "2367ecf98e90636b4e3e334f5a022f4d4751a7836688c5fc40c9cf411355fb26",
      "d5b2df0d0443eca488bfa2d7680a7e1f1f16dd76d7f10297598cc44e2de2c9f8",
      "faa47aac5e932f4878ef16f7f7f4383a1ef6050db070d366c9f98cd8ff775599",
      "b6a272db0b6b6397d424195a59efaec56514e7e21cd76191a2b4ec6cd83dd9a1",
      "ab1bb60b858effcc35cf2111fc9cdb6dc90d371b9345837eb3fba32fa0354a81",
      "0a1d730f410c5e8aa6e17c76502ce584d4e5690a0ef3e52352a494ba9630e553",
      "77528bb167e40b13c07ab65af9268da61601f2afa0e7447724c7c31672fc6558",
      "8bfff17b7dc4b840717f62fda573771e81dcce2a911919df8e3b3925f0ba181d",
      "31aa9780b8770003a90c456a761654d0f13141e9ffc7dfce74c5d876a1b6328d",
      "879a7d9b2482a397b9dea8f9e6e91135da300cb9b1d2377241fd7ddb7d251c1e",
      "b9e14e77dbcb0711427aeabcf118c7d80d6998269a887a44d49639556066bfb5",
      "4f7d926bfc5f9a264a3a0972d09087f38eaa76b2879e61715d01017194386a72",
      "3ae858e31c725bdc414984b3bd51c811a8cc3be60cc5d5825233d40afd8ece43",
      "f1601d0e7000065e0a23a25b83d0115c44749deff8037241caaa2f2677bf24c5",
      "851f450921e37545a804c63bc10d4d403eacc0aec823ad861c5233e84aa5e192",
      "01494ec0e954c527ebb3dced7d8e0c1a2ef95b1183034dfdb70c8345d507490e",
      "592010c8de072ac789e792b63e50b9048aecb64b0edbc8a7e0bb41500e10cf3f",
      "d8e9769b34373e7eb2f82b91dc5046714595d8f80d1f8793ed0e84798c527ef6",
      "095237eeb750ef8c0c10c96e89a54cfa448cac8f031ee2007700e5b11becaf3b",
      "d685543dc209da64006fe922e1091b4b683ab6f05e6695133ad75f7762df1d17",
      "c993d744c77580361968411ae1201ea0514a002825d7aa0af2d9428ef621e6e8",
      "41c4948730283f4bfa498819444c03cf8eaa159e9fb8ad02a7364c31dd182279",
      "4ed4b99af67859e051f49bb4dfb08c2d1b60993ad64752d326688db191dd7eab",
      "6081920bd10a4dfc3eb8dd29e8fa7791f450a8081b6659af335ef87da30779aa",
      "d66ac6f8dfed95688c1dab37129fcf6af793ec694d2afbabd4b488b8e5248d46",
      "23acc0688ab2c620b5bab815f4685ccf7b39c09fec52aea539a6c29f794b1bde",
      "fc1a3b72e819e5af4e64663ea959efd6dd91a1e803aaa80eecbc0129ac44728b",
      "98c5fc86b4700ac8280500707e9d368b2330ddfe75329d915c55ce628abd942e",
      "cf7fdb83942a2f4f4ed3acdc8a3b0a67b9561b8d16cde61ae5f821150498a537",
      "23d0a95a178863b2c70685ef01e335452dda09e541aa5415830d73588ca2d702",
      "bf4b8963a41856fd1629a9920bf8c47a177d874b88e957651c5e31e6b7dab3b4",
      "8f487cc93154b36d423cd74db955320d22956fec83d484a68747fcc83682f7c3",
      "6c43a23dc0d0b0496d4fc35434d4ae8ccb26e5d444ac1a1187fac1062f3bad6f",
      "47138315af577191066a762eb34789d93266b9f2b2bede649c49fa13d6806bc6",
      "f87fe98e826ea34eee3ff755178cb0bb8fa8d2775d51d761f1681253226e6720",
    };

    void init()
    {
      if (secret_view_keys.size() > 0) return;

#define ARRAY_COUNT(array) (sizeof(array) / sizeof(array[0]))
      secret_view_keys.resize(ARRAY_COUNT(secret_view_keys_str));
      public_view_keys.resize(ARRAY_COUNT(secret_view_keys_str));
      secret_spend_keys.resize(ARRAY_COUNT(secret_view_keys_str));
      public_spend_keys.resize(ARRAY_COUNT(secret_view_keys_str));

      for (size_t i = 0; i < ARRAY_COUNT(secret_view_keys_str); i++)
      {
        assert(epee::string_tools::hex_to_pod(secret_view_keys_str[i] , secret_view_keys[i]));
        assert(epee::string_tools::hex_to_pod(secret_spend_keys_str[i], secret_spend_keys[i]));
        assert(epee::string_tools::hex_to_pod(public_view_keys_str[i] , public_view_keys[i]));
        assert(epee::string_tools::hex_to_pod(public_spend_keys_str[i], public_spend_keys[i]));
      }
#undef ARRAY_COUNT
    }

  };

  struct copy_region
  {
    void const *ptr;
    size_t num_bytes;
  };

  static crypto::hash hash_region_to_buf(void *buf, size_t buf_size, copy_region const *regions, int num_regions)
  {
    auto *buf_ptr = reinterpret_cast<char *>(buf);
    for (int i = 0; i < num_regions; i++)
    {
      copy_region const *region = regions + i;
      memcpy(buf_ptr, region->ptr, region->num_bytes);
      buf_ptr += region->num_bytes;
    }

    crypto::hash result = crypto::null_hash;
    crypto::cn_fast_hash(buf, buf_size, result);
    return result;
  }

  static inline crypto::hash make_hash_from(uint32_t block_height, uint32_t service_node_index)
  {
    const int buf_size = sizeof(block_height) + sizeof(service_node_index);
    char buf[buf_size];

    const copy_region regions[] =
    {
      { reinterpret_cast<void const *>(&block_height),       sizeof(block_height)},
      { reinterpret_cast<void const *>(&service_node_index), sizeof(service_node_index)},
    };
    const int num_regions = sizeof(regions)/sizeof(regions[0]);
    crypto::hash result = hash_region_to_buf(buf, buf_size, regions, num_regions);
    return result;
  }

  crypto::hash service_node_deregister::make_unsigned_vote_hash(const cryptonote::tx_extra_service_node_deregister& deregister)
  {
    crypto::hash result = make_hash_from(deregister.block_height, deregister.service_node_index);
    return result;
  }

  crypto::hash service_node_deregister::make_unsigned_vote_hash(const vote& v)
  {
    crypto::hash result = make_hash_from(v.block_height, v.service_node_index);
    return result;
  }

  static bool xx__is_service_node_registered(uint64_t block_height, uint32_t service_node_index)
  {
    // TODO(doyle): Check service_node_index is in list bounds
    // MERROR_VER("TX version deregister_tx specifies invalid service node index: " << deregister.service_node_index << ", value must be between [0, " << quorum.size() << "]");
    return true;
  }

  static bool verify_vote(const crypto::hash &hash, uint32_t voters_quorum_index,
                          const crypto::signature &signature, const std::vector<crypto::public_key>& quorum,
                          cryptonote::vote_verification_context &vvc)
  {
    if (voters_quorum_index >= quorum.size())
    {
      vvc.m_voters_quorum_index_out_of_bounds = true;
      LOG_PRINT_L1("Voter's index in deregister vote was out of bounds:  " << voters_quorum_index << ", expected to be in range of: [0, " << quorum.size() << "]");
      return false;
    }

    const crypto::public_key& public_spend_key = quorum[voters_quorum_index];
    if (!crypto::check_signature(hash, public_spend_key, signature))
    {
      vvc.m_signature_not_valid = true;
      const std::string public_spend_key_str = epee::string_tools::pod_to_hex(public_spend_key);
      LOG_PRINT_L1("Signature in deregister could not be verified against the voters public spend key: " << public_spend_key_str);
      return false;
    }

    return true;
  }

  bool service_node_deregister::verify(const cryptonote::tx_extra_service_node_deregister& deregister, 
                                       cryptonote::vote_verification_context &vvc,
                                       const std::vector<crypto::public_key> &quorum)
  {
    if (xx__is_service_node_registered(deregister.block_height, deregister.service_node_index))
    {
      bool all_votes_verified = true;
      const crypto::hash hash = make_unsigned_vote_hash(deregister);
      for (const cryptonote::tx_extra_service_node_deregister::vote& vote : deregister.votes)
      {
        const auto* signature = reinterpret_cast<const crypto::signature *>(&vote.signature);
        if (!verify_vote(hash, vote.voters_quorum_index, *signature, quorum, vvc))
        {
          all_votes_verified = false;
          break;
        }
      }

      if (all_votes_verified)
      {
        return true;
      }
    }
    else
    {
      // TODO(doyle): Update the log print to print out the correct bounds
      vvc.m_service_node_index_out_of_bounds = true;
      LOG_PRINT_L1("Service node index to deregister in partial deregister was out of bounds: " << deregister.service_node_index << ", expected to be in range of: [0, ]");
    }

    vvc.m_verification_failed = true;
    return false;
  }

  bool service_node_deregister::verify(const vote& v, cryptonote::vote_verification_context &vvc,
                                       const std::vector<crypto::public_key> &quorum)
  {
    if (xx__is_service_node_registered(v.block_height, v.service_node_index))
    {
      const crypto::hash hash = make_unsigned_vote_hash(v);
      if (verify_vote(hash, v.voters_quorum_index, v.signature, quorum, vvc))
      {
        return true;
      }
    }
    else
    {
      // TODO(doyle): Update the log print to print out the correct bounds
      vvc.m_service_node_index_out_of_bounds = true;
      LOG_PRINT_L1("Service node index to deregister in partial deregister was out of bounds: " << v.service_node_index << ", expected to be in range of: [0, ]");
    }

    vvc.m_verification_failed = true;
    return false;
  }

  void deregister_vote_pool::xx__print_service_node() const
  {
    CRITICAL_REGION_LOCAL(m_lock);
    printf("\nReceived new deregister vote, current state is: \n");
    for (auto const &deregister_at_height : m_deregisters)
    {
      printf("    ");
      printf("block[%zu]\n", deregister_at_height.block_height);

      for (auto it = deregister_at_height.service_node.begin(); it != deregister_at_height.service_node.end(); it++)
      {
        printf("    ");
        printf("    ");
        printf("snode_quorum_index[%d]:\n", it->first);

        const auto &vote_list = it->second;
        for (size_t i = 0; i < vote_list.size(); i++)
        {
          auto const &pool_entry      = vote_list[i];
          const std::string sig = epee::string_tools::pod_to_hex(pool_entry.m_vote.signature);

          printf("    ");
          printf("    ");
          printf("    ");
          printf("[%zu: P2P: %010zu] %.*s (index %d in quorum)\n", i, pool_entry.m_time_last_sent_p2p, 10, sig.c_str(), pool_entry.m_vote.voters_quorum_index);
        }
      }
    }
  }

  void deregister_vote_pool::set_relayed(const std::vector<service_node_deregister::vote>& votes)
  {
    CRITICAL_REGION_LOCAL(m_lock);
    const time_t now = time(NULL);

    for (const service_node_deregister::vote &find_vote : votes)
    {
      for (pool_group &deregisters_for : m_deregisters)
      {
        if (deregisters_for.block_height == find_vote.block_height)
        {
          std::vector<pool_entry> &entries = deregisters_for.service_node[find_vote.service_node_index];
          int xx__vote_index = 0;
          for (auto &entry : entries)
          {
            service_node_deregister::vote &vote = entry.m_vote;
            if (vote.voters_quorum_index == find_vote.voters_quorum_index)
            {
              printf("Service node deregister vote was updated block (%zu) for service node (%d), vote index (%d) with time %zu\n", find_vote.block_height, find_vote.service_node_index, xx__vote_index, now);
              xx__print_service_node();
              entry.m_time_last_sent_p2p = now;
              break;
            }
            xx__vote_index++;
          }
          break;
        }
      }
    }
  }

  std::vector<service_node_deregister::vote> deregister_vote_pool::get_relayable_votes() const
  {
    CRITICAL_REGION_LOCAL(m_lock);
    const cryptonote::cryptonote_connection_context fake_context = AUTO_VAL_INIT(fake_context);

    // TODO(doyle): Rate-limiting: A better threshold value that follows suite
    // with transaction relay time back-off
    const time_t now       = time(NULL);
    const time_t THRESHOLD = 60 * 2;

    std::vector<service_node_deregister::vote> result;
    for (const pool_group &deregisters_for : m_deregisters)
    {
      for (auto it = deregisters_for.service_node.begin();
           it != deregisters_for.service_node.end();
           it++)
      {
        const std::vector<pool_entry> &entries = it->second;
        for (const auto &entry : entries)
        {
          const time_t last_sent = now - entry.m_time_last_sent_p2p;
          if (last_sent > THRESHOLD)
          {
            result.push_back(entry.m_vote);
          }
        }
      }
    }
    return result;
  }

  bool deregister_vote_pool::add_vote(const service_node_deregister::vote& new_vote,
                                      cryptonote::vote_verification_context& vvc,
                                      const std::vector<crypto::public_key>& quorum,
                                      cryptonote::transaction &tx)
  {
    if (!service_node_deregister::verify(new_vote, vvc, quorum))
    {
      LOG_PRINT_L1("Verification failed for deregister vote");
      return false;
    }

    CRITICAL_REGION_LOCAL(m_lock);
    time_t const now = time(NULL);
    std::vector<pool_group>::iterator deregisters_for;
    {
      bool group_found = false;
      for (auto it = m_deregisters.begin(); it != m_deregisters.end(); it++)
      {
        if (it->block_height == new_vote.block_height)
        {
          deregisters_for = it;
          group_found = true;
          break;
        }
      }

      if (!group_found)
      {
        m_deregisters.resize(m_deregisters.size() + 1);
        deregisters_for               = m_deregisters.end() - 1;
        deregisters_for->block_height = new_vote.block_height;
        deregisters_for->time_group_created = now;
      }
    }

    bool new_deregister_is_unique             = true;
    const uint32_t deregister_index           = new_vote.service_node_index;
    std::vector<pool_entry> &deregister_votes = deregisters_for->service_node[deregister_index];

    for (const auto &entry : deregister_votes)
    {
      if (entry.m_vote.voters_quorum_index == new_vote.voters_quorum_index)
      {
        new_deregister_is_unique = false;
        break;
      }
    }

    if (new_deregister_is_unique)
    {
      vvc.m_added_to_pool = true;
      deregister_votes.emplace_back(pool_entry(0, new_vote));
      xx__print_service_node();

      if (deregister_votes.size() == quorum.size())
      {
        cryptonote::tx_extra_service_node_deregister deregister;
        deregister.block_height       = new_vote.block_height;
        deregister.service_node_index = new_vote.service_node_index;
        deregister.votes.reserve(deregister_votes.size());

        for (const auto& entry : deregister_votes)
        {
          cryptonote::tx_extra_service_node_deregister::vote tx_vote = {};
          tx_vote.signature           = *reinterpret_cast<const cryptonote::tx_extra_service_node_deregister::signature_pod *>(&new_vote.signature);
          tx_vote.voters_quorum_index = new_vote.voters_quorum_index;
          deregister.votes.push_back(tx_vote);
        }

        vvc.m_full_tx_deregister_made = true;
        tx.version = cryptonote::transaction::version_3_deregister_tx;
        cryptonote::add_service_node_deregister_to_tx_extra(tx.extra, deregister);
      }
    }

    return true;
  }

  void deregister_vote_pool::remove_expired_votes(uint64_t height)
  {
    uint64_t const ALIVE_HEIGHT_WINDOW = 20;
    if (height < ALIVE_HEIGHT_WINDOW)
    {
      return;
    }

    CRITICAL_REGION_LOCAL(m_lock);
    const time_t now                  = time(NULL);
    const time_t ALIVE_SECONDS_WINDOW = DIFFICULTY_TARGET_V2 * ALIVE_HEIGHT_WINDOW;

    uint64_t minimum_height = height - ALIVE_HEIGHT_WINDOW;
    for (auto it = m_deregisters.begin(); it != m_deregisters.end();)
    {
      time_t lifetime = now - it->time_group_created;
      if (it->block_height < minimum_height && lifetime >= ALIVE_SECONDS_WINDOW)
      {
        printf("Removing stale votes from height: %zu, the min height is: %zu || min life time is: %zu\n", it->block_height, minimum_height, ALIVE_SECONDS_WINDOW);
        it = m_deregisters.erase(it);
      }
      else
      {
        it++;
      }
    }
  }
}; // namespace loki
