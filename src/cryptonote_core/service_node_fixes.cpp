#include "service_node_fixes.h"

#include <crypto/literals.h>

using namespace crypto::literals;

namespace service_nodes {

std::pair<std::vector<hf22_fixup>, std::vector<crypto::public_key>> get_hf22_fixups(
        cryptonote::network_type nettype) {

    std::pair<std::vector<hf22_fixup>, std::vector<crypto::public_key>> result;
    auto& [fixups, pks_to_remove] = result;

    switch (nettype) {
        case cryptonote::network_type::MAINNET:
            fixups = {
                    // clang-format off

                // Blk 1852106/0 state change tx 29cbbd7c683efa10323f9971de69d22a05701e136eb5928a201f68fa143a6f99 confirmed by votes, was sn purge
                // (bls: 081b6d52379146b0127b06875577a83b82f4362a92b8afc99d0697d669c7001d2e1338be37d8d6407e37fa4f80e2ec2a1c2c9cfcbcd54f5d09826a6dc15ce090, key: 488b88449534170e93b6f695840b9f3040239ec7045d9c82ec3e18cba16e3261)
                //   00 0x3adA97D64272aC01cF832E930259f078f337e5A5: 25000.000000000
                //
                // Note that this purge did *not* get properly accounted for in the lifetime stakes
                // accounting because of a different bug that only counted the last one.  This
                // accounting value is corrected in db_sqlite.cpp when upgrading the database upon
                // first 11.4.0 load of an earlier database.
                {HF22Fix::Purge, 1852106, 0, 0, "488b88449534170e93b6f695840b9f3040239ec7045d9c82ec3e18cba16e3261"_edpk, "0x3adA97D64272aC01cF832E930259f078f337e5A5"_eth, 25'000'000'000'000},

                // Blk 1852106/1 state change tx b27eebff80b6187ef5868a5c1c941ae4603c2acfaab258d3282731f3f63216e5 confirmed by votes, was sn purge
                // (bls: 2a4fc9a520571bbc898df9f95616187a582592a1a843fe72ad5923fa763e03f7243a35c61678f14ed380759fa6e03b29c16036a58d5f15f8dfe68a06d8b2670e, key: 2c75c8e0cfacd35dd8f50edd020d584969b31df0a20c794d60a140815a91af62)
                //   00 0x442D88b2E3eAa2357506e5A1eCBfd40cD7Af0fCb: 25000.000000000
                {HF22Fix::Purge, 1852106, 1, 0, "2c75c8e0cfacd35dd8f50edd020d584969b31df0a20c794d60a140815a91af62"_edpk, "0x442D88b2E3eAa2357506e5A1eCBfd40cD7Af0fCb"_eth, 25'000'000'000'000},

                // Blk 1853003/0 state change tx ae78ab38b357db1bee5c34b0d0d64ff4808f60b3a53bb154ea1b0ec4c51ba321 denied by votes, was registration v2
                // (key: 231d574425fa6026d88eae691ecb7da5a92ae3d058b88ce586a808d164f55f98, bls: 23e340d4682c4fa1bd91580ccb5c66aa87463c5de6197b6c505282964c2a29a62d2e4c27db3c565fbba52f244d5524b335dc6ed9bd365d140835daf96f5146db)
                //   00 0x66c968b031592663AAcb6c0CD79C18bb46Eb483C: 6250.000000000
                //   01 0xCf94C6a3F0a483cb7B955740f4894D149BDC584c: 3058.497000000
                //   02 0x778113D050479aC1a5F96fccEfEe33211759c4bD: 2986.821000000
                //   03 0x2B137fD9042eC98C15cd4516799977Bd7BF52253: 3233.690000000
                //   04 0x81131E93535768A5b0D265229252babdC3bB6D3C: 2810.648000000
                //   05 0xB69c582DbaF25dd8aF9cbc8e3Af4D259FbB078E5: 3153.906300000
                //   06 0x557CDDb939d1541B2b82Bc01A229e643A931f9b9: 3506.437700000
                {HF22Fix::Reg, 1853003, 0, 0, "231d574425fa6026d88eae691ecb7da5a92ae3d058b88ce586a808d164f55f98"_edpk, "0x66c968b031592663AAcb6c0CD79C18bb46Eb483C"_eth, 6'250'000'000'000},
                {HF22Fix::Reg, 1853003, 0, 1, "231d574425fa6026d88eae691ecb7da5a92ae3d058b88ce586a808d164f55f98"_edpk, "0xCf94C6a3F0a483cb7B955740f4894D149BDC584c"_eth, 3'058'497'000'000},
                {HF22Fix::Reg, 1853003, 0, 2, "231d574425fa6026d88eae691ecb7da5a92ae3d058b88ce586a808d164f55f98"_edpk, "0x778113D050479aC1a5F96fccEfEe33211759c4bD"_eth, 2'986'821'000'000},
                {HF22Fix::Reg, 1853003, 0, 3, "231d574425fa6026d88eae691ecb7da5a92ae3d058b88ce586a808d164f55f98"_edpk, "0x2B137fD9042eC98C15cd4516799977Bd7BF52253"_eth, 3'233'690'000'000},
                {HF22Fix::Reg, 1853003, 0, 4, "231d574425fa6026d88eae691ecb7da5a92ae3d058b88ce586a808d164f55f98"_edpk, "0x81131E93535768A5b0D265229252babdC3bB6D3C"_eth, 2'810'648'000'000},
                {HF22Fix::Reg, 1853003, 0, 5, "231d574425fa6026d88eae691ecb7da5a92ae3d058b88ce586a808d164f55f98"_edpk, "0xB69c582DbaF25dd8aF9cbc8e3Af4D259FbB078E5"_eth, 3'153'906'300'000},
                {HF22Fix::Reg, 1853003, 0, 6, "231d574425fa6026d88eae691ecb7da5a92ae3d058b88ce586a808d164f55f98"_edpk, "0x557CDDb939d1541B2b82Bc01A229e643A931f9b9"_eth, 3'506'437'700'000},

                // Blk 1853002/0 state change tx 68c66840c06891e49f5a4686bf7963f6c992222175a3ce26572942187774c3e9 denied by votes, was registration v2
                // (key: da2b08e1018c66b4e05011adc7c8dd4b335bb0fc6473a60aba9fb1ec11dd8055, bls: 0db6d3e6b4b6a37323a5637a69b91d34a0e2c920d54a71d0f1c89d43ece1d52c2c173ce267dc081cc9e1ad9d9e83eba6bb3e7377d3be78ac100d6a84141c1e7d)
                //   00 0x66c968b031592663AAcb6c0CD79C18bb46Eb483C: 6250.000000000
                //   01 0x38E1fBB32B121Ea18BFd005131c4b06886b306B1: 6132.066900000
                //   02 0xA621d6869D9092a171A05B6c4eDF49b9CA50F0C8: 2189.242200000
                //   03 0x3A722cdaEd11a45873080CfC4Eb584F31A0aCBC0: 2100.674200000
                //   04 0x7AaF70e681F17aae9284dC311431341CB7b64A43: 4291.000000000
                //   05 0xcA7e33614AF24Ae6fe62e0147Bf386CC5aa25EB5: 4037.016700000
                {HF22Fix::Reg, 1853002, 0, 0, "da2b08e1018c66b4e05011adc7c8dd4b335bb0fc6473a60aba9fb1ec11dd8055"_edpk, "0x66c968b031592663AAcb6c0CD79C18bb46Eb483C"_eth, 6'250'000'000'000},
                {HF22Fix::Reg, 1853002, 0, 1, "da2b08e1018c66b4e05011adc7c8dd4b335bb0fc6473a60aba9fb1ec11dd8055"_edpk, "0x38E1fBB32B121Ea18BFd005131c4b06886b306B1"_eth, 6'132'066'900'000},
                {HF22Fix::Reg, 1853002, 0, 2, "da2b08e1018c66b4e05011adc7c8dd4b335bb0fc6473a60aba9fb1ec11dd8055"_edpk, "0xA621d6869D9092a171A05B6c4eDF49b9CA50F0C8"_eth, 2'189'242'200'000},
                {HF22Fix::Reg, 1853002, 0, 3, "da2b08e1018c66b4e05011adc7c8dd4b335bb0fc6473a60aba9fb1ec11dd8055"_edpk, "0x3A722cdaEd11a45873080CfC4Eb584F31A0aCBC0"_eth, 2'100'674'200'000},
                {HF22Fix::Reg, 1853002, 0, 4, "da2b08e1018c66b4e05011adc7c8dd4b335bb0fc6473a60aba9fb1ec11dd8055"_edpk, "0x7AaF70e681F17aae9284dC311431341CB7b64A43"_eth, 4'291'000'000'000},
                {HF22Fix::Reg, 1853002, 0, 5, "da2b08e1018c66b4e05011adc7c8dd4b335bb0fc6473a60aba9fb1ec11dd8055"_edpk, "0xcA7e33614AF24Ae6fe62e0147Bf386CC5aa25EB5"_eth, 4'037'016'700'000},

                // Blk 1852999/0 state change tx 9a9b1c2416c33a034446c8829d0bfd280f7f71390b3c240a1573e6ae871bc2dd denied by votes, was registration v2
                // (key: 966056fc975e65908b9b3ac896649021679a725025e91a0a79bf3147a6a777ac, bls: 0c40f1c16f819b15bcace9066641518c9de1f726e379586d6ed2ca22710cebfa0fa9a10f7dc565bd2f1f319f8407c63c0ddd9ae1b8511bdb302eadd1e2b03f6b)
                //   00 0x66c968b031592663AAcb6c0CD79C18bb46Eb483C: 6250.000000000
                //   01 0x4Cf48e2834C2e2d221b010D0720D81136E7A554b: 6432.000000000
                //   02 0x87332b867DF656C715d808A5Aa172F7bF5c2DFF6: 9524.453000000
                //   03 0x11B9C7477307CB63731f9657DD16dc420f47D265: 2076.275300000
                //   04 0x3A722cdaEd11a45873080CfC4Eb584F31A0aCBC0: 717.271700000
                {HF22Fix::Reg, 1852999, 0, 0, "966056fc975e65908b9b3ac896649021679a725025e91a0a79bf3147a6a777ac"_edpk, "0x66c968b031592663AAcb6c0CD79C18bb46Eb483C"_eth, 6'250'000'000'000},
                {HF22Fix::Reg, 1852999, 0, 1, "966056fc975e65908b9b3ac896649021679a725025e91a0a79bf3147a6a777ac"_edpk, "0x4Cf48e2834C2e2d221b010D0720D81136E7A554b"_eth, 6'432'000'000'000},
                {HF22Fix::Reg, 1852999, 0, 2, "966056fc975e65908b9b3ac896649021679a725025e91a0a79bf3147a6a777ac"_edpk, "0x87332b867DF656C715d808A5Aa172F7bF5c2DFF6"_eth, 9'524'453'000'000},
                {HF22Fix::Reg, 1852999, 0, 3, "966056fc975e65908b9b3ac896649021679a725025e91a0a79bf3147a6a777ac"_edpk, "0x11B9C7477307CB63731f9657DD16dc420f47D265"_eth, 2'076'275'300'000},
                {HF22Fix::Reg, 1852999, 0, 4, "966056fc975e65908b9b3ac896649021679a725025e91a0a79bf3147a6a777ac"_edpk, "0x3A722cdaEd11a45873080CfC4Eb584F31A0aCBC0"_eth, 717'271'700'000},

                // Blk 1853017/0 state change tx cc8dafe383374bd5fc0811d755a397d06974c820a2662532a7910195f096f5f6 denied by votes, was registration v2
                // (key: 9f0eccf89421cf6b2c9db1919ddccae4983f35fbbdb46814c43c58246d6606b3, bls: 028813ac9255f0023ad0a54d995b583a51ef081471777497f26ddddaefb062422405597150a150ada23692fa91e6521e44d8de3390cf257e19ce1978755674b5)
                //   00 0x226Fa898550EF48313d359d90F69914018a89F73: 6250.000000000
                //   01 0xDB017D96E78D05b41C1AaD7F9224943893a4b969: 1782.000000000
                //   02 0x155707DfE98D93892FE9F73945f9763b58cE0576: 3728.000000000
                //   03 0xa414cFf0c72D83FF1A42F73d2063aB1d1E31fe46: 3812.000000000
                //   04 0xED79690cC83b40B33F934A1416CDC105Cb983F22: 9428.000000000
                {HF22Fix::Reg, 1853017, 0, 0, "9f0eccf89421cf6b2c9db1919ddccae4983f35fbbdb46814c43c58246d6606b3"_edpk, "0x226Fa898550EF48313d359d90F69914018a89F73"_eth, 6'250'000'000'000},
                {HF22Fix::Reg, 1853017, 0, 1, "9f0eccf89421cf6b2c9db1919ddccae4983f35fbbdb46814c43c58246d6606b3"_edpk, "0xDB017D96E78D05b41C1AaD7F9224943893a4b969"_eth, 1'782'000'000'000},
                {HF22Fix::Reg, 1853017, 0, 2, "9f0eccf89421cf6b2c9db1919ddccae4983f35fbbdb46814c43c58246d6606b3"_edpk, "0x155707DfE98D93892FE9F73945f9763b58cE0576"_eth, 3'728'000'000'000},
                {HF22Fix::Reg, 1853017, 0, 3, "9f0eccf89421cf6b2c9db1919ddccae4983f35fbbdb46814c43c58246d6606b3"_edpk, "0xa414cFf0c72D83FF1A42F73d2063aB1d1E31fe46"_eth, 3'812'000'000'000},
                {HF22Fix::Reg, 1853017, 0, 4, "9f0eccf89421cf6b2c9db1919ddccae4983f35fbbdb46814c43c58246d6606b3"_edpk, "0xED79690cC83b40B33F934A1416CDC105Cb983F22"_eth, 9'428'000'000'000},

                // NOTE: A request to unlock that was denied has minor side effects. It stops the
                // 15 day unlock timer from starting. The user is allowed to request exit on the
                // smart contract 1 hour after their last attempt hence there is no action to be
                // taken here.
                // Blk 1853013/0 state change tx a9986b14747098914621ae31d9017492c7573d2731d3255c3d079ef9a8c527e6 denied by expiry, was unlock
                // (bls: 0788748bc2d87188f7922dad1531f38652f739a143fbdb8d8ae62ca663b3eaec19c557802785bcdc3c5f02611b6ddc0e75645f012520646a24e49fdd3ac365ff, key: a06122ddbc339b090e7f05590fa59741c8b931a454410b7c83652bdfeb605375)

                // Blk 1853022/0 state change tx 0c51e6c92a57550cb142840e64111153c3846c143858b7175dd366ae1dfb9aa9 denied by expiry, was registration v2
                // (key: 3104e0573435846514794c429a571115cde1fe1b4f4c5399284af7829e34a0b6, bls: 1f6e3d22b64b7661c1fbabe21fff54e5187dfd5e0b708c15b1e595f7d88a68111d5de443dd7914e4622b1871cc3cfd87a21be88c9b9110bb60028c84948358fe)
                //   00 0x226Fa898550EF48313d359d90F69914018a89F73: 6250.000000000
                //   01 0xD8413762Fe3C797769BeAC1140D98994FaC81479: 3985.000000000
                //   02 0xB257b68301aFF55C2d13499F0F7bC9998343E197: 3780.000000000
                //   03 0xaEE7f38ff2F8e096e83519d0c0d398b6c1581CA9: 3732.000000000
                //   04 0x1062d876BD363311bC209c9dDc8b4AF9f1C5BF9b: 3846.000000000
                //   05 0x1F352714a58625E7673Bd9161AC0F92629A0079e: 3407.000000000
                {HF22Fix::Reg, 1853022, 0, 0, "3104e0573435846514794c429a571115cde1fe1b4f4c5399284af7829e34a0b6"_edpk, "0x226Fa898550EF48313d359d90F69914018a89F73"_eth, 6'250'000'000'000},
                {HF22Fix::Reg, 1853022, 0, 1, "3104e0573435846514794c429a571115cde1fe1b4f4c5399284af7829e34a0b6"_edpk, "0xD8413762Fe3C797769BeAC1140D98994FaC81479"_eth, 3'985'000'000'000},
                {HF22Fix::Reg, 1853022, 0, 2, "3104e0573435846514794c429a571115cde1fe1b4f4c5399284af7829e34a0b6"_edpk, "0xB257b68301aFF55C2d13499F0F7bC9998343E197"_eth, 3'780'000'000'000},
                {HF22Fix::Reg, 1853022, 0, 3, "3104e0573435846514794c429a571115cde1fe1b4f4c5399284af7829e34a0b6"_edpk, "0xaEE7f38ff2F8e096e83519d0c0d398b6c1581CA9"_eth, 3'732'000'000'000},
                {HF22Fix::Reg, 1853022, 0, 4, "3104e0573435846514794c429a571115cde1fe1b4f4c5399284af7829e34a0b6"_edpk, "0x1062d876BD363311bC209c9dDc8b4AF9f1C5BF9b"_eth, 3'846'000'000'000},
                {HF22Fix::Reg, 1853022, 0, 5, "3104e0573435846514794c429a571115cde1fe1b4f4c5399284af7829e34a0b6"_edpk, "0x1F352714a58625E7673Bd9161AC0F92629A0079e"_eth, 3'407'000'000'000},

                // NOTE: See denied exit-request above, there is no action to be taken here.
                // Blk 1853100/0 state change tx 574f1a43a498f2886ecf0b10f73998de6481ff8510f194b5822ccc7bce6c3970 denied by expiry, was unlock
                // (bls: 09685275494887567472bec663705cad3c197ffe0b2fc36a2c84bd684bdef4990a5a3c3bdc929e8dc759c088dcd8434829e37f4cd29dcf2b02320728ecea1816, key: f09e15702057949dffefe5260e121552751361e86fcab26d5ec1714022b9ddfc)

                // Blk 1854383/0 state change tx ac507b47640d8afc5bc4b5a8430743bffae2a699803246ff89ea0f9342b3facb denied by votes, was registration v2
                // (key: 304456e3d61b05560a855fd2adc8e4fe062b9450f16f79d71132ca07a33eb633, bls: 08e2b2207473fbfe95435c15a94126ab1db0e5e16693792f64927795af2f66821b4f94ab6302947d5d813edce2bb141b0fd0062cabccc29422198bfcb76e923f)
                //   00 0x1C2b2E766b4441e56A90594b00710bc397F129e1: 6250.000000000
                //   01 0xC4f9131d3Cd82E0728e425a2902B4c1dff2314a7: 2270.000000000
                //   02 0x83ae44bf6C5053ff20d592902d9c43eEA1bB38Ec: 4016.000000000
                //   03 0x41349071f757cC6262Db9F785B96d8d51044eA3a: 3943.000000000
                //   04 0x7Fcba28a59C8fd78daB8Bb1CeD1688489517f21c: 5069.000000000
                //   05 0x24A9D200dB7f91d0ed40AD6bF8986b081D50D015: 3452.000000000
                {HF22Fix::Reg, 1854383, 0, 0, "304456e3d61b05560a855fd2adc8e4fe062b9450f16f79d71132ca07a33eb633"_edpk, "0x1C2b2E766b4441e56A90594b00710bc397F129e1"_eth, 6'250'000'000'000},
                {HF22Fix::Reg, 1854383, 0, 1, "304456e3d61b05560a855fd2adc8e4fe062b9450f16f79d71132ca07a33eb633"_edpk, "0xC4f9131d3Cd82E0728e425a2902B4c1dff2314a7"_eth, 2'270'000'000'000},
                {HF22Fix::Reg, 1854383, 0, 2, "304456e3d61b05560a855fd2adc8e4fe062b9450f16f79d71132ca07a33eb633"_edpk, "0x83ae44bf6C5053ff20d592902d9c43eEA1bB38Ec"_eth, 4'016'000'000'000},
                {HF22Fix::Reg, 1854383, 0, 3, "304456e3d61b05560a855fd2adc8e4fe062b9450f16f79d71132ca07a33eb633"_edpk, "0x41349071f757cC6262Db9F785B96d8d51044eA3a"_eth, 3'943'000'000'000},
                {HF22Fix::Reg, 1854383, 0, 4, "304456e3d61b05560a855fd2adc8e4fe062b9450f16f79d71132ca07a33eb633"_edpk, "0x7Fcba28a59C8fd78daB8Bb1CeD1688489517f21c"_eth, 5'069'000'000'000},
                {HF22Fix::Reg, 1854383, 0, 5, "304456e3d61b05560a855fd2adc8e4fe062b9450f16f79d71132ca07a33eb633"_edpk, "0x24A9D200dB7f91d0ed40AD6bF8986b081D50D015"_eth, 3'452'000'000'000},

                // Blk 1854380/0 state change tx f7adbd955ef7b9e0e19dcc519229f88db1e3dd6db1bb372e13d34b52ccb8caad denied by expiry, was registration v2
                // (key: 8945537c50fa966bd28765d8373973351ef39ea5468b4ea0e0ccb51a3452d705, bls: 0685f9ee1b64ab54f33dcd3ff96a90bb7416a7a1d6c77c84f819225527725011104e8e2be70ab5cecda2c9bf1d67a1048bac5d8c0b1abf1781dd162e1e835305)
                //   00 0xC69955a2ffec718C53497328b96d16CF3351A80c: 6250.000000000
                //   01 0xaf27EF9c0ea760E42052ccAd0E3CeD0b2542d440: 5630.000000000
                //   02 0x6C2dbB55d8612e6DaB545C02DeaA922DE7698D33: 5473.000000000
                //   03 0xa47e4D6F3E27C9de69377A8be422CCf527d7bB66: 5315.000000000
                //   04 0x4379C83B663Aa7469564B08B32c6898198A7Fc86: 2332.000000000
                {HF22Fix::Reg, 1854380, 0, 0, "8945537c50fa966bd28765d8373973351ef39ea5468b4ea0e0ccb51a3452d705"_edpk, "0xC69955a2ffec718C53497328b96d16CF3351A80c"_eth, 6'250'000'000'000},
                {HF22Fix::Reg, 1854380, 0, 1, "8945537c50fa966bd28765d8373973351ef39ea5468b4ea0e0ccb51a3452d705"_edpk, "0xaf27EF9c0ea760E42052ccAd0E3CeD0b2542d440"_eth, 5'630'000'000'000},
                {HF22Fix::Reg, 1854380, 0, 2, "8945537c50fa966bd28765d8373973351ef39ea5468b4ea0e0ccb51a3452d705"_edpk, "0x6C2dbB55d8612e6DaB545C02DeaA922DE7698D33"_eth, 5'473'000'000'000},
                {HF22Fix::Reg, 1854380, 0, 3, "8945537c50fa966bd28765d8373973351ef39ea5468b4ea0e0ccb51a3452d705"_edpk, "0xa47e4D6F3E27C9de69377A8be422CCf527d7bB66"_eth, 5'315'000'000'000},
                {HF22Fix::Reg, 1854380, 0, 4, "8945537c50fa966bd28765d8373973351ef39ea5468b4ea0e0ccb51a3452d705"_edpk, "0x4379C83B663Aa7469564B08B32c6898198A7Fc86"_eth, 2'332'000'000'000},

                // Blk 1854403/0 state change tx d3839d1105e70274a5d2c3cd3462f0e31fe567d11d7e014bc30d7e1a14075b8a denied by expiry, was exit
                // (op: 0x76510193cAE84056150d3426fB6ACCD0bC0682a7; key: 0bc61ecbd86839f21dc7ed7598f7c8d8c644d6541149e86672a8ca75fff99456; returned: 25000000000000)
                //   00 0x76510193cAE84056150d3426fB6ACCD0bC0682a7: 6250.000000001
                //   01 0x6D20Cb170F100151cDF637656B9e55D427461AAA: 5636.666666666
                //   02 0x48808fFe48efC3Aa7266C1C7e3226C284FD83988: 4730.000000000
                //   03 0xCfbbD8AC14Fe4c0b9098bC2A9515b004B7429c6D: 4710.000000000
                //   04 0xbb726dd6BEEe92ae4C6C61cBEa0eD64E4bCb38fF: 3333.333333333
                //   05 0x4F6ecBCC4bD165eb95Ca2A8107Ddc60671eC84Ad: 340.000000000
                {HF22Fix::Exit, 1854403, 0, 0, "0bc61ecbd86839f21dc7ed7598f7c8d8c644d6541149e86672a8ca75fff99456"_edpk, "0x76510193cAE84056150d3426fB6ACCD0bC0682a7"_eth, 6250'000'000'001},
                {HF22Fix::Exit, 1854403, 0, 1, "0bc61ecbd86839f21dc7ed7598f7c8d8c644d6541149e86672a8ca75fff99456"_edpk, "0x6D20Cb170F100151cDF637656B9e55D427461AAA"_eth, 5636'666'666'666},
                {HF22Fix::Exit, 1854403, 0, 2, "0bc61ecbd86839f21dc7ed7598f7c8d8c644d6541149e86672a8ca75fff99456"_edpk, "0x48808fFe48efC3Aa7266C1C7e3226C284FD83988"_eth, 4730'000'000'000},
                {HF22Fix::Exit, 1854403, 0, 3, "0bc61ecbd86839f21dc7ed7598f7c8d8c644d6541149e86672a8ca75fff99456"_edpk, "0xCfbbD8AC14Fe4c0b9098bC2A9515b004B7429c6D"_eth, 4710'000'000'000},
                {HF22Fix::Exit, 1854403, 0, 4, "0bc61ecbd86839f21dc7ed7598f7c8d8c644d6541149e86672a8ca75fff99456"_edpk, "0xbb726dd6BEEe92ae4C6C61cBEa0eD64E4bCb38fF"_eth, 3333'333'333'333},
                {HF22Fix::Exit, 1854403, 0, 5, "0bc61ecbd86839f21dc7ed7598f7c8d8c644d6541149e86672a8ca75fff99456"_edpk, "0x4F6ecBCC4bD165eb95Ca2A8107Ddc60671eC84Ad"_eth, 340'000'000'000},

                    // clang-format on
            };
            pks_to_remove = {"0bc61ecbd86839f21dc7ed7598f7c8d8c644d6541149e86672a8ca75fff99456"_pk};
            break;

        case cryptonote::network_type::TESTNET:
            // FIXME - add dummy values for testing
            fixups = {

                    // clang-format off

                {HF22Fix::Purge, 790188, 0, 0, "84271c77e6863190f7a2d088088083d7439fd17e45b93906aed3e62d626123bb"_edpk, "0xB0CefD61ddB88176Fb972955341adC6c1d05230e"_eth, 20'000'000'000'000},
                {HF22Fix::Purge, 790188, 1, 0, "d6957e48b0053e36f3fcba8c37f4db00842544a229f80ec888fab31f00f15672"_edpk, "0x00979F83287a7eD917faA37bB1DA51f9f7aEb767"_eth, 20'000'000'000'000},

                {HF22Fix::Reg, 789456, 0, 0, "32889030dc8cde311d691c68263882d9a62b087b920d53725b781517b41fbae7"_edpk, "0xB0CefD61ddB88176Fb972955341adC6c1d05230e"_eth, 5'000'000'000'000},
                {HF22Fix::Reg, 789456, 0, 1, "32889030dc8cde311d691c68263882d9a62b087b920d53725b781517b41fbae7"_edpk, "0xB7649B5A5DfABAA0713ACFB3040945035b0bBD9e"_eth, 2'308'497'000'000},
                {HF22Fix::Reg, 789456, 0, 2, "32889030dc8cde311d691c68263882d9a62b087b920d53725b781517b41fbae7"_edpk, "0xb82Cd271CE0E498e4203AC4db801698Bd720f6AF"_eth, 2'986'821'000'000},
                {HF22Fix::Reg, 789456, 0, 3, "32889030dc8cde311d691c68263882d9a62b087b920d53725b781517b41fbae7"_edpk, "0x00979F83287a7eD917faA37bB1DA51f9f7aEb767"_eth, 2'233'690'000'000},
                {HF22Fix::Reg, 789456, 0, 4, "32889030dc8cde311d691c68263882d9a62b087b920d53725b781517b41fbae7"_edpk, "0xfe288fc67cea4014f7fe47054352f559badd281e"_eth, 2'810'648'000'000},
                {HF22Fix::Reg, 789456, 0, 5, "32889030dc8cde311d691c68263882d9a62b087b920d53725b781517b41fbae7"_edpk, "0x8850214b39f70b36d5c81e08d746a0fc3d89d2d5"_eth, 2'153'906'300'000},
                {HF22Fix::Reg, 789456, 0, 6, "32889030dc8cde311d691c68263882d9a62b087b920d53725b781517b41fbae7"_edpk, "0x684de77897a2038b77a76ab4794ca2f627268039"_eth, 2'506'437'700'000},

                {HF22Fix::Reg, 789567, 0, 0, "ab3236f70b37ca974ea5783dc5e84e8ae0e58b9642a2dab93ed595b4ace7af50"_edpk, "0xB0CefD61ddB88176Fb972955341adC6c1d05230e"_eth, 5'666'666'666'667},
                {HF22Fix::Reg, 789567, 0, 1, "ab3236f70b37ca974ea5783dc5e84e8ae0e58b9642a2dab93ed595b4ace7af50"_edpk, "0xb7649b5a5dfabaa0713acfb3040945035b0bbd9e"_eth, 14'333'333'333'333},

                // This one (a denied contract liquidation) was actually on chain (using a hacked up oxend to deliberately introduce to l2 vote denial bug):
                // Blk 790037/0 state change tx 5ee77e298ab4927ffd858b96ee0349c3de0408572e2d12fa1cddd31d67ef25c9 denied by vote, was exit
                // (op: 0xFe288fC67cEa4014F7fE47054352f559BAdD281E; key: f4a895743bd4171ed97bdf162be9f6f4a1013a757dfedfdc7f12a125a74c08d7; returned: 19960000000000)
                {HF22Fix::Exit, 790037, 0, 0, "f4a895743bd4171ed97bdf162be9f6f4a1013a757dfedfdc7f12a125a74c08d7"_edpk, "0xFe288fC67cEa4014F7fE47054352f559BAdD281E"_eth, 19'960'000'000'000},

                    // clang-format on

            };
            pks_to_remove = {"f4a895743bd4171ed97bdf162be9f6f4a1013a757dfedfdc7f12a125a74c08d7"_pk};
            break;

        default: break;
    }

    return result;
}

}  // namespace service_nodes
