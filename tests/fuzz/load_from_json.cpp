// Copyright (c) 2017-2018, The Monero Project
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

#include "common/file.h"
#include "epee/serialization/keyvalue_serialization.h"
#include "epee/storages/portable_storage_base.h"
#include "epee/storages/portable_storage_template_helper.h"
#include "fuzzer.h"

class PortableStorageFuzzer : public Fuzzer {
  public:
    PortableStorageFuzzer() {}
    virtual int init();
    virtual int run(const std::string& filename);
};

int PortableStorageFuzzer::init() {
    return 0;
}

int PortableStorageFuzzer::run(const std::string& filename) {
    std::string s;

    if (!tools::slurp_file(filename, s)) {
        std::cout << "Error: failed to load file " << filename << std::endl;
        return 1;
    }
    try {
        epee::serialization::portable_storage ps;
        ps.load_from_json(s);
    } catch (const std::exception& e) {
        std::cerr << "Failed to load from binary: " << e.what() << std::endl;
        return 1;
    }
    return 0;
}

int main(int argc, const char** argv) {
    auto logcat = oxen::log::Cat("fuzz");
    TRY_ENTRY();
    PortableStorageFuzzer fuzzer;
    return run_fuzzer(argc, argv, fuzzer);
    CATCH_ENTRY("main", 1);
}
