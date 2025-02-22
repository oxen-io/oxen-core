// Copyright (c) 2014-2019, The Monero Project
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
//
// Parts of this file are originally copyright (c) 2012-2013 The Cryptonote developers

#pragma once

#include <boost/archive/binary_iarchive.hpp>
#include <boost/archive/portable_binary_iarchive.hpp>
#include <boost/archive/portable_binary_oarchive.hpp>
#include <fstream>

#include "epee/misc_log_ex.h"
#include "fs.h"

namespace tools {
template <class T>
bool serialize_obj_to_file(T& obj, const fs::path& file_path) {
    auto logcat = oxen::log::Cat("serialization");
    TRY_ENTRY();
    std::ofstream data_file{file_path, std::ios::binary | std::ios::trunc};
    if (data_file.fail())
        return false;

    boost::archive::portable_binary_oarchive{data_file} << obj;

    if (data_file.fail())
        return false;

    data_file.flush();

    return true;
    CATCH_ENTRY("serialize_obj_to_file", false);
}

template <class T>
bool unserialize_obj_from_file(T& obj, const fs::path& file_path) {
    auto logcat = oxen::log::Cat("serialization");
    TRY_ENTRY();

    std::ifstream data_file{file_path, std::ios_base::binary};
    if (data_file.fail())
        return false;
    try {
        // first try reading in portable mode
        boost::archive::portable_binary_iarchive{data_file} >> obj;
    } catch (...) {
        // if failed, try reading in unportable mode
        auto unportable = file_path;
        unportable += ".unportable";
        fs::copy_file(file_path, unportable, fs::copy_options::overwrite_existing);
        data_file.close();
        data_file.open(file_path, std::ios_base::binary);
        if (data_file.fail())
            return false;
        boost::archive::binary_iarchive{data_file} >> obj;
    }
    return !data_file.fail();
    CATCH_ENTRY("unserialize_obj_from_file", false);
}
}  // namespace tools
