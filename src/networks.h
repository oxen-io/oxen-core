#pragma once

#include <boost/uuid/uuid.hpp>
#include <string_view>

#include "common/exception.h"
#include "common/fs.h"
#include "cryptonote_config.h"
#include "network_config/devnet.h"
#include "network_config/fakechain.h"
#include "network_config/localdev.h"
#include "network_config/mainnet.h"
#include "network_config/network_config.h"
#include "network_config/stagenet.h"
#include "network_config/testnet.h"

using namespace std::literals;

namespace cryptonote {

inline constexpr std::array ALL_NETWORKS = {
        network_type::MAINNET,
        network_type::STAGENET,
        network_type::TESTNET,
        network_type::DEVNET,
        network_type::LOCALDEV,
        network_type::FAKECHAIN,
};

constexpr network_type network_type_from_string(std::string_view s) {
    return s == "mainnet"sv   ? network_type::MAINNET
         : s == "testnet"sv   ? network_type::TESTNET
         : s == "devnet"sv    ? network_type::DEVNET
         : s == "stagenet"sv  ? network_type::STAGENET
         : s == "localdev"sv  ? network_type::LOCALDEV
         : s == "fakechain"sv ? network_type::FAKECHAIN
                              : network_type::UNDEFINED;
}

constexpr std::string_view network_type_to_string(network_type t) {
    switch (t) {
        case network_type::MAINNET: return "mainnet"sv;
        case network_type::TESTNET: return "testnet"sv;
        case network_type::DEVNET: return "devnet"sv;
        case network_type::STAGENET: return "stagenet"sv;
        case network_type::LOCALDEV: return "localdev"sv;
        case network_type::FAKECHAIN: return "fakechain"sv;
        case network_type::UNDEFINED: break;
    }
    return "undefined";
}

inline constexpr const network_config& get_config(network_type nettype) {
    switch (nettype) {
        case network_type::MAINNET: return config::mainnet::config;
        case network_type::STAGENET: return config::stagenet::config;
        case network_type::TESTNET: return config::testnet::config;
        case network_type::DEVNET: return config::devnet::config;
        case network_type::LOCALDEV: return config::localdev::config;
        case network_type::FAKECHAIN: return config::fakechain::config;
        case network_type::UNDEFINED: break;
    }
    throw oxen::traced<std::runtime_error>{"Invalid network type"};
}

inline std::filesystem::path network_config_subdir(network_type t) {
    fs::path result;
    if (auto subdir = get_config(t).DEFAULT_CONFIG_SUBDIR; !subdir.empty())
        result = tools::utf8_path(subdir);
    return result;
}

}  // namespace cryptonote
