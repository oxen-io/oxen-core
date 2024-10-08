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

#include <array>
#include <boost/program_options/options_description.hpp>
#include <boost/program_options/parsers.hpp>
#include <boost/program_options/value_semantic.hpp>
#include <boost/program_options/variables_map.hpp>
#include <concepts>
#include <functional>
#include <type_traits>
#include <variant>

#include "common/format.h"
#include "common/i18n.h"
#include "common/meta.h"
#include "common/string_util.h"
#include "cryptonote_config.h"
#include "logging/oxen_logger.h"

namespace command_line {
namespace log = oxen::log;

inline const char* tr(const char* str) {
    return i18n_translate(str, "command_line");
}

/// @return True if `str` is (case-insensitively) y, yes, a potentially translated yes, or any of
/// the optional extra arguments passed in.
template <typename S, typename... More>
bool is_yes(const S& str, const More&... more) {
    return tools::string_iequal_any(str, "y", "yes", tr("yes"), more...);
}
/// @return True if `str` is (case-insensitively) n, no, or a potentially translated no, or any of
/// the optional extra arguments passed in.
template <typename S, typename... More>
bool is_no(const S& str, const More&... more) {
    return tools::string_iequal_any(str, "n", "no", tr("no"), more...);
}
/// @return True if `str` is (case-insensitively) c, cancel, or a potentially translated cancel,
/// or any of the optional extra arguments passed in.
template <typename S, typename... More>
bool is_cancel(const S& str, const More&... more) {
    return tools::string_iequal_any(str, "c", "cancel", tr("cancel"), more...);
}
/// @return True if `str` is (case-insensitively) b, back, or a potentially translated back, or
/// any of the optional extra arguments passed in.
template <typename S, typename... More>
bool is_back(const S& str, const More&... more) {
    return tools::string_iequal_any(str, "b", "back", tr("back"), more...);
}

struct required_t {};
constexpr inline required_t required{};

// Extra values that can be specified in a arg_descriptor constructor.  Currently supports just
// `required` (but doesn't allow even that for a `bool` argument).
template <typename Opt, typename T>
concept arg_option = (std::same_as<required_t, T> && !std::same_as<Opt, bool>);

namespace {
    template <typename T>
    std::string arg_stringify(const T& a) {
        return "{}"_format(a);
    }
    template <typename T>
    std::string arg_stringify(const std::vector<T>& v) {
        return v.empty() ? "" : "[{}]"_format(fmt::join(v, ","));
    }
}  // namespace

template <typename T>
struct arg_descriptor {
    using value_type = T;

    using default_cb = std::function<T(cryptonote::network_type)>;

    std::string name;
    std::string description;
    // The default value variant: will be required_t for a no-default, required argument; otherwise
    // a fixed default, or a network-dependent callback that returns the default.
    std::variant<required_t, T, default_cb> default_value;

    // Constructs an non-required arg descriptor from a name, description, and default-constructed
    // T for default value.
    template <arg_option<T>... Opts>
    arg_descriptor(std::string name, std::string description) :
            name{std::move(name)}, description{std::move(description)}, default_value{T{}} {}

    // Constructs an non-required arg descriptor from a name, description, and default value.  This
    // constructor is not available if T is bool (flags always default to false).
    template <arg_option<T>... Opts>
    arg_descriptor(std::string name, std::string description, T def)
        requires(!std::same_as<T, bool>)
            :
            name{std::move(name)},
            description{std::move(description)},
            default_value{std::move(def)} {}

    // Constructs an arg descriptor for a required argument.  This constructor is not available if T
    // is bool (flags can never be required).
    template <arg_option<T>... Opts>
    arg_descriptor(std::string name, std::string description, required_t)
        requires(!std::same_as<T, bool>)
            : name{std::move(name)}, description{std::move(description)}, default_value{required} {}

    // Constructs a non-required arg descriptor with a name, description, and network-dependent
    // default value callback.
    arg_descriptor(std::string name, std::string description, default_cb get_default) :
            name{std::move(name)},
            description{std::move(description)},
            default_value{std::move(get_default)} {}

    boost::program_options::typed_value<T, char>* make_semantic() const {
        if constexpr (std::same_as<bool, T>)
            return boost::program_options::bool_switch();
        auto* semantic = boost::program_options::value<T>();
        if (std::holds_alternative<required_t>(default_value))
            semantic->required();
        else if (auto* def = std::get_if<T>(&default_value)) {
            if constexpr (!std::same_as<bool, T>)
                semantic->default_value(*def, arg_stringify(*def));
        } else {
            auto* cb_ptr = std::get_if<default_cb>(&default_value);
            assert(cb_ptr && *cb_ptr);
            auto& cb = *cb_ptr;
            auto mainnet_default = cb(cryptonote::network_type::MAINNET);
            std::string default_disp = "{}; {}/{}/{} for stage/test/dev networks"_format(
                    arg_stringify(mainnet_default),
                    arg_stringify(cb(cryptonote::network_type::STAGENET)),
                    arg_stringify(cb(cryptonote::network_type::TESTNET)),
                    arg_stringify(cb(cryptonote::network_type::DEVNET)));
            semantic->default_value(std::move(mainnet_default), std::move(default_disp));
        }

        return semantic;
    }
};

using arg_flag = arg_descriptor<bool>;

template <typename T>
void add_arg(
        boost::program_options::options_description& description, const arg_descriptor<T>& arg) {
    if (0 != description.find_nothrow(arg.name, false)) {
        log::error(globallogcat, "Argument already exists: {}", arg.name);
        return;
    }

    description.add_options()(arg.name.c_str(), arg.make_semantic(), arg.description.c_str());
}

template <typename charT>
boost::program_options::basic_parsed_options<charT> parse_command_line(
        int argc,
        const charT* const argv[],
        const boost::program_options::options_description& desc,
        bool allow_unregistered = false) {
    auto parser = boost::program_options::command_line_parser(argc, argv);
    parser.options(desc);
    if (allow_unregistered) {
        parser.allow_unregistered();
    }
    return parser.run();
}

bool handle_error_helper(
        const boost::program_options::options_description& desc, std::function<bool()> parser);

template <typename T>
    requires(!std::same_as<T, bool>)
bool has_arg(const boost::program_options::variables_map& vm, const arg_descriptor<T>& arg) {
    auto value = vm[arg.name];
    return !value.empty();
}

template <typename T>
bool is_arg_defaulted(
        const boost::program_options::variables_map& vm, const arg_descriptor<T>& arg) {
    return vm[arg.name].defaulted();
}

/// Adds the --testnet, --devnet, etc. arguments to an options_description.  Use `get_network(vm)`
/// after parsing CLI arguments to see which network is implied by the flags.
void add_network_args(boost::program_options::options_description& od);

/// Returns the network type implied by the current testnet/devnet/etc. network selection flags.
cryptonote::network_type get_network(const boost::program_options::variables_map& vm);

template <typename T>
T get_arg(const boost::program_options::variables_map& vm, const arg_descriptor<T>& arg) {
    using default_cb = arg_descriptor<T>::default_cb;
    if (is_arg_defaulted(vm, arg)) {
        if (auto* cb = std::get_if<default_cb>(&arg.default_value)) {
            assert(*cb);
            return (*cb)(get_network(vm));
        }
    }
    return vm[arg.name].template as<T>();
}

// Same as above, but fetches multiple arguments at once:
template <tools::instantiation_of<arg_descriptor>... ArgDescriptor>
std::tuple<typename ArgDescriptor::value_type...> get_args(
        const boost::program_options::variables_map& vm, const ArgDescriptor&... arg) {
    return std::make_tuple(get_arg(vm, arg)...);
}

extern const arg_flag arg_help;
extern const arg_flag arg_version;

// Network type arguments; we handle these centrally, here, as various other options defined
// elsewhere have defaults that depend on the network type.
extern const arg_flag arg_testnet;
extern const arg_flag arg_devnet;
extern const arg_flag arg_regtest;
extern const arg_flag arg_stagenet;
extern const arg_flag arg_localdev;

/// Returns the terminal width and height (in characters), if supported on this system and
/// available.  Returns {0,0} if not available or could not be determined.
std::pair<unsigned, unsigned> terminal_size();

/// Returns the ideal line width and description width values for
/// boost::program_options::options_description, using the terminal width (if available).  Returns
/// the boost defaults if terminal width isn't available.
std::pair<unsigned, unsigned> boost_option_sizes();

// Clears the screen using readline, if available, otherwise trying some terminal escape hacks.
void clear_screen();
}  // namespace command_line
