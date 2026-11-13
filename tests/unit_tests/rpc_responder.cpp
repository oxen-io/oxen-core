#include <gtest/gtest.h>

#include <optional>
#include <variant>

#include "rpc/common/rpc_command.h"
#include "rpc/core_rpc_server_commands_defs.h"
#include "rpc/core_rpc_server_error_codes.h"

namespace {

using namespace cryptonote::rpc;
using result_type = std::variant<oxenc::bt_value, nlohmann::json, std::string>;

struct outcome {
    std::optional<result_type> result;
    std::optional<rpc_error> error;
};

// A responder for a BLS signing RPC, as make_invoke creates, recording what it sends.
std::shared_ptr<rpc_responder<BLS_REWARDS_REQUEST, result_type>> make_responder(outcome& out) {
    return std::make_shared<rpc_responder<BLS_REWARDS_REQUEST, result_type>>(
            [&out](result_type r) { out.result = std::move(r); },
            [&out](rpc_error e) { out.error = std::move(e); });
}

}  // namespace

// The BLS signing RPCs set their error up front and clear it only once the response is complete,
// so a request that never gets there (whatever stops it) is answered with that error rather than
// with an empty result.
TEST(rpc_responder, preset_error_is_sent_unless_cleared) {
    outcome out;
    {
        auto r = make_responder(out);
        r->error.emplace(ERROR_BLS_SIG, "Failed to obtain a BLS signature from the network");
        r->rpc.response["address"] = "0x00";  // a response that was never completed
    }
    EXPECT_FALSE(out.result);
    ASSERT_TRUE(out.error);
    EXPECT_EQ(out.error->code, ERROR_BLS_SIG);
}

TEST(rpc_responder, cleared_error_sends_the_response) {
    outcome out;
    {
        auto r = make_responder(out);
        r->error.emplace(ERROR_BLS_SIG, "Failed to obtain a BLS signature from the network");
        r->rpc.response["status"] = "OK";
        r->error.reset();
    }
    EXPECT_FALSE(out.error);
    ASSERT_TRUE(out.result);
    auto* j = std::get_if<nlohmann::json>(&*out.result);
    ASSERT_TRUE(j);
    EXPECT_EQ(j->value("status", ""), "OK");
}
