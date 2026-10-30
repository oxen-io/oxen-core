// Checks, for every wallet RPC request and response, that the JSON the wallet RPC reads and writes
// through levin_kv's archive is what it read and wrote through epee's KV serialization.

#include <gtest/gtest.h>

#include <nlohmann/json.hpp>
#include <string>

#include "epee/storages/portable_storage.h"
#include "serialization/levin_kv/archive.h"
#include "wallet/kv_json.h"
#include "wallet/wallet_rpc_server_commands_defs.h"

namespace {

// Sets every field that a type's serialize() reads to a distinct value, giving containers two
// elements (and so filling in all that's nested).
class filler final : public levin_kv::archive {
  public:
    filler() : archive{true} {}

  protected:
    bool scalar_value(std::string_view, scalar_ref v) override {
        std::visit([this]<typename T>(std::reference_wrapper<T> x) { x.get() = make<T>(); }, v);
        return true;
    }
    bool array(std::string_view, array_ref v) override {
        std::visit(
                [this]<typename T>(std::reference_wrapper<std::vector<T>> x) {
                    x.get() = {make<T>(), make<T>()};
                },
                v);
        return true;
    }
    bool packed_array(std::string_view name, packed_ref v) override {
        return std::visit([&](auto vec) { return array(name, vec); }, v);
    }
    bool bytes(std::string_view, std::span<std::byte> v) override {
        for (auto& b : v)
            b = std::byte(make<uint8_t>());
        return true;
    }
    bool blobs(
            std::string_view,
            size_t,
            size_t,
            const std::function<std::span<std::byte>(size_t)>& storage) override {
        for (auto& b : storage(2))
            b = std::byte(make<uint8_t>());
        return true;
    }
    bool map(std::string_view, const std::function<void(archive&)>& f) override {
        f(*this);
        return true;
    }
    bool maps(
            std::string_view,
            size_t,
            const std::function<void(size_t)>& resize,
            const std::function<void(size_t, archive&)>& each) override {
        resize(2);
        each(0, *this);
        each(1, *this);
        return true;
    }

  private:
    int n = 0;

    template <typename T>
    T make() {
        ++n;
        if constexpr (std::is_same_v<T, std::string>)
            return "s" + std::to_string(n);
        else if constexpr (std::is_same_v<T, bool>)
            return n % 2 == 0;
        else
            // Small enough for every integer type
            return static_cast<T>(n % 100 + 1);
    }
};

std::string printable(const nlohmann::json& j) {
    return j.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace);
}

template <typename T>
void check(std::string_view what) {
    T v{};
    filler f;
    levin_kv::serialize_fields(f, v);

    epee::serialization::portable_storage ps;
    ASSERT_TRUE(v.store(ps)) << what;
    auto epee_json = tools::kv_json::to_json(ps.root());

    auto ours = tools::kv_json::to_json(v);
    EXPECT_TRUE(ours == epee_json)
            << what << ": " << printable(ours) << "\n  vs epee's: " << printable(epee_json);

    T read{};
    ASSERT_TRUE(tools::kv_json::from_json(epee_json, read)) << what;
    auto reread = tools::kv_json::to_json(read);
    EXPECT_TRUE(reread == epee_json)
            << what << ": " << printable(reread) << "\n  vs epee's: " << printable(epee_json);
}

template <typename... RPC>
void check_all(tools::type_list<RPC...>) {
    (check<typename RPC::request>(std::string{RPC::names()[0]} + " request"), ...);
    (check<typename RPC::response>(std::string{RPC::names()[0]} + " response"), ...);
}

}  // namespace

TEST(wallet_rpc_json_compat, every_request_and_response) {
    check_all(tools::wallet_rpc::wallet_rpc_types{});
}

TEST(wallet_rpc_json_compat, transfer_views) {
    check<wallet::transfer_view>("transfer_view");
}

TEST(wallet_rpc_json_compat, filler_fills_everything) {
    // That the comparisons above compare something: nested structs, lists of them, and their
    // fields all filled in.
    tools::wallet_rpc::GET_TRANSFERS::response r{};
    filler f;
    levin_kv::serialize_fields(f, r);
    auto j = tools::kv_json::to_json(r);
    ASSERT_TRUE(j["in"].is_array());
    ASSERT_EQ(j["in"].size(), 2u);
    const auto& t = j["in"][1];
    ASSERT_EQ(t["destinations"].size(), 2u);
    EXPECT_TRUE(t["destinations"][0]["address"].is_string());
    EXPECT_TRUE(t["destinations"][0]["amount"].is_number());
    EXPECT_TRUE(t["subaddr_index"]["major"].is_number());
    EXPECT_EQ(t["subaddr_indices"].size(), 2u);
    EXPECT_TRUE(t["txid"].is_string());
}
