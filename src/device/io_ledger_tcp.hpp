// TCP APDU interface, as used by Ledger's emulator system (Speculos).

#pragma once

#include <chrono>
#include <memory>
#include <string>

#include "io_device.hpp"

#pragma once

namespace hw::io {

using namespace std::literals;

class ledger_tcp : public device {

    std::unique_ptr<int> sockfd;

  public:
    std::string host = "localhost";
    std::string port = "9999";

    std::chrono::microseconds connect_timeout = 10s;
    std::chrono::microseconds exchange_timeout = 120s;

    ledger_tcp() = default;
    ~ledger_tcp() override;

    ledger_tcp(ledger_tcp&&) = default;
    ledger_tcp& operator=(ledger_tcp&&) = default;

    void init() override {}
    void release() override {}
    void connect();
    bool connected() const override;
    int exchange(
            const unsigned char* command,
            unsigned int cmd_len,
            unsigned char* response,
            unsigned int max_resp_len,
            bool user_input) override;
    void disconnect() override;
};

}  // namespace hw::io
