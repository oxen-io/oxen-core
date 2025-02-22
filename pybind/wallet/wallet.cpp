#include <oxenmq/oxenmq.h>

#include <oxen/log.hpp>
#include <wallet3/config/config.hpp>
#include <wallet3/default_daemon_comms.hpp>
#include <wallet3/keyring.hpp>
#include <wallet3/wallet.hpp>

#include "../common.hpp"

static auto logcat = oxen::log::Cat("omq");

void omq_logger(oxenmq::LogLevel level, const char* file, int line, std::string message) {
    constexpr std::string_view format = "[{}:{}]: {}";
    switch (level) {
        case oxenmq::LogLevel::fatal:
            oxen::log::critical(logcat, format, file, line, message);
            break;
        case oxenmq::LogLevel::error: oxen::log::error(logcat, format, file, line, message); break;
        case oxenmq::LogLevel::warn: oxen::log::warning(logcat, format, file, line, message); break;
        case oxenmq::LogLevel::info: oxen::log::info(logcat, format, file, line, message); break;
        case oxenmq::LogLevel::debug: oxen::log::debug(logcat, format, file, line, message); break;
        case oxenmq::LogLevel::trace: oxen::log::trace(logcat, format, file, line, message); break;
    }
}

namespace wallet {
void Wallet_Init(py::module& mod) {
    py::class_<Wallet, std::shared_ptr<Wallet>>(mod, "Wallet")
            .def(py::init([](const std::string& wallet_name,
                             std::shared_ptr<Keyring> keyring,
                             Config config) {
                auto& comms_config = config.daemon;
                auto& omq_rpc_config = config.omq_rpc;
                auto oxenmq = std::make_shared<oxenmq::OxenMQ>(omq_logger, oxenmq::LogLevel::info);
                auto comms = std::make_shared<DefaultDaemonComms>(oxenmq, comms_config);
                return Wallet::create(
                        std::move(oxenmq),
                        std::move(keyring),
                        nullptr,
                        std::move(comms),
                        wallet_name + ".sqlite",
                        "",
                        std::move(config));
            }))
            .def("get_balance", &Wallet::get_balance)
            .def("deregister", &Wallet::deregister);
}

}  // namespace wallet
