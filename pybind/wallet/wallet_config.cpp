#include "../common.hpp"
#include "wallet3/config/config.hpp"

namespace wallet {
void WalletConfig_Init(py::module& mod) {
    py::class_<Config, std::shared_ptr<Config>>(mod, "WalletConfig")
            .def(py::init<>())
            .def_readwrite("general", &Config::general)
            .def_readwrite("logging", &Config::logging)
            .def_readwrite("daemon", &Config::daemon)
            .def_readwrite("omq_rpc", &Config::omq_rpc);
}

}  // namespace wallet
