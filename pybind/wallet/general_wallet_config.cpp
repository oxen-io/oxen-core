#include "../common.hpp"
#include "wallet3/config/config.hpp"

namespace wallet {
void GeneralWalletConfig_Init(py::module& mod) {
    py::class_<GeneralWalletConfig, std::shared_ptr<GeneralWalletConfig>>(
            mod, "GeneralWalletConfig")
            .def(py::init<>())
            .def_readwrite("datadir", &GeneralWalletConfig::datadir)
            .def_readwrite(
                    "append_network_type_to_datadir",
                    &GeneralWalletConfig::append_network_type_to_datadir);
}

}  // namespace wallet
