#include "../common.hpp"
#include "wallet3/config/config.hpp"

namespace wallet {
void DaemonCommsConfig_Init(py::module& mod) {
    py::class_<DaemonCommsConfig, std::shared_ptr<DaemonCommsConfig>>(mod, "DaemonCommsConfig")
            .def(py::init<>())
            .def_readwrite("address", &DaemonCommsConfig::address);
}

}  // namespace wallet
