#include "../common.hpp"
#include "wallet3/config/config.hpp"

namespace wallet {
void RPCConfig_Init(py::module& mod) {
    py::class_<rpc::Config, std::shared_ptr<rpc::Config>>(mod, "RPCConfig")
            .def(py::init<>())
            .def_readwrite("sockname", &rpc::Config::sockname);
}

}  // namespace wallet
