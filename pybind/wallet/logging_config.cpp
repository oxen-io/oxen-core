#include "../common.hpp"
#include "wallet3/config/config.hpp"

namespace wallet {
void LoggingConfig_Init(py::module& mod) {
    py::class_<LoggingConfig, std::shared_ptr<LoggingConfig>>(mod, "LoggingConfig")
            .def(py::init<>())
            .def_readwrite("level", &LoggingConfig::level)
            .def_readwrite("save_logs_in_subdirectory", &LoggingConfig::save_logs_in_subdirectory)
            .def_readwrite("logdir", &LoggingConfig::logdir)
            .def_readwrite("log_filename", &LoggingConfig::log_filename);
}

}  // namespace wallet
