#pragma once
#include <pybind11/functional.h>
#include <pybind11/pybind11.h>
#include <pybind11/stl.h>

namespace py = pybind11;

namespace wallet {
void Wallet_Init(py::module& mod);

void Keyring_Init(py::module& mod);

void KeyringManager_Init(py::module& mod);

void WalletConfig_Init(py::module& mod);

void GeneralWalletConfig_Init(py::module& mod);

void DaemonCommsConfig_Init(py::module& mod);

void RPCConfig_Init(py::module& mod);

void LoggingConfig_Init(py::module& mod);

}  // namespace wallet
