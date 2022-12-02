pybind11_add_module(pywallet3 MODULE
  module.cpp
  wallet/keyring.cpp
  wallet/keyring_manager.cpp
  wallet/wallet.cpp
  wallet/wallet_config.cpp
  wallet/general_wallet_config.cpp
  wallet/logging_config.cpp
  wallet/daemon_comms_config.cpp
  wallet/rpc_config.cpp
)
target_link_libraries(pywallet3 PUBLIC wallet3)
target_include_directories(pywallet3 PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

file(GENERATE
    OUTPUT setup.py
    INPUT setup.py.in)
configure_file(pyproject.toml pyproject.toml COPYONLY)
