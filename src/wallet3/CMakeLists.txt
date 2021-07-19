add_library(wallet3
  db.cpp
  default_daemon_comms.cpp
  default_keys.cpp
  default_transaction_constructor.cpp
  transaction_scanner.cpp
  wallet.cpp)

target_link_libraries(wallet3
  PRIVATE
  cryptonote_basic
  cryptonote_core
  SQLiteCpp)
