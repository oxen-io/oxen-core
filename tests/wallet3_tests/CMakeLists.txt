add_executable(wallet3_tests
  db_schema.cpp
  scan_received.cpp
  tx_creation.cpp
  sign.cpp
  verify.cpp
  decoy.cpp
  main.cpp
)

target_link_libraries(wallet3_tests
  PRIVATE
  Catch2::Catch2
  SQLiteCpp
  ringct
  wallet3)


add_test(
  NAME    wallet3_tests
  COMMAND wallet3_tests)



add_executable(jank_wallet_test
  jank_wallet.cpp
)

target_link_libraries(jank_wallet_test
  cryptonote_core
  cryptonote_protocol
  blockchain_db
  version
  extra
  wallet3
  SQLiteCpp
  ringct)
