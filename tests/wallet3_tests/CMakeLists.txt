

add_executable(wallet3_tests
  sign.cpp
  verify.cpp
  decoy.cpp
  main.cpp
)

target_link_libraries(wallet3_tests
  PRIVATE
  Catch2::Catch2
  ringct
  wallet3)


add_test(
  NAME    wallet3_tests
  COMMAND wallet3_tests)
