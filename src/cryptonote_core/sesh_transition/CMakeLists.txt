oxen_add_library(sesh_transition_data
  devnet.cpp
  localdev.cpp
  mainnet.cpp
  testnet.cpp)

if (CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
  target_compile_options(sesh_transition_data PUBLIC -fno-var-tracking)
endif()

target_link_libraries(sesh_transition_data
    PUBLIC
    common
    oxenc::oxenc)
