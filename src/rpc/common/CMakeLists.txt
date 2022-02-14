add_library(rpc_common
  rpc_binary.cpp
  command_decorators.cpp
  json_bt.cpp
  rpc_args.cpp
  http_server_base.cpp
  )

target_link_libraries(rpc_common
  PUBLIC
    common
    uWebSockets
    nlohmann_json::nlohmann_json
    oxenmq::oxenmq
  PRIVATE
    extra)
