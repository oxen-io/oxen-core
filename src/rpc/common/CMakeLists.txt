oxen_add_library(rpc_common
  command_decorators.cpp
  json_bt.cpp
  rpc_args.cpp
  http_server_base.cpp
  )

target_link_libraries(rpc_common
  PUBLIC
    common
    uWebSockets
    oxenmq::oxenmq
    logging
  PRIVATE
    extra)
