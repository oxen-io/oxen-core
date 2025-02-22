#include "command_decorators.h"

namespace cryptonote::rpc {

void RPC_COMMAND::set_bt() {
    bt = true;
    response_b64.format = tools::json_binary_proxy::fmt::bt;
    response_hex.format = tools::json_binary_proxy::fmt::bt;
}

}  // namespace cryptonote::rpc
