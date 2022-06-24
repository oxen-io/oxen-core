# Oxen Daemon RPC Endpoints

These pages describe the available RPC endpoints available from a running `oxend` node.  These
endpoints are used for querying blockchain data, submitting transactions, obtaining service node
information, and controlling the running oxend.

Many of the endpoints described here are publicly accessible; those that are not are marked
accordingly and can only be used by a local administrator.

## HTTP JSON access

Accessing an endpoint using HTTP and JSON can be done by making a JSON RPC request.  For example, to
call the `get_info` endpoint on a service node with an HTTP RPC listener on `localhost:22023` (the
default) using JSON RPC you would make a POST request to `http://localhost:22023/json_rpc` with a
JSON body:

```json
{
  "jsonrpc": "2.0",
  "id": "0",
  "method": "get_info",
  "params": { "foo": 123 }
}
```

The pages here describe only the values of the inner "params" value; the outer boilerplate is the
same for all requests.  For methods that do not require any input parameters the `"params"` field
may be omitted entirely.

### Command-line usage

For example, to make a request using `curl` to the public RPC node `public-na.optf.ngo`, using the
command-line with `jq` to "prettify" the json response:

```
curl -sSX POST http://public-na.optf.ngo:22023/json_rpc \
    -d '{"jsonrpc":"2.0","id":"0","method":"get_info"}' | jq .
```

## OxenMQ RPC access

All oxend endpoints are also available via OxenMQ at either the `rpc.ENDPOINT` or `admin.ENDPOINT`
name (the latter if the endpoint is marked admin-only), with an optional additional data part
containing a JSON or bencoded request.

### Command-line usage:

The oxen-core source code contains a script (`utils/lmq-rpc.py`) that can invoke such a request:

```
./utils/lmq-rpc.py ipc://$HOME/.oxen/oxend.sock rpc.get_info | jq .
```
to query a local oxend, or:
```
./utils/lmq-rpc.py tcp://public-na.optf.ngo:22027 02ae9aa1bdface3ce32488874d16671b04d44f611d1076033c92f3379f221161 rpc.get_info | jq .
```
or
```
./utils/lmq-rpc.py tcp://public-na.optf.ngo:22029 rpc.get_info '{}' | jq .
```
to query a public node.  (The first version uses an encrypted public connection given the remote
oxend's X25519 pubkey; the second version uses an unencrypted public connection).
