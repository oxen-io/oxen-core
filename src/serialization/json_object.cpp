// Copyright (c) 2016-2019, The Monero Project
// 
// All rights reserved.
// 
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
// 
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
// 
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
// 
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
// 
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#include "json_object.h"

#include <limits>
#include <type_traits>
#include "string_tools.h"

namespace cryptonote
{

namespace json
{

namespace
{
  template<typename Source, typename Destination>
  constexpr bool precision_loss()
  {
    return
      std::numeric_limits<Destination>::is_signed != std::numeric_limits<Source>::is_signed ||
      std::numeric_limits<Destination>::min() > std::numeric_limits<Source>::min() ||
      std::numeric_limits<Destination>::max() < std::numeric_limits<Source>::max();
  }

  template<typename Source, typename Type>
  void convert_numeric(Source source, Type& i)
  {
    static_assert(
      (std::is_same<Type, char>() && std::is_same<Source, int>()) ||
      std::numeric_limits<Source>::is_signed == std::numeric_limits<Type>::is_signed,
      "comparisons below may have undefined behavior"
    );
    if (source < std::numeric_limits<Type>::min())
    {
      throw WRONG_TYPE{"numeric underflow"};
    }
    if (std::numeric_limits<Type>::max() < source)
    {
      throw WRONG_TYPE{"numeric overflow"};
    }
    i = Type(source);
  }

  template<typename Type>
  void to_int(const rapidjson::Value& val, Type& i)
  {
    if (!val.IsInt())
    {
      throw WRONG_TYPE{"integer"};
    }
    convert_numeric(val.GetInt(), i);
  }
  template<typename Type>
  void to_int64(const rapidjson::Value& val, Type& i)
  {
    if (!val.IsInt64())
    {
      throw WRONG_TYPE{"integer"};
    }
    convert_numeric(val.GetInt64(), i);
  }

  template<typename Type>
  void to_uint(const rapidjson::Value& val, Type& i)
  {
    if (!val.IsUint())
    {
      throw WRONG_TYPE{"unsigned integer"};
    }
    convert_numeric(val.GetUint(), i);
  }
  template<typename Type>
  void to_uint64(const rapidjson::Value& val, Type& i)
  {
    if (!val.IsUint64())
    {
      throw WRONG_TYPE{"unsigned integer"};
    }
    convert_numeric(val.GetUint64(), i);
  }
}

void toJsonValue(rapidjson::Document& doc, const std::string& i, rapidjson::Value& val)
{
  val = rapidjson::Value(i.c_str(), doc.GetAllocator());
}

void fromJsonValue(const rapidjson::Value& val, std::string& str)
{
  if (!val.IsString())
  {
    throw WRONG_TYPE("string");
  }

  str = val.GetString();
}

void toJsonValue(rapidjson::Document& doc, bool i, rapidjson::Value& val)
{
  val.SetBool(i);
}

void fromJsonValue(const rapidjson::Value& val, bool& b)
{
  if (!val.IsBool())
  {
    throw WRONG_TYPE("boolean");
  }
  b = val.GetBool();
}

void fromJsonValue(const rapidjson::Value& val, unsigned char& i)
{
  to_uint(val, i);
}

void fromJsonValue(const rapidjson::Value& val, char& i)
{
  to_int(val, i);
}

void fromJsonValue(const rapidjson::Value& val, signed char& i)
{
  to_int(val, i);
}

void fromJsonValue(const rapidjson::Value& val, unsigned short& i)
{
  to_uint(val, i);
}

void fromJsonValue(const rapidjson::Value& val, short& i)
{
  to_int(val, i);
}

void toJsonValue(rapidjson::Document& doc, const unsigned int i, rapidjson::Value& val)
{
  val = rapidjson::Value(i);
}

void fromJsonValue(const rapidjson::Value& val, unsigned int& i)
{
  to_uint(val, i);
}

void toJsonValue(rapidjson::Document& doc, const int i, rapidjson::Value& val)
{
  val = rapidjson::Value(i);
}

void fromJsonValue(const rapidjson::Value& val, int& i)
{
  to_int(val, i);
}

void toJsonValue(rapidjson::Document& doc, const unsigned long long i, rapidjson::Value& val)
{
  static_assert(!precision_loss<unsigned long long, std::uint64_t>(), "precision loss");
  val = rapidjson::Value(std::uint64_t(i));
}

void fromJsonValue(const rapidjson::Value& val, unsigned long long& i)
{
  to_uint64(val, i);
}

void toJsonValue(rapidjson::Document& doc, const long long i, rapidjson::Value& val)
{
  static_assert(!precision_loss<long long, std::int64_t>(), "precision loss");
  val = rapidjson::Value(std::int64_t(i));
}

void fromJsonValue(const rapidjson::Value& val, long long& i)
{
  to_int64(val, i);
}

void fromJsonValue(const rapidjson::Value& val, unsigned long& i)
{
  to_uint64(val, i);
}

void fromJsonValue(const rapidjson::Value& val, long& i)
{
  to_int64(val, i);
}

void toJsonValue(rapidjson::Document& doc, const cryptonote::transaction& tx, rapidjson::Value& val)
{
  val.SetObject();

  insert_into_json_object(val, doc, "version", static_cast<uint16_t>(tx.version));
  insert_into_json_object(val, doc, "unlock_time", tx.unlock_time);
  insert_into_json_object(val, doc, "output_unlock_times", tx.output_unlock_times);
  insert_into_json_object(val, doc, "type", static_cast<uint16_t>(tx.type));
  insert_into_json_object(val, doc, "inputs", tx.vin);
  insert_into_json_object(val, doc, "outputs", tx.vout);
  insert_into_json_object(val, doc, "extra", tx.extra);
  insert_into_json_object(val, doc, "signatures", tx.signatures);
  insert_into_json_object(val, doc, "ringct", tx.rct_signatures);
}


void fromJsonValue(const rapidjson::Value& val, cryptonote::transaction& tx)
{
  if (!val.IsObject())
  {
    throw WRONG_TYPE("json object");
  }

  uint16_t tx_ver, tx_type;

  load_from_json_object(val, "version", tx_ver);
  load_from_json_object(val, "unlock_time", tx.unlock_time);
  load_from_json_object(val, "output_unlock_times", tx.output_unlock_times);
  load_from_json_object(val, "type", tx_type);
  load_from_json_object(val, "inputs", tx.vin);
  load_from_json_object(val, "outputs", tx.vout);
  load_from_json_object(val, "extra", tx.extra);
  load_from_json_object(val, "signatures", tx.signatures);
  load_from_json_object(val, "ringct", tx.rct_signatures);

  tx.version = static_cast<txversion>(tx_ver);
  tx.type    = static_cast<txtype>(tx_type);
  if (tx.version == txversion::v0 || tx.version >= txversion::_count)
    throw BAD_INPUT();
  if (tx.type >= txtype::_count)
    throw BAD_INPUT();
}

void toJsonValue(rapidjson::Document& doc, const cryptonote::block& b, rapidjson::Value& val)
{
  val.SetObject();

  insert_into_json_object(val, doc, "major_version", b.major_version);
  insert_into_json_object(val, doc, "minor_version", b.minor_version);
  insert_into_json_object(val, doc, "timestamp", b.timestamp);
  insert_into_json_object(val, doc, "prev_id", b.prev_id);
  insert_into_json_object(val, doc, "nonce", b.nonce);
  insert_into_json_object(val, doc, "miner_tx", b.miner_tx);
  insert_into_json_object(val, doc, "tx_hashes", b.tx_hashes);
}


void fromJsonValue(const rapidjson::Value& val, cryptonote::block& b)
{
  if (!val.IsObject())
  {
    throw WRONG_TYPE("json object");
  }

  load_from_json_object(val, "major_version", b.major_version);
  load_from_json_object(val, "minor_version", b.minor_version);
  load_from_json_object(val, "timestamp", b.timestamp);
  load_from_json_object(val, "prev_id", b.prev_id);
  load_from_json_object(val, "nonce", b.nonce);
  load_from_json_object(val, "miner_tx", b.miner_tx);
  load_from_json_object(val, "tx_hashes", b.tx_hashes);
}

void toJsonValue(rapidjson::Document& doc, const cryptonote::txin_v& txin, rapidjson::Value& val)
{
  val.SetObject();

  struct add_input
  {
    rapidjson::Document& doc;
    rapidjson::Value& val;

    void operator()(cryptonote::txin_to_key const& input) const
    {
      insert_into_json_object(val, doc, "to_key", input);
    }
    void operator()(cryptonote::txin_gen const& input) const
    {
      insert_into_json_object(val, doc, "gen", input);
    }
    void operator()(cryptonote::txin_to_script const& input) const
    {
      insert_into_json_object(val, doc, "to_script", input);
    }
    void operator()(cryptonote::txin_to_scripthash const& input) const
    {
      insert_into_json_object(val, doc, "to_scripthash", input);
    }
  };
  std::visit(add_input{doc, val}, txin);
}


void fromJsonValue(const rapidjson::Value& val, cryptonote::txin_v& txin)
{
  if (!val.IsObject())
  {
    throw WRONG_TYPE("json object");
  }

  if (val.MemberCount() != 1)
  {
    throw MISSING_KEY("Invalid input object");
  }

  for (auto const& elem : val.GetObject())
  {
    if (elem.name == "to_key")
    {
      cryptonote::txin_to_key tmpVal;
      fromJsonValue(elem.value, tmpVal);
      txin = std::move(tmpVal);
    }
    else if (elem.name == "gen")
    {
      cryptonote::txin_gen tmpVal;
      fromJsonValue(elem.value, tmpVal);
      txin = std::move(tmpVal);
    }
    else if (elem.name == "to_script")
    {
      cryptonote::txin_to_script tmpVal;
      fromJsonValue(elem.value, tmpVal);
      txin = std::move(tmpVal);
    }
    else if (elem.name == "to_scripthash")
    {
      cryptonote::txin_to_scripthash tmpVal;
      fromJsonValue(elem.value, tmpVal);
      txin = std::move(tmpVal);
    }
  }
}

void toJsonValue(rapidjson::Document& doc, const cryptonote::txin_gen& txin, rapidjson::Value& val)
{
  val.SetObject();

  insert_into_json_object(val, doc, "height", txin.height);
}


void fromJsonValue(const rapidjson::Value& val, cryptonote::txin_gen& txin)
{
  if (!val.IsObject())
  {
    throw WRONG_TYPE("json object");
  }

  load_from_json_object(val, "height", txin.height);
}

void toJsonValue(rapidjson::Document& doc, const cryptonote::txin_to_script& txin, rapidjson::Value& val)
{
  val.SetObject();

  insert_into_json_object(val, doc, "prev", txin.prev);
  insert_into_json_object(val, doc, "prevout", txin.prevout);
  insert_into_json_object(val, doc, "sigset", txin.sigset);
}


void fromJsonValue(const rapidjson::Value& val, cryptonote::txin_to_script& txin)
{
  if (!val.IsObject())
  {
    throw WRONG_TYPE("json object");
  }

  load_from_json_object(val, "prev", txin.prev);
  load_from_json_object(val, "prevout", txin.prevout);
  load_from_json_object(val, "sigset", txin.sigset);
}

void toJsonValue(rapidjson::Document& doc, const cryptonote::txin_to_scripthash& txin, rapidjson::Value& val)
{
  val.SetObject();

  insert_into_json_object(val, doc, "prev", txin.prev);
  insert_into_json_object(val, doc, "prevout", txin.prevout);
  insert_into_json_object(val, doc, "script", txin.script);
  insert_into_json_object(val, doc, "sigset", txin.sigset);
}


void fromJsonValue(const rapidjson::Value& val, cryptonote::txin_to_scripthash& txin)
{
  if (!val.IsObject())
  {
    throw WRONG_TYPE("json object");
  }

  load_from_json_object(val, "prev", txin.prev);
  load_from_json_object(val, "prevout", txin.prevout);
  load_from_json_object(val, "script", txin.script);
  load_from_json_object(val, "sigset", txin.sigset);
}

void toJsonValue(rapidjson::Document& doc, const cryptonote::txin_to_key& txin, rapidjson::Value& val)
{
  val.SetObject();

  insert_into_json_object(val, doc, "amount", txin.amount);
  insert_into_json_object(val, doc, "key_offsets", txin.key_offsets);
  insert_into_json_object(val, doc, "key_image", txin.k_image);
}


void fromJsonValue(const rapidjson::Value& val, cryptonote::txin_to_key& txin)
{
  if (!val.IsObject())
  {
    throw WRONG_TYPE("json object");
  }

  load_from_json_object(val, "amount", txin.amount);
  load_from_json_object(val, "key_offsets", txin.key_offsets);
  load_from_json_object(val, "key_image", txin.k_image);
}

void toJsonValue(rapidjson::Document& doc, const cryptonote::txout_to_script& txout, rapidjson::Value& val)
{
  val.SetObject();

  insert_into_json_object(val, doc, "keys", txout.keys);
  insert_into_json_object(val, doc, "script", txout.script);
}


void fromJsonValue(const rapidjson::Value& val, cryptonote::txout_to_script& txout)
{
  if (!val.IsObject())
  {
    throw WRONG_TYPE("json object");
  }

  load_from_json_object(val, "keys", txout.keys);
  load_from_json_object(val, "script", txout.script);
}

void toJsonValue(rapidjson::Document& doc, const cryptonote::txout_to_scripthash& txout, rapidjson::Value& val)
{
  val.SetObject();

  insert_into_json_object(val, doc, "hash", txout.hash);
}


void fromJsonValue(const rapidjson::Value& val, cryptonote::txout_to_scripthash& txout)
{
  if (!val.IsObject())
  {
    throw WRONG_TYPE("json object");
  }

  load_from_json_object(val, "hash", txout.hash);
}

void toJsonValue(rapidjson::Document& doc, const cryptonote::txout_to_key& txout, rapidjson::Value& val)
{
  val.SetObject();

  insert_into_json_object(val, doc, "key", txout.key);
}


void fromJsonValue(const rapidjson::Value& val, cryptonote::txout_to_key& txout)
{
  if (!val.IsObject())
  {
    throw WRONG_TYPE("json object");
  }

  load_from_json_object(val, "key", txout.key);
}

template <typename T>
static constexpr const char* txout_target_key() { static_assert(std::is_void_v<T>, "Internal error: unhandled txout type"); return ""; }
template <> inline constexpr const char* txout_target_key<txout_to_key>() { return "to_key"; }
template <> inline constexpr const char* txout_target_key<txout_to_script>() { return "to_script"; }
template <> inline constexpr const char* txout_target_key<txout_to_scripthash>() { return "to_scripthash"; }

void toJsonValue(rapidjson::Document& doc, const cryptonote::tx_out& txout, rapidjson::Value& val)
{
  val.SetObject();

  insert_into_json_object(val, doc, "amount", txout.amount);

  std::visit([&doc, &val](const auto& output) {
      using T = std::decay_t<decltype(output)>;
      rapidjson::Value jv;
      toJsonValue(doc, output, jv);
      val.AddMember(rapidjson::StringRef(txout_target_key<T>()), jv, doc.GetAllocator());
    }, txout.target);
}

template <typename T, typename Elem>
bool txout_target_element_one(const Elem& elem, txout_target_v& target) {
  if (elem.name != txout_target_key<T>())
    return false;
  T tmp;
  fromJsonValue(elem.value, tmp);
  target = std::move(tmp);
  return true;
}

template <typename Elem, typename... T>
void txout_target_element(const Elem& elem, std::variant<T...>& v) {
  (... || txout_target_element_one<T>(elem, v));
}

void fromJsonValue(const rapidjson::Value& val, cryptonote::tx_out& txout)
{
  if (!val.IsObject())
  {
    throw WRONG_TYPE("json object");
  }

  if (val.MemberCount() != 2)
  {
    throw MISSING_KEY("Invalid input object");
  }

  for (auto const& elem : val.GetObject())
  {
    if (elem.name == "amount")
    {
      fromJsonValue(elem.value, txout.amount);
    }
    else
    {
      txout_target_element(elem, txout.target);
    }
  }
}

void toJsonValue(rapidjson::Document& doc, const cryptonote::connection_info& info, rapidjson::Value& val)
{
  val.SetObject();

  insert_into_json_object(val, doc, "incoming", info.incoming);
  insert_into_json_object(val, doc, "localhost", info.localhost);
  insert_into_json_object(val, doc, "local_ip", info.local_ip);
  insert_into_json_object(val, doc, "address_type", info.address_type);

  insert_into_json_object(val, doc, "ip", info.ip);
  insert_into_json_object(val, doc, "port", info.port);
  insert_into_json_object(val, doc, "rpc_port", info.rpc_port);

  insert_into_json_object(val, doc, "peer_id", info.peer_id);

  insert_into_json_object(val, doc, "recv_count", info.recv_count);
  insert_into_json_object(val, doc, "recv_idle_time", info.recv_idle_time);

  insert_into_json_object(val, doc, "send_count", info.send_count);
  insert_into_json_object(val, doc, "send_idle_time", info.send_idle_time);

  insert_into_json_object(val, doc, "state", info.state);

  insert_into_json_object(val, doc, "live_time", info.live_time);

  insert_into_json_object(val, doc, "avg_download", info.avg_download);
  insert_into_json_object(val, doc, "current_download", info.current_download);

  insert_into_json_object(val, doc, "avg_upload", info.avg_upload);
  insert_into_json_object(val, doc, "current_upload", info.current_upload);
}


void fromJsonValue(const rapidjson::Value& val, cryptonote::connection_info& info)
{
  if (!val.IsObject())
  {
    throw WRONG_TYPE("json object");
  }

  load_from_json_object(val, "incoming", info.incoming);
  load_from_json_object(val, "localhost", info.localhost);
  load_from_json_object(val, "local_ip", info.local_ip);
  load_from_json_object(val, "address_type", info.address_type);

  load_from_json_object(val, "ip", info.ip);
  load_from_json_object(val, "port", info.port);
  load_from_json_object(val, "rpc_port", info.rpc_port);

  load_from_json_object(val, "peer_id", info.peer_id);

  load_from_json_object(val, "recv_count", info.recv_count);
  load_from_json_object(val, "recv_idle_time", info.recv_idle_time);

  load_from_json_object(val, "send_count", info.send_count);
  load_from_json_object(val, "send_idle_time", info.send_idle_time);

  load_from_json_object(val, "state", info.state);

  load_from_json_object(val, "live_time", info.live_time);

  load_from_json_object(val, "avg_download", info.avg_download);
  load_from_json_object(val, "current_download", info.current_download);

  load_from_json_object(val, "avg_upload", info.avg_upload);
  load_from_json_object(val, "current_upload", info.current_upload);
}

void toJsonValue(rapidjson::Document& doc, const cryptonote::block_complete_entry& blk, rapidjson::Value& val)
{
  val.SetObject();

  insert_into_json_object(val, doc, "block", blk.block);
  insert_into_json_object(val, doc, "transactions", blk.txs);
}


void fromJsonValue(const rapidjson::Value& val, cryptonote::block_complete_entry& blk)
{
  if (!val.IsObject())
  {
    throw WRONG_TYPE("json object");
  }

  load_from_json_object(val, "block", blk.block);
  load_from_json_object(val, "transactions", blk.txs);
}

void toJsonValue(rapidjson::Document& doc, const cryptonote::rpc::block_with_transactions& blk, rapidjson::Value& val)
{
  val.SetObject();

  insert_into_json_object(val, doc, "block", blk.block);
  insert_into_json_object(val, doc, "transactions", blk.transactions);
}


void fromJsonValue(const rapidjson::Value& val, cryptonote::rpc::block_with_transactions& blk)
{
  if (!val.IsObject())
  {
    throw WRONG_TYPE("json object");
  }

  load_from_json_object(val, "block", blk.block);
  load_from_json_object(val, "transactions", blk.transactions);
}

void toJsonValue(rapidjson::Document& doc, const cryptonote::rpc::transaction_info& tx_info, rapidjson::Value& val)
{
  val.SetObject();

  insert_into_json_object(val, doc, "height", tx_info.height);
  insert_into_json_object(val, doc, "in_pool", tx_info.in_pool);
  insert_into_json_object(val, doc, "transaction", tx_info.transaction);
}


void fromJsonValue(const rapidjson::Value& val, cryptonote::rpc::transaction_info& tx_info)
{
  if (!val.IsObject())
  {
    throw WRONG_TYPE("json object");
  }

  load_from_json_object(val, "height", tx_info.height);
  load_from_json_object(val, "in_pool", tx_info.in_pool);
  load_from_json_object(val, "transaction", tx_info.transaction);
}

void toJsonValue(rapidjson::Document& doc, const cryptonote::rpc::output_key_and_amount_index& out, rapidjson::Value& val)
{
  val.SetObject();

  insert_into_json_object(val, doc, "amount_index", out.amount_index);
  insert_into_json_object(val, doc, "key", out.key);
}


void fromJsonValue(const rapidjson::Value& val, cryptonote::rpc::output_key_and_amount_index& out)
{
  if (!val.IsObject())
  {
    throw WRONG_TYPE("json object");
  }

  load_from_json_object(val, "amount_index", out.amount_index);
  load_from_json_object(val, "key", out.key);
}

void toJsonValue(rapidjson::Document& doc, const cryptonote::rpc::amount_with_random_outputs& out, rapidjson::Value& val)
{
  val.SetObject();

  insert_into_json_object(val, doc, "amount", out.amount);
  insert_into_json_object(val, doc, "outputs", out.outputs);
}


void fromJsonValue(const rapidjson::Value& val, cryptonote::rpc::amount_with_random_outputs& out)
{
  if (!val.IsObject())
  {
    throw WRONG_TYPE("json object");
  }

  load_from_json_object(val, "amount", out.amount);
  load_from_json_object(val, "outputs", out.outputs);
}

void toJsonValue(rapidjson::Document& doc, const cryptonote::rpc::peer& peer, rapidjson::Value& val)
{
  val.SetObject();

  insert_into_json_object(val, doc, "id", peer.id);
  insert_into_json_object(val, doc, "ip", peer.ip);
  insert_into_json_object(val, doc, "port", peer.port);
  insert_into_json_object(val, doc, "rpc_port", peer.rpc_port);
  insert_into_json_object(val, doc, "last_seen", peer.last_seen);
  insert_into_json_object(val, doc, "pruning_seed", peer.pruning_seed);
}


void fromJsonValue(const rapidjson::Value& val, cryptonote::rpc::peer& peer)
{
  if (!val.IsObject())
  {
    throw WRONG_TYPE("json object");
  }

  load_from_json_object(val, "id", peer.id);
  load_from_json_object(val, "ip", peer.ip);
  load_from_json_object(val, "port", peer.port);
  load_from_json_object(val, "rpc_port", peer.rpc_port);
  load_from_json_object(val, "last_seen", peer.last_seen);
  load_from_json_object(val, "pruning_seed", peer.pruning_seed);
}

void toJsonValue(rapidjson::Document& doc, const cryptonote::rpc::tx_in_pool& tx, rapidjson::Value& val)
{
  val.SetObject();

  insert_into_json_object(val, doc, "tx", tx.tx);
  insert_into_json_object(val, doc, "tx_hash", tx.tx_hash);
  insert_into_json_object(val, doc, "blob_size", tx.blob_size);
  insert_into_json_object(val, doc, "weight", tx.weight);
  insert_into_json_object(val, doc, "fee", tx.fee);
  insert_into_json_object(val, doc, "max_used_block_hash", tx.max_used_block_hash);
  insert_into_json_object(val, doc, "max_used_block_height", tx.max_used_block_height);
  insert_into_json_object(val, doc, "kept_by_block", tx.kept_by_block);
  insert_into_json_object(val, doc, "last_failed_block_hash", tx.last_failed_block_hash);
  insert_into_json_object(val, doc, "last_failed_block_height", tx.last_failed_block_height);
  insert_into_json_object(val, doc, "receive_time", tx.receive_time);
  insert_into_json_object(val, doc, "last_relayed_time", tx.last_relayed_time);
  insert_into_json_object(val, doc, "relayed", tx.relayed);
  insert_into_json_object(val, doc, "do_not_relay", tx.do_not_relay);
  insert_into_json_object(val, doc, "double_spend_seen", tx.double_spend_seen);
}


void fromJsonValue(const rapidjson::Value& val, cryptonote::rpc::tx_in_pool& tx)
{
  if (!val.IsObject())
  {
    throw WRONG_TYPE("json object");
  }

  load_from_json_object(val, "tx", tx.tx);
  load_from_json_object(val, "blob_size", tx.blob_size);
  load_from_json_object(val, "weight", tx.weight);
  load_from_json_object(val, "fee", tx.fee);
  load_from_json_object(val, "max_used_block_hash", tx.max_used_block_hash);
  load_from_json_object(val, "max_used_block_height", tx.max_used_block_height);
  load_from_json_object(val, "kept_by_block", tx.kept_by_block);
  load_from_json_object(val, "last_failed_block_hash", tx.last_failed_block_hash);
  load_from_json_object(val, "last_failed_block_height", tx.last_failed_block_height);
  load_from_json_object(val, "receive_time", tx.receive_time);
  load_from_json_object(val, "last_relayed_time", tx.last_relayed_time);
  load_from_json_object(val, "relayed", tx.relayed);
  load_from_json_object(val, "do_not_relay", tx.do_not_relay);
  load_from_json_object(val, "double_spend_seen", tx.double_spend_seen);
}

void toJsonValue(rapidjson::Document& doc, const cryptonote::rpc::hard_fork_info& info, rapidjson::Value& val)
{
  val.SetObject();

  insert_into_json_object(val, doc, "version", info.version);
  insert_into_json_object(val, doc, "enabled", info.enabled);
  insert_into_json_object(val, doc, "window", info.window);
  insert_into_json_object(val, doc, "votes", info.votes);
  insert_into_json_object(val, doc, "threshold", info.threshold);
  insert_into_json_object(val, doc, "voting", info.voting);
  insert_into_json_object(val, doc, "state", info.state);
  insert_into_json_object(val, doc, "earliest_height", info.earliest_height);
}


void fromJsonValue(const rapidjson::Value& val, cryptonote::rpc::hard_fork_info& info)
{
  if (!val.IsObject())
  {
    throw WRONG_TYPE("json object");
  }

  load_from_json_object(val, "version", info.version);
  load_from_json_object(val, "enabled", info.enabled);
  load_from_json_object(val, "window", info.window);
  load_from_json_object(val, "votes", info.votes);
  load_from_json_object(val, "threshold", info.threshold);
  load_from_json_object(val, "voting", info.voting);
  load_from_json_object(val, "state", info.state);
  load_from_json_object(val, "earliest_height", info.earliest_height);
}

void toJsonValue(rapidjson::Document& doc, const cryptonote::rpc::output_amount_count& out, rapidjson::Value& val)
{
  val.SetObject();

  insert_into_json_object(val, doc, "amount", out.amount);
  insert_into_json_object(val, doc, "total_count", out.total_count);
  insert_into_json_object(val, doc, "unlocked_count", out.unlocked_count);
  insert_into_json_object(val, doc, "recent_count", out.recent_count);
}


void fromJsonValue(const rapidjson::Value& val, cryptonote::rpc::output_amount_count& out)
{
  if (!val.IsObject())
  {
    throw WRONG_TYPE("json object");
  }

  load_from_json_object(val, "amount", out.amount);
  load_from_json_object(val, "total_count", out.total_count);
  load_from_json_object(val, "unlocked_count", out.unlocked_count);
  load_from_json_object(val, "recent_count", out.recent_count);
}

void toJsonValue(rapidjson::Document& doc, const cryptonote::rpc::output_amount_and_index& out, rapidjson::Value& val)
{
  val.SetObject();

  insert_into_json_object(val, doc, "amount", out.amount);
  insert_into_json_object(val, doc, "index", out.index);
}


void fromJsonValue(const rapidjson::Value& val, cryptonote::rpc::output_amount_and_index& out)
{
  if (!val.IsObject())
  {
    throw WRONG_TYPE("json object");
  }

  load_from_json_object(val, "amount", out.amount);
  load_from_json_object(val, "index", out.index);
}

void toJsonValue(rapidjson::Document& doc, const cryptonote::rpc::output_key_mask_unlocked& out, rapidjson::Value& val)
{
  val.SetObject();

  insert_into_json_object(val, doc, "key", out.key);
  insert_into_json_object(val, doc, "mask", out.mask);
  insert_into_json_object(val, doc, "unlocked", out.unlocked);
}

void fromJsonValue(const rapidjson::Value& val, cryptonote::rpc::output_key_mask_unlocked& out)
{
  if (!val.IsObject())
  {
    throw WRONG_TYPE("json object");
  }

  load_from_json_object(val, "key", out.key);
  load_from_json_object(val, "mask", out.mask);
  load_from_json_object(val, "unlocked", out.unlocked);
}

void toJsonValue(rapidjson::Document& doc, const cryptonote::rpc::error& err, rapidjson::Value& val)
{
  val.SetObject();

  insert_into_json_object(val, doc, "code", err.code);
  insert_into_json_object(val, doc, "error_str", err.error_str);
  insert_into_json_object(val, doc, "message", err.message);
}

void fromJsonValue(const rapidjson::Value& val, cryptonote::rpc::error& error)
{
  if (!val.IsObject())
  {
    throw WRONG_TYPE("json object");
  }

  load_from_json_object(val, "code", error.code);
  load_from_json_object(val, "error_str", error.error_str);
  load_from_json_object(val, "message", error.message);
}

void toJsonValue(rapidjson::Document& doc, const cryptonote::rpc::BlockHeaderResponse& response, rapidjson::Value& val)
{
  val.SetObject();

  insert_into_json_object(val, doc, "major_version", response.major_version);
  insert_into_json_object(val, doc, "minor_version", response.minor_version);
  insert_into_json_object(val, doc, "timestamp", response.timestamp);
  insert_into_json_object(val, doc, "prev_id", response.prev_id);
  insert_into_json_object(val, doc, "nonce", response.nonce);
  insert_into_json_object(val, doc, "height", response.height);
  insert_into_json_object(val, doc, "depth", response.depth);
  insert_into_json_object(val, doc, "hash", response.hash);
  insert_into_json_object(val, doc, "difficulty", response.difficulty);
  insert_into_json_object(val, doc, "reward", response.reward);
}

void fromJsonValue(const rapidjson::Value& val, cryptonote::rpc::BlockHeaderResponse& response)
{
  if (!val.IsObject())
  {
    throw WRONG_TYPE("json object");
  }

  load_from_json_object(val, "major_version", response.major_version);
  load_from_json_object(val, "minor_version", response.minor_version);
  load_from_json_object(val, "timestamp", response.timestamp);
  load_from_json_object(val, "prev_id", response.prev_id);
  load_from_json_object(val, "nonce", response.nonce);
  load_from_json_object(val, "height", response.height);
  load_from_json_object(val, "depth", response.depth);
  load_from_json_object(val, "hash", response.hash);
  load_from_json_object(val, "difficulty", response.difficulty);
  load_from_json_object(val, "reward", response.reward);
}

void toJsonValue(rapidjson::Document& doc, const rct::rctSig& sig, rapidjson::Value& val)
{
  val.SetObject();

  std::vector<rct::key> pk_masks;
  pk_masks.reserve(sig.outPk.size());
  for (const auto& key : sig.outPk)
    pk_masks.push_back(key.mask);

  insert_into_json_object(val, doc, "type", sig.type);
  insert_into_json_object(val, doc, "encrypted", sig.ecdhInfo);
  insert_into_json_object(val, doc, "commitments", pk_masks);
  insert_into_json_object(val, doc, "fee", sig.txnFee);

  // prunable
  {
    rapidjson::Value prunable;
    prunable.SetObject();

    insert_into_json_object(prunable, doc, "range_proofs", sig.p.rangeSigs);
    insert_into_json_object(prunable, doc, "bulletproofs", sig.p.bulletproofs);
    insert_into_json_object(prunable, doc, "mlsags", sig.p.MGs);
    insert_into_json_object(prunable, doc, "pseudo_outs", sig.get_pseudo_outs());

    val.AddMember("prunable", prunable, doc.GetAllocator());
  }
}

void fromJsonValue(const rapidjson::Value& val, rct::rctSig& sig)
{
  if (!val.IsObject())
  {
    throw WRONG_TYPE("json object");
  }

  std::vector<rct::key> commitments;

  load_from_json_object(val, "type", sig.type);
  load_from_json_object(val, "encrypted", sig.ecdhInfo);
  load_from_json_object(val, "commitments", commitments);
  load_from_json_object(val, "fee", sig.txnFee);

  // prunable
  {
    require_member(val, "prunable");
    const auto& prunable = val["prunable"];

    rct::keyV pseudo_outs;

    load_from_json_object(prunable, "range_proofs", sig.p.rangeSigs);
    load_from_json_object(prunable, "bulletproofs", sig.p.bulletproofs);
    load_from_json_object(prunable, "mlsags", sig.p.MGs);
    load_from_json_object(prunable, "pseudo_outs", pseudo_outs);

    sig.get_pseudo_outs() = std::move(pseudo_outs);
  }

  sig.outPk.reserve(commitments.size());
  for (rct::key const& commitment : commitments)
  {
    sig.outPk.push_back({{}, commitment});
  }
}

void toJsonValue(rapidjson::Document& doc, const rct::ecdhTuple& tuple, rapidjson::Value& val)
{
  val.SetObject();

  insert_into_json_object(val, doc, "mask", tuple.mask);
  insert_into_json_object(val, doc, "amount", tuple.amount);
}

void fromJsonValue(const rapidjson::Value& val, rct::ecdhTuple& tuple)
{
  if (!val.IsObject())
  {
    throw WRONG_TYPE("json object");
  }

  load_from_json_object(val, "mask", tuple.mask);
  load_from_json_object(val, "amount", tuple.amount);
}

void toJsonValue(rapidjson::Document& doc, const rct::rangeSig& sig, rapidjson::Value& val)
{
  val.SetObject();

  insert_into_json_object(val, doc, "asig", sig.asig);

  std::vector<rct::key> keyVector(sig.Ci, std::end(sig.Ci));
  insert_into_json_object(val, doc, "Ci", keyVector);
}

void fromJsonValue(const rapidjson::Value& val, rct::rangeSig& sig)
{
  if (!val.IsObject())
  {
    throw WRONG_TYPE("json object");
  }

  const auto ci = val.FindMember("Ci");
  if (ci == val.MemberEnd())
  {
    throw MISSING_KEY("Ci");
  }

  load_from_json_object(val, "asig", sig.asig);

  std::vector<rct::key> keyVector;
  cryptonote::json::fromJsonValue(ci->value, keyVector);
  if (!(keyVector.size() == 64))
  {
    throw WRONG_TYPE("key64 (rct::key[64])");
  }
  for (size_t i=0; i < 64; i++)
  {
    sig.Ci[i] = keyVector[i];
  }
}

void toJsonValue(rapidjson::Document& doc, const rct::Bulletproof& p, rapidjson::Value& val)
{
  val.SetObject();

  insert_into_json_object(val, doc, "V", p.V);
  insert_into_json_object(val, doc, "A", p.A);
  insert_into_json_object(val, doc, "S", p.S);
  insert_into_json_object(val, doc, "T1", p.T1);
  insert_into_json_object(val, doc, "T2", p.T2);
  insert_into_json_object(val, doc, "taux", p.taux);
  insert_into_json_object(val, doc, "mu", p.mu);
  insert_into_json_object(val, doc, "L", p.L);
  insert_into_json_object(val, doc, "R", p.R);
  insert_into_json_object(val, doc, "a", p.a);
  insert_into_json_object(val, doc, "b", p.b);
  insert_into_json_object(val, doc, "t", p.t);
}

void fromJsonValue(const rapidjson::Value& val, rct::Bulletproof& p)
{
  if (!val.IsObject())
  {
    throw WRONG_TYPE("json object");
  }

  load_from_json_object(val, "V", p.V);
  load_from_json_object(val, "A", p.A);
  load_from_json_object(val, "S", p.S);
  load_from_json_object(val, "T1", p.T1);
  load_from_json_object(val, "T2", p.T2);
  load_from_json_object(val, "taux", p.taux);
  load_from_json_object(val, "mu", p.mu);
  load_from_json_object(val, "L", p.L);
  load_from_json_object(val, "R", p.R);
  load_from_json_object(val, "a", p.a);
  load_from_json_object(val, "b", p.b);
  load_from_json_object(val, "t", p.t);
}

void toJsonValue(rapidjson::Document& doc, const rct::boroSig& sig, rapidjson::Value& val)
{
  val.SetObject();

  std::vector<rct::key> keyVector(sig.s0, std::end(sig.s0));
  insert_into_json_object(val, doc, "s0", keyVector);

  keyVector.assign(sig.s1, std::end(sig.s1));
  insert_into_json_object(val, doc, "s1", keyVector);

  insert_into_json_object(val, doc, "ee", sig.ee);
}

void fromJsonValue(const rapidjson::Value& val, rct::boroSig& sig)
{
  if (!val.IsObject())
  {
    throw WRONG_TYPE("json object");
  }

  require_member(val, "s0");
  std::vector<rct::key> keyVector;
  cryptonote::json::fromJsonValue(val["s0"], keyVector);
  if (!(keyVector.size() == 64))
  {
    throw WRONG_TYPE("key64 (rct::key[64])");
  }
  for (size_t i=0; i < 64; i++)
  {
    sig.s0[i] = keyVector[i];
  }

  require_member(val, "s1");
  keyVector.clear();
  cryptonote::json::fromJsonValue(val["s1"], keyVector);
  if (!(keyVector.size() == 64))
  {
    throw WRONG_TYPE("key64 (rct::key[64])");
  }
  for (size_t i=0; i < 64; i++)
  {
    sig.s1[i] = keyVector[i];
  }

  load_from_json_object(val, "ee", sig.ee);
}

void toJsonValue(rapidjson::Document& doc, const rct::mgSig& sig, rapidjson::Value& val)
{
  val.SetObject();

  insert_into_json_object(val, doc, "ss", sig.ss);
  insert_into_json_object(val, doc, "cc", sig.cc);
}

void fromJsonValue(const rapidjson::Value& val, rct::mgSig& sig)
{
  if (!val.IsObject())
  {
    throw WRONG_TYPE("key64 (rct::key[64])");
  }

  load_from_json_object(val, "ss", sig.ss);
  load_from_json_object(val, "cc", sig.cc);
}

void toJsonValue(rapidjson::Document& doc, const cryptonote::rpc::DaemonInfo& info, rapidjson::Value& val)
{
  val.SetObject();

  insert_into_json_object(val, doc, "height", info.height);
  insert_into_json_object(val, doc, "target_height", info.target_height);
  insert_into_json_object(val, doc, "difficulty", info.difficulty);
  insert_into_json_object(val, doc, "target", info.target);
  insert_into_json_object(val, doc, "tx_count", info.tx_count);
  insert_into_json_object(val, doc, "tx_pool_size", info.tx_pool_size);
  insert_into_json_object(val, doc, "alt_blocks_count", info.alt_blocks_count);
  insert_into_json_object(val, doc, "outgoing_connections_count", info.outgoing_connections_count);
  insert_into_json_object(val, doc, "incoming_connections_count", info.incoming_connections_count);
  insert_into_json_object(val, doc, "white_peerlist_size", info.white_peerlist_size);
  insert_into_json_object(val, doc, "grey_peerlist_size", info.grey_peerlist_size);
  insert_into_json_object(val, doc, "mainnet", info.mainnet);
  insert_into_json_object(val, doc, "testnet", info.testnet);
  insert_into_json_object(val, doc, "stagenet", info.stagenet);
  insert_into_json_object(val, doc, "nettype", info.nettype);
  insert_into_json_object(val, doc, "top_block_hash", info.top_block_hash);
  insert_into_json_object(val, doc, "cumulative_difficulty", info.cumulative_difficulty);
  insert_into_json_object(val, doc, "block_size_limit", info.block_size_limit);
  insert_into_json_object(val, doc, "block_weight_limit", info.block_weight_limit);
  insert_into_json_object(val, doc, "block_size_median", info.block_size_median);
  insert_into_json_object(val, doc, "block_weight_median", info.block_weight_median);
  insert_into_json_object(val, doc, "start_time", info.start_time);
}

void fromJsonValue(const rapidjson::Value& val, cryptonote::rpc::DaemonInfo& info)
{
  if (!val.IsObject())
  {
    throw WRONG_TYPE("json object");
  }

  load_from_json_object(val, "height", info.height);
  load_from_json_object(val, "target_height", info.target_height);
  load_from_json_object(val, "difficulty", info.difficulty);
  load_from_json_object(val, "target", info.target);
  load_from_json_object(val, "tx_count", info.tx_count);
  load_from_json_object(val, "tx_pool_size", info.tx_pool_size);
  load_from_json_object(val, "alt_blocks_count", info.alt_blocks_count);
  load_from_json_object(val, "outgoing_connections_count", info.outgoing_connections_count);
  load_from_json_object(val, "incoming_connections_count", info.incoming_connections_count);
  load_from_json_object(val, "white_peerlist_size", info.white_peerlist_size);
  load_from_json_object(val, "grey_peerlist_size", info.grey_peerlist_size);
  load_from_json_object(val, "mainnet", info.mainnet);
  load_from_json_object(val, "testnet", info.testnet);
  load_from_json_object(val, "stagenet", info.stagenet);
  load_from_json_object(val, "nettype", info.nettype);
  load_from_json_object(val, "top_block_hash", info.top_block_hash);
  load_from_json_object(val, "cumulative_difficulty", info.cumulative_difficulty);
  load_from_json_object(val, "block_size_limit", info.block_size_limit);
  load_from_json_object(val, "block_weight_limit", info.block_weight_limit);
  load_from_json_object(val, "block_size_median", info.block_size_median);
  load_from_json_object(val, "block_weight_median", info.block_weight_median);
  load_from_json_object(val, "start_time", info.start_time);
}

void toJsonValue(rapidjson::Document& doc, const cryptonote::rpc::output_distribution& dist, rapidjson::Value& val)
{
  val.SetObject();

  insert_into_json_object(val, doc, "distribution", dist.data.distribution);
  insert_into_json_object(val, doc, "amount", dist.amount);
  insert_into_json_object(val, doc, "start_height", dist.data.start_height);
  insert_into_json_object(val, doc, "base", dist.data.base);
}

void fromJsonValue(const rapidjson::Value& val, cryptonote::rpc::output_distribution& dist)
{
  if (!val.IsObject())
  {
    throw WRONG_TYPE("json object");
  }

  load_from_json_object(val, "distribution", dist.data.distribution);
  load_from_json_object(val, "amount", dist.amount);
  load_from_json_object(val, "start_height", dist.data.start_height);
  load_from_json_object(val, "base", dist.data.base);
}

}  // namespace json

}  // namespace cryptonote
