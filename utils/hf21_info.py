#!/usr/bin/env python3

import requests

from hf21_transition_data import addresses, transition_bonus

print(f"{len(addresses)} addresses and {len(transition_bonus)} bonus entries")

#url_base = 'http://127.0.0.1:38157/'
url_base = 'http://127.0.0.1:22023/'

def json_rpc(method, params=None, timeout=50):
    json = {
        "jsonrpc": "2.0",
        "id": "0",
        "method": method,
    }
    if params:
        json["params"] = params

    return requests.post('{}/json_rpc'.format(url_base), json=json, timeout=timeout)

def get_service_nodes():
    return json_rpc('get_service_nodes').json()

conversion_ratio = 0.54  # dummy value
conversion_ratio_parts = [54, 100]  # dummy value
staking_requirement = 25000000000000

# added for testnet to get all contributor addresses to put in the
# list above, as I did not have a list.
def get_addresses():

    addrs = {}
    for res in get_service_nodes()['result']['service_node_states']:
        for contributor in res['contributors']:
            addrs[contributor['address']] = 1

    for addr in addrs:
        print(addr)

def get_migration():
    bls_map = {}
    edkey_map = {}
    seed_list = []
    not_migrating_count = 0
    for res in get_service_nodes()['result']['service_node_states']:
        edkey = res['pubkey_ed25519']

        if not res['active']:
            print(f"Not migrating {edkey} because it's not active")
            not_migrating_count += 1
            continue

        if 'pubkey_bls' not in res:
            print(f"Not migrating {edkey} because it somehow does not have a bls pubkey set")
            not_migrating_count += 1
            continue

        if res['operator_address'] not in addresses:
            print(f"Not migrating {edkey} because its operator address is not registered to convert")
            not_migrating_count += 1
            continue

        if res['operator_address'] != res['contributors'][0]['address']:
            print(f"operator_address != first contributor address -- ({res['operator_address']} != {res['contributors'][0]['address']}")
            not_migrating_count += 1
            continue

        ok = True
        contributors = []
        contribution_sum = 0
        for cont in res['contributors']:
            if cont['address'] not in addresses or len(addresses[cont['address']]) == 0:
                ok = False
                break
            contributors.append({'address': addresses[cont['address']], 'amount': int(cont['amount'] * conversion_ratio)})
            contribution_sum += contributors[-1]['amount']

        if not ok:
            print(f"Not migrating {edkey} because a contributor address is not registered to convert")
            not_migrating_count += 1
            continue

        # TODO: normalize if sum > req for the few nodes on mainnet with a higher stake sum
        if contribution_sum != staking_requirement:
            new_sum = 0
            for c in contributors:
                c['amount'] = int(c['amount'] / (contribution_sum + 1) * staking_requirement)
                new_sum += c['amount']
            if new_sum < staking_requirement:
                contributors[0]['amount'] += staking_requirement - new_sum

        seed_list.append({
            'bls_pubkey': res['pubkey_bls'],
            'ed25519_pubkey': edkey,
            'contributors': contributors,
        })

        bls_map[edkey] = res['pubkey_bls']

        if res['service_node_pubkey'] != edkey:
            edkey_map[res['service_node_pubkey']] = edkey

    print(f"\nNot migrating {not_migrating_count} nodes\n")
    return [bls_map, edkey_map, seed_list]

def print_migration():
    bls_map, edkey_map, seed_list = get_migration()
    
    with open("hf21_transition_data.cpp", "w") as f:
        f.write(
"""#include <oxenc/hex.h>

#include <cstdint>
#include <string_view>
#include <unordered_map>

#include "crypto/crypto.h"
#include "crypto/eth.h"
#include "crypto/literals.h"
#include "detail.h"

namespace oxen::sent::mainnet {

using namespace std::literals;
using namespace crypto::literals;

// clang-format off

const std::unordered_map<std::string_view, eth::address> addresses{
""")
        print("Printing C++ for oxen -> eth mapping\n")
        for addr, eth in sorted(addresses.items()):
            if len(eth):
                to_write = f'    {{"{addr}"sv, "{eth}"_eth}},\n'
                print(to_write, end="")
                f.write(to_write)
        print("")
        f.write(
"""};

const std::unordered_map<crypto::public_key, crypto::ed25519_public_key> proper_ed_keys{
""")

        print("Printing C++ for monero key -> ed25519 key mapping\n")
        for monero_key, ed_key in sorted(edkey_map.items()):
            to_write = f'    {{"{monero_key}"_pk, "{ed_key}"_edpk}},\n'
            print(to_write, end="")
            f.write(to_write)
        print("")
        f.write(
"""};

const std::unordered_map<crypto::ed25519_public_key, eth::bls_public_key> bls_keys{
""")

        print("Printing C++ for ed -> bls mapping\n")
        for edkey, blskey in sorted(bls_map.items()):
            to_write = f'    {{"{edkey}"_edpk, "{blskey}"_blspk}},\n'
            print(to_write, end="")
            f.write(to_write)
        print("")
        f.write("};\n\n")
        f.write(f"const std::pair<std::uint64_t, std::uint64_t> conv_ratio{{{conversion_ratio_parts[0]}, {conversion_ratio_parts[1]}}};\n")

        f.write("\nconst std::unordered_map<eth::address, std::uint64_t> transition_bonus{\n")

        print("Printing C++ for transition bonus\n")
        for addr, amt in sorted(transition_bonus.items(), key=lambda x: str.lower(x[0])):
            to_write = f'    {{"{addr}"_eth, {amt}}},\n'
            print(to_write, end="")
            f.write(to_write)
        print("")
        f.write(
"""};

// clang-format-on

}  // namespace oxen::sent::mainnet
""")

    print("Printing python for seeding contract\n")
    from pprint import pformat
    s = pformat(seed_list)
    print(s)
    with open("contract_seed_info.py", "w") as f:
        f.write(s)
    print("Wrote cpp code to hf21_transition_data.cpp as well as printing")
    print("Wrote contract seed info to contract_seed_info.py as well as printing")

def write_proofs_file():
    proofs = json_rpc('get_all_uptime_proofs').json()
    with open("bls_proofs.txt", "w") as f:
        f.write("{} {} {} {} {} {} {}".format(
                "proof",
                "pubkey",
                "sig",
                "pubkey_ed25519",
                "sig_ed25519",
                "pubkey_bls",
                "pop_bls"))
        for proof in proofs['result']['proofs']:
            f.write("\n{} {} {} {} {} {} {}".format(
                    proof["proof"],
                    proof["pubkey"],
                    proof["sig"],
                    proof["pubkey_ed25519"],
                    proof["sig_ed25519"],
                    proof["pubkey_bls"],
                    proof["pop_bls"]))
    print("Wrote bls proof of possession table to bls_proofs.txt")

print_migration()
write_proofs_file()
