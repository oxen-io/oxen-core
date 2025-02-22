#!/user/bin/python3

## USAGE
### python3 main.py --tx-extra 0158b9e078dd8c9789be6cc38e7922679734363b87400b9a9bd2ecfd63bffc1a1902090147195636b035b6947a0000114185c0b8bbe6c88966f4393e3069a2b28a979feee27750fc8f527e7cc6ecee00000000000000000000000000000000000000000000000000000000000000000900a1bd51151cc8bc101e523e1a65f27ee83b8e69cbbfefe12320163fd4a22844d6f1595f615164cd19cab8db5c9c00b1a257acf968c6ba72a556cf0b11d3884f480049c2be24ea21c5c91008081ccf401b5a26552b8572bde2d541f8095865c9358184423d738b729f6163301e04c02cccb1fe9680dbc03afe44526856abe99ad2b76d7987b1e333850e1f097900863ba101000000

import argparse
from enum import IntFlag, auto

parser = argparse.ArgumentParser(description='Decode TX Extra')
parser.add_argument("--tx-extra", required=True, help="Hex string for the tx txtra to be decoded, type=string")
args = parser.parse_args()

tx_extra = args.tx_extra

tx_extra_list = list(tx_extra)

tag_dictionary = {
    "00" : "TX_EXTRA_TAG_PADDING",
    "01" : "TX_EXTRA_TAG_PUBKEY",
    "02" : "TX_EXTRA_NONCE",
    "03" : "TX_EXTRA_MERGE_MINING_TAG",
    "04" : "TX_EXTRA_TAG_ADDITIONAL_PUBKEYS",
    "70" : "TX_EXTRA_TAG_SERVICE_NODE_REGISTER",
    "71" : "TX_EXTRA_TAG_SERVICE_NODE_DEREG_OLD",
    "72" : "TX_EXTRA_TAG_SERVICE_NODE_WINNER",
    "73" : "TX_EXTRA_TAG_SERVICE_NODE_CONTRIBUTOR",
    "74" : "TX_EXTRA_TAG_SERVICE_NODE_PUBKEY",
    "75" : "TX_EXTRA_TAG_TX_SECRET_KEY",
    "76" : "TX_EXTRA_TAG_TX_KEY_IMAGE_PROOFS",
    "77" : "TX_EXTRA_TAG_TX_KEY_IMAGE_UNLOCK",
    "78" : "TX_EXTRA_TAG_SERVICE_NODE_STATE_CHANGE",
    "79" : "TX_EXTRA_TAG_BURN",
    "7A" : "TX_EXTRA_TAG_OXEN_NAME_SYSTEM"
}

def eat_pubkey_data():
    global tx_extra_list
    pubkey = ''.join(tx_extra_list[:64])
    tx_extra_list = tx_extra_list[64:]
    return {"pubkey": pubkey}


nonce_tag_dictionary = {
    "00" : "payment_id",
    "01" : "encrypted_payment_id"
}

def eat_nonce_data():
    global tx_extra_list
    size = (int(''.join(tx_extra_list[:2])) - 1)*2
    tx_extra_list = tx_extra_list[2:]
    nonce_tag = ''.join(tx_extra_list[:2])
    tx_extra_list = tx_extra_list[2:]
    nonce_data = ''.join(tx_extra_list[:size])
    tx_extra_list = tx_extra_list[size:]
    return {nonce_tag_dictionary[nonce_tag]: nonce_data}

ons_type_dictionary = {
    "00" : "session",
    "01" : "wallet",
    "02" : "lokinet",
    "03" : "lokinet 2 year",
    "04" : "lokinet 5 year",
    "05" : "lokinet 10 year"
}

class ONS_EXTRA_FIELD(IntFlag):
    OWNER = auto()
    BACKUP_OWNER = auto()
    SIGNATURE = auto()
    ENCRYPTED_VALUE = auto()

class ONS_Extra_Field_Set:
    def __init__(self, *flags):
        self._extras = ONS_EXTRA_FIELD(0)  # Initiate no permissions
        for flag in flags:
            self._extras |= ONS_EXTRA_FIELD[flag.upper()]
    def __contains__(self, item):
        return (self._extras & item) == item

def eat_ons_generic_owner():
    global tx_extra_list
    owner_type = ''.join(tx_extra_list[:2])
    tx_extra_list = tx_extra_list[2:]
    spend_public_key = ''.join(tx_extra_list[:64])
    tx_extra_list = tx_extra_list[64:]
    view_public_key = ''.join(tx_extra_list[:64])
    tx_extra_list = tx_extra_list[64:]
    is_subaddress = ''.join(tx_extra_list[:2])
    tx_extra_list = tx_extra_list[2:]
    return {"type": owner_type,
            "spend_public_key": spend_public_key,
            "view_public_key": view_public_key,
            "is_subaddress": is_subaddress }


def eat_ons_data():
    global tx_extra_list
    version = ''.join(tx_extra_list[:2])
    tx_extra_list = tx_extra_list[2:]
    ons_type = ''.join(tx_extra_list[:2])
    tx_extra_list = tx_extra_list[2:]
    name_hash = ''.join(tx_extra_list[:64])
    tx_extra_list = tx_extra_list[64:]
    prev_txid = ''.join(tx_extra_list[:64])
    tx_extra_list = tx_extra_list[64:]
    ons_fields = ONS_EXTRA_FIELD(int(''.join(tx_extra_list[:2])))
    ons_data = {'version': version,
            'type': ons_type_dictionary[ons_type],
            'name_hash': name_hash,
            'prev_txid': prev_txid,
            'fields': ons_fields}
    tx_extra_list = tx_extra_list[2:]
    ons_extra_field_set = ONS_Extra_Field_Set()
    ons_extra_field_set._extras = ons_fields
    if ONS_EXTRA_FIELD.OWNER in ons_extra_field_set:
        ons_data['owner'] = eat_ons_generic_owner()
    if ONS_EXTRA_FIELD.BACKUP_OWNER in ons_extra_field_set:
        ons_data['backup_owner'] = eat_ons_generic_owner()
    if ONS_EXTRA_FIELD.SIGNATURE in ons_extra_field_set:
        signature = ''.join(tx_extra_list[:64])
        tx_extra_list = tx_extra_list[64:]
        ons_data['signature'] = signature
    if ONS_EXTRA_FIELD.ENCRYPTED_VALUE in ons_extra_field_set:
        size = (int(''.join(tx_extra_list[:2]), 16))*2
        tx_extra_list = tx_extra_list[2:]
        encrypted_value = ''.join(tx_extra_list[:size])
        tx_extra_list = tx_extra_list[size:]
        ons_data['encrypted_value'] = encrypted_value
    return ons_data

def eat_uint64_t():
    global tx_extra_list
    amount = ''.join(tx_extra_list[:8*2])
    tx_extra_list = tx_extra_list[8*2:]
    return int.from_bytes(bytearray.fromhex(amount), "little", signed=False)


def eat_burn():
    global tx_extra_list
    return {"amount": eat_uint64_t()}



eat_data_functions = {
    "TX_EXTRA_TAG_PUBKEY": eat_pubkey_data,
    "TX_EXTRA_NONCE": eat_nonce_data,
    "TX_EXTRA_TAG_OXEN_NAME_SYSTEM": eat_ons_data,
    "TX_EXTRA_TAG_BURN": eat_burn
}

# Main loop that reads over every item
while len(tx_extra_list) > 0:
    tag = tag_dictionary[''.join(tx_extra_list[:2]).upper()]
    tx_extra_list = tx_extra_list[2:]
    print(tag)
    print(eat_data_functions[tag]())




