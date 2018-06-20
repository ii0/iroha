#
# Copyright Soramitsu Co., Ltd. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#

import iroha
import commons

admin = commons.user('admin@first')
alice = commons.user('alice@second')

alice_tx1_hash = None
alice_tx2_hash_hex = None

def genesis_tx():
    test_permissions = iroha.StringVector()
    test_permissions.append('can_get_my_txs')
    test_permissions.append('can_add_asset_qty')
    test_permissions.append('can_create_asset')
    tx = iroha.ModelTransactionBuilder() \
        .createdTime(commons.now()) \
        .creatorAccountId(admin['id']) \
        .addPeer('0.0.0.0:50541', admin['key'].publicKey()) \
        .createRole('admin_role', commons.all_permissions()) \
        .createRole('test_role', test_permissions) \
        .createDomain('first', 'admin_role') \
        .createDomain('second', 'test_role') \
        .createAccount('admin', 'first', admin['key'].publicKey()) \
        .createAccount('alice', 'second', alice['key'].publicKey()) \
        .build()
    return iroha.ModelProtoTransaction(tx) \
        .signAndAddSignature(admin['key']).finish()


def alice_action_1_tx():
    global alice_tx1_hash
    tx = iroha.ModelTransactionBuilder() \
        .createdTime(commons.now()) \
        .creatorAccountId(alice['id']) \
        .createAsset('coin', 'first', 2) \
        .build()
    alice_tx1_hash = tx.hash()
    return iroha.ModelProtoTransaction(tx) \
        .signAndAddSignature(alice['key']).finish()


def alice_action_2_tx():
    global alice_tx2_hash_hex
    tx = iroha.ModelTransactionBuilder() \
        .createdTime(commons.now()) \
        .creatorAccountId(alice['id']) \
        .addAssetQuantity(alice['id'], 'coin#first', '600.30') \
        .build()
    alice_tx2_hash_hex = tx.hash().hex()
    return iroha.ModelProtoTransaction(tx) \
        .signAndAddSignature(alice['key']).finish()


def transactions_query():
    hashes = iroha.HashVector()
    hashes.append(alice_tx1_hash)
    hashes.append(iroha.Hash(alice_tx2_hash_hex))
    tx = iroha.ModelQueryBuilder() \
        .createdTime(commons.now()) \
        .queryCounter(1) \
        .creatorAccountId(alice['id']) \
        .getTransactions(hashes) \
        .build()
    return iroha.ModelProtoQuery(tx) \
        .signAndAddSignature(alice['key']).finish()


print(admin['key'].privateKey().hex())
print(genesis_tx().hex())
print(alice_action_1_tx().hex())
print(alice_action_2_tx().hex())
print(transactions_query().hex())