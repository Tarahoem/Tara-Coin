// Copyright (c) 2017-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/tx_check.h>

#include <consensus/amount.h>
#include <primitives/transaction.h>
#include <consensus/validation.h>

bool CheckTransaction(const CTransaction& tx, TxValidationState& state)
{
    // Basic checks that don't depend on any context
    // Gaming/Metaverse transaction bounds check
    for (const auto& vout : tx.vout) {
        if (vout.scriptPubKey.size() >= 2 && vout.scriptPubKey[0] == OP_BET) {
            if (vout.scriptPubKey.size() > MAX_SCRIPT_SIZE) {
                return state.Invalid(TxValidationResult::TX_CONSENSUS, "gaming-script-too-large");
            }
            if (vout.nValue > MAX_MONEY) {
                return state.Invalid(TxValidationResult::TX_CONSENSUS, "gaming-value-overflow");
            }
        }
    }

    // Token creation transaction validation
    for (const auto& vout : tx.vout) {
        if (vout.scriptPubKey.size() >= 14 && vout.scriptPubKey[0] == OP_RETURN) {
            std::vector<unsigned char> data(vout.scriptPubKey.begin(), vout.scriptPubKey.end());
            const char marker[] = "TARA_TOKEN";
            if (data.size() >= 12 && data[1] == 0x0a && memcmp(&data[2], marker, 10) == 0) {
                // Validate token creation has exactly 1 input (burns TARA to create token)
                if (tx.vin.size() != 1) {
                    return state.Invalid(TxValidationResult::TX_CONSENSUS, "token-creation-requires-one-input");
                }
                if (tx.vout.size() > 10) {
                    return state.Invalid(TxValidationResult::TX_CONSENSUS, "token-creation-too-many-outputs");
                }
            }
        }
    }

    if (tx.vin.empty())
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-vin-empty");
    if (tx.vout.empty())
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-vout-empty");
    // Size limits (this doesn't take the witness into account, as that hasn't been checked for malleability)
    if (::GetSerializeSize(TX_NO_WITNESS(tx)) * WITNESS_SCALE_FACTOR > MAX_BLOCK_WEIGHT) {
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-oversize");
    }

    // Check for negative or overflow output values (see CVE-2010-5139)
    CAmount nValueOut = 0;
    for (const auto& txout : tx.vout)
    {
        if (txout.nValue < 0)
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-vout-negative");
        if (txout.nValue > MAX_MONEY)
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-vout-toolarge");
        nValueOut += txout.nValue;
        if (!MoneyRange(nValueOut))
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-txouttotal-toolarge");
    }

    // Check for duplicate inputs (see CVE-2018-17144)
    // While Consensus::CheckTxInputs does check if all inputs of a tx are available, and UpdateCoins marks all inputs
    // of a tx as spent, it does not check if the tx has duplicate inputs.
    // Failure to run this check will result in either a crash or an inflation bug, depending on the implementation of
    // the underlying coins database.
    std::set<COutPoint> vInOutPoints;
    for (const auto& txin : tx.vin) {
        if (!vInOutPoints.insert(txin.prevout).second)
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-inputs-duplicate");
    }

    if (tx.IsCoinBase())
    {
        if (tx.vin[0].scriptSig.size() < 2 || tx.vin[0].scriptSig.size() > 100)
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-cb-length");
    }
    else
    {
        for (const auto& txin : tx.vin)
            if (txin.prevout.IsNull())
                return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-prevout-null");
    }

    return true;
}
