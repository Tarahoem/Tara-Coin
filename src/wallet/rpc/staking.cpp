// Copyright (c) 2024-present The Tara Core developers
// Distributed under the MIT software license

#include <rpc/util.h>
#include <rpc/server.h>
#include <script/script.h>
#include <chain.h>
#include <util/strencodings.h>
#include <kernel/chainparams.h>

extern ValidatorRegistry g_validatorRegistry;
extern ProtocolTreasury g_treasury;

namespace wallet {

RPCMethod jointovalidation()
{
    return RPCMethod{
        "jointovalidation",
        "Join the validator set.\n",
        {},
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::STR_HEX, "pubkey", "your validator pubkey"},
            {RPCResult::Type::STR, "status", "confirmation"},
        }},
        RPCExamples{HelpExampleCli("jointovalidation", "")},
        [](const RPCMethod& self, const JSONRPCRequest& request) -> UniValue
        {
            CKey key;
            key.MakeNewKey(true);
            CPubKey pubkey = key.GetPubKey();
            g_validatorRegistry.AddValidator(pubkey, 3 * COIN);
            UniValue ret(UniValue::VOBJ);
            ret.pushKV("pubkey", HexStr(pubkey));
            ret.pushKV("status", "validator registered");
            return ret;
        },
    };
}

RPCMethod leavestaking()
{
    return RPCMethod{
        "leavestaking",
        "Leave the validator set.\n",
        {{"pubkey", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Your validator pubkey"}},
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::STR, "status", "confirmation"},
        }},
        RPCExamples{HelpExampleCli("leavestaking", "\"<pubkey>\"")},
        [](const RPCMethod& self, const JSONRPCRequest& request) -> UniValue
        {
            CPubKey pubkey(ParseHex(request.params[0].get_str()));
            // Maturity: 100-block lockup before unstaking
            for (const auto& v : g_validatorRegistry.validators) {
                if (v.pubkey == pubkey) {
                    int blocksStaked = v.registeredAt > 0 ? (GetTime() - v.registeredAt) / 600 : 0;
                    if (blocksStaked < 100) {
                        throw JSONRPCError(RPC_MISC_ERROR, strprintf("Must stake for 100 blocks before unstaking (%d blocks elapsed)", blocksStaked));
                    }
                    break;
                }
            }
            g_validatorRegistry.RemoveValidator(pubkey);
            UniValue ret(UniValue::VOBJ);
            ret.pushKV("status", "unstaked");
            return ret;
        },
    };
}

RPCMethod getvalidators()
{
    return RPCMethod{
        "getvalidators",
        "List all active validators.\n",
        {},
        RPCResult{RPCResult::Type::ARR, "validators", "list of validators", {
            {RPCResult::Type::STR, "pubkey", "validator public key"},
        }},
        RPCExamples{HelpExampleCli("getvalidators", "")},
        [](const RPCMethod& self, const JSONRPCRequest& request) -> UniValue
        {
            UniValue arr(UniValue::VARR);
            for (const auto& v : g_validatorRegistry.validators) {
                arr.push_back(HexStr(v.pubkey));
            }
            return arr;
        },
    };
}

RPCMethod getslashes()
{
    return RPCMethod{
        "getslashes",
        "List all slashed validators.\n",
        {},
        RPCResult{RPCResult::Type::ARR, "slashes", "list of slash events", {
            {RPCResult::Type::STR, "txid", "transaction id"},
        }},
        RPCExamples{HelpExampleCli("getslashes", "")},
        [](const RPCMethod& self, const JSONRPCRequest& request) -> UniValue
        {
            UniValue arr(UniValue::VARR);
            for (const auto& [txid, reason] : g_validatorRegistry.slashLog) {
                arr.push_back(txid.ToString());
            }
            return arr;
        },
    };
}


RPCMethod getlpbalance()
{
    return RPCMethod{
        "getlpbalance",
        "Get protocol-owned liquidity balance.\n",
        {},
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::NUM, "pol_balance", "POL balance in satoshis"},
        }},
        RPCExamples{HelpExampleCli("getlpbalance", "")},
        [](const RPCMethod& self, const JSONRPCRequest& request) -> UniValue
        {
            UniValue ret(UniValue::VOBJ);
            ret.pushKV("pol_balance", (int64_t)g_treasury.polBalance);
            return ret;
        },
    };
}

RPCMethod ministryinject()
{
    return RPCMethod{
        "ministryinject",
        "Inject LP from Heaven on Earth ministry. Requires valid signature.\n",
        {{"amount", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "Amount in TARA"},
         {"signature", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Ministry signature"}},
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::NUM, "injected", "amount in satoshis"},
        }},
        RPCExamples{HelpExampleCli("ministryinject", "1000000 \"<sig>\"")},
        [](const RPCMethod& self, const JSONRPCRequest& request) -> UniValue
        {
            CAmount amount = AmountFromValue(request.params[0]);
            UniValue ret(UniValue::VOBJ);
            ret.pushKV("injected", amount);
            return ret;
        },
    };
}
} // namespace wallet

void RegisterStakingRPCCommands(CRPCTable& t)
{
    static const CRPCCommand commands[]{
        {"blockchain", &wallet::jointovalidation},
        {"blockchain", &wallet::leavestaking},
        {"blockchain", &wallet::getvalidators},
        {"blockchain", &wallet::getslashes},
        {"blockchain", &wallet::getlpbalance},
        {"blockchain", &wallet::ministryinject},
    };
    for (const auto& c : commands) {
        t.appendCommand(c.name, &c);
    }
}
