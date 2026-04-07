//! fl-send-tx — Final Layer transaction sender
//! Commands:
//!   transfer        --key-file <path> --receiver <account> --amount <FLC>
//!   create-account  --key-file <path> --new-account <id> --new-public-key <pk> --initial-balance <FLC>
//!   add-key         --key-file <path> --new-public-key <pk> [--permission full-access|function-call]
//!   delete-key      --key-file <path> --delete-public-key <pk>
//!   deploy    --key-file <path> --receiver <account> --wasm <path> [--init-method <fn> --init-args <json>]
//!   call      --key-file <path> --receiver <account> --method <fn> --args <json> [--deposit <FLC>]
//!   stake     --key-file <path> --amount <FLC>
//!   view      --account <id>
//!   [--rpc <url>]

use base64::Engine as _;
use near_crypto::{InMemorySigner, PublicKey};
use near_primitives::account::{AccessKey, AccessKeyPermission};
use near_primitives::action::{AddKeyAction, CreateAccountAction, DeleteKeyAction, DeployContractAction, FunctionCallAction, StakeAction, TransferAction};
use near_primitives::transaction::{Action, SignedTransaction, Transaction, TransactionV0};
use near_primitives::types::Gas;
use near_token::NearToken;
use serde_json::Value;
use std::path::PathBuf;
use std::str::FromStr;

const DEFAULT_RPC: &str = "http://127.0.0.1:3030";
const YOCTO_PER_FLC: u128 = 1_000_000_000_000_000_000_000_000;
fn default_gas() -> Gas { Gas::from_teragas(100) }

fn rpc_call(rpc_url: &str, method: &str, params: Value) -> anyhow::Result<Value> {
    let client = reqwest::blocking::Client::new();
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": "1",
        "method": method,
        "params": params
    });
    let body_str = serde_json::to_string(&body)?;
    let resp_text = client
        .post(rpc_url)
        .header("Content-Type", "application/json")
        .body(body_str)
        .send()?
        .text()?;
    let resp: Value = serde_json::from_str(&resp_text)?;
    if let Some(err) = resp.get("error") {
        anyhow::bail!("RPC error: {}", err);
    }
    Ok(resp["result"].clone())
}

fn get_access_key_nonce(rpc_url: &str, account_id: &str, public_key: &str) -> anyhow::Result<u64> {
    let result = rpc_call(
        rpc_url,
        "query",
        serde_json::json!({
            "request_type": "view_access_key",
            "finality": "optimistic",
            "account_id": account_id,
            "public_key": public_key
        }),
    )?;
    Ok(result["nonce"].as_u64().unwrap_or(0))
}

fn get_latest_block_hash(rpc_url: &str) -> anyhow::Result<[u8; 32]> {
    let result = rpc_call(rpc_url, "block", serde_json::json!({ "finality": "final" }))?;
    let hash_str = result["header"]["hash"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("No block hash in response"))?;
    let decoded = bs58::decode(hash_str)
        .into_vec()
        .map_err(|e| anyhow::anyhow!("bs58 decode error: {}", e))?;
    decoded.try_into().map_err(|_| anyhow::anyhow!("Block hash wrong length"))
}

fn broadcast_tx(rpc_url: &str, signed_tx_bytes: &[u8]) -> anyhow::Result<Value> {
    let encoded = base64::engine::general_purpose::STANDARD.encode(signed_tx_bytes);
    rpc_call(rpc_url, "broadcast_tx_commit", serde_json::json!([encoded]))
}

fn build_and_send(
    rpc_url: &str,
    signer: &near_crypto::Signer,
    receiver: &str,
    actions: Vec<Action>,
) -> anyhow::Result<Value> {
    let signer_account_id = signer.get_account_id();
    let public_key: PublicKey = signer.public_key();

    let nonce = get_access_key_nonce(rpc_url, signer_account_id.as_ref(), &public_key.to_string())?;
    eprintln!("Nonce: {} → {}", nonce, nonce + 1);

    let block_hash_bytes = get_latest_block_hash(rpc_url)?;
    let block_hash = near_primitives::hash::CryptoHash(block_hash_bytes);
    eprintln!("Block hash: {}", block_hash);

    let receiver_id = near_account_id::AccountId::from_str(receiver)
        .map_err(|e| anyhow::anyhow!("Invalid receiver: {}", e))?;

    let tx = Transaction::V0(TransactionV0 {
        signer_id: signer_account_id,
        public_key,
        nonce: nonce + 1,
        receiver_id,
        block_hash,
        actions,
    });

    let (tx_hash, _) = tx.get_hash_and_size();
    let signature = signer.sign(tx_hash.as_ref());
    let signed_tx = SignedTransaction::new(signature, tx);

    let tx_bytes = borsh::to_vec(&signed_tx)?;
    eprintln!("TX size: {} bytes — broadcasting...", tx_bytes.len());

    broadcast_tx(rpc_url, &tx_bytes)
}

fn print_result(result: &Value) {
    println!("{}", serde_json::to_string_pretty(result).unwrap());
    if let Some(status) = result.get("status") {
        if status.get("SuccessValue").is_some() {
            if let Some(val) = status["SuccessValue"].as_str() {
                if !val.is_empty() {
                    if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(val) {
                        if let Ok(s) = std::str::from_utf8(&decoded) {
                            eprintln!("\nReturn value: {}", s);
                        }
                    }
                }
            }
            eprintln!("\n✓ Transaction SUCCESS");
        } else if let Some(failure) = status.get("Failure") {
            eprintln!("\n✗ Transaction FAILED: {}", failure);
        }
    }
}

fn cmd_transfer(args: &std::collections::HashMap<String, String>) -> anyhow::Result<()> {
    let key_file = PathBuf::from(args.get("key-file").ok_or_else(|| anyhow::anyhow!("--key-file required"))?);
    let receiver = args.get("receiver").ok_or_else(|| anyhow::anyhow!("--receiver required"))?;
    let amount_flc: f64 = args.get("amount").ok_or_else(|| anyhow::anyhow!("--amount required"))?.parse()?;
    let rpc_url = args.get("rpc").map(|s| s.as_str()).unwrap_or(DEFAULT_RPC);

    let amount_yocto = NearToken::from_yoctonear((amount_flc * YOCTO_PER_FLC as f64) as u128);
    eprintln!("Transfer {} FLC → {}", amount_flc, receiver);

    let signer = InMemorySigner::from_file(&key_file)?;
    let result = build_and_send(rpc_url, &signer, receiver, vec![
        Action::Transfer(TransferAction { deposit: amount_yocto }),
    ])?;
    print_result(&result);
    Ok(())
}

fn cmd_create_account(args: &std::collections::HashMap<String, String>) -> anyhow::Result<()> {
    let key_file     = PathBuf::from(args.get("key-file").ok_or_else(|| anyhow::anyhow!("--key-file required"))?);
    let new_account  = args.get("new-account").ok_or_else(|| anyhow::anyhow!("--new-account required"))?;
    let new_pub_key  = args.get("new-public-key").ok_or_else(|| anyhow::anyhow!("--new-public-key required"))?;
    let balance_flc: f64 = args.get("initial-balance").ok_or_else(|| anyhow::anyhow!("--initial-balance required"))?.parse()?;
    let rpc_url      = args.get("rpc").map(|s| s.as_str()).unwrap_or(DEFAULT_RPC);

    let amount_yocto = NearToken::from_yoctonear((balance_flc * YOCTO_PER_FLC as f64) as u128);
    let new_pk = PublicKey::from_str(new_pub_key)
        .map_err(|e| anyhow::anyhow!("Invalid public key: {}", e))?;

    eprintln!("CreateAccount {} with {} FLC, key {}", new_account, balance_flc, new_pub_key);

    let signer = InMemorySigner::from_file(&key_file)?;
    let result = build_and_send(rpc_url, &signer, new_account, vec![
        Action::CreateAccount(CreateAccountAction {}),
        Action::AddKey(Box::new(AddKeyAction {
            public_key: new_pk,
            access_key: AccessKey { nonce: 0, permission: AccessKeyPermission::FullAccess },
        })),
        Action::Transfer(TransferAction { deposit: amount_yocto }),
    ])?;
    print_result(&result);
    Ok(())
}

fn cmd_add_key(args: &std::collections::HashMap<String, String>) -> anyhow::Result<()> {
    let key_file    = PathBuf::from(args.get("key-file").ok_or_else(|| anyhow::anyhow!("--key-file required"))?);
    let new_pub_key = args.get("new-public-key").ok_or_else(|| anyhow::anyhow!("--new-public-key required"))?;
    let rpc_url     = args.get("rpc").map(|s| s.as_str()).unwrap_or(DEFAULT_RPC);

    let new_pk = PublicKey::from_str(new_pub_key)
        .map_err(|e| anyhow::anyhow!("Invalid public key: {}", e))?;

    eprintln!("AddKey {} (FullAccess)", new_pub_key);

    let signer = InMemorySigner::from_file(&key_file)?;
    let signer_id = signer.get_account_id().to_string();
    let result = build_and_send(rpc_url, &signer, &signer_id, vec![
        Action::AddKey(Box::new(AddKeyAction {
            public_key: new_pk,
            access_key: AccessKey { nonce: 0, permission: AccessKeyPermission::FullAccess },
        })),
    ])?;
    print_result(&result);
    Ok(())
}

fn cmd_delete_key(args: &std::collections::HashMap<String, String>) -> anyhow::Result<()> {
    let key_file       = PathBuf::from(args.get("key-file").ok_or_else(|| anyhow::anyhow!("--key-file required"))?);
    let del_pub_key    = args.get("delete-public-key").ok_or_else(|| anyhow::anyhow!("--delete-public-key required"))?;
    let rpc_url        = args.get("rpc").map(|s| s.as_str()).unwrap_or(DEFAULT_RPC);

    let del_pk = PublicKey::from_str(del_pub_key)
        .map_err(|e| anyhow::anyhow!("Invalid public key: {}", e))?;

    eprintln!("DeleteKey {}", del_pub_key);

    let signer = InMemorySigner::from_file(&key_file)?;
    let signer_id = signer.get_account_id().to_string();
    let result = build_and_send(rpc_url, &signer, &signer_id, vec![
        Action::DeleteKey(Box::new(DeleteKeyAction { public_key: del_pk })),
    ])?;
    print_result(&result);
    Ok(())
}

fn cmd_deploy(args: &std::collections::HashMap<String, String>) -> anyhow::Result<()> {
    let key_file = PathBuf::from(args.get("key-file").ok_or_else(|| anyhow::anyhow!("--key-file required"))?);
    let receiver = args.get("receiver").ok_or_else(|| anyhow::anyhow!("--receiver required"))?;
    let wasm_path = args.get("wasm").ok_or_else(|| anyhow::anyhow!("--wasm required"))?;
    let rpc_url = args.get("rpc").map(|s| s.as_str()).unwrap_or(DEFAULT_RPC);

    let code = std::fs::read(wasm_path)?;
    eprintln!("Deploy {} ({} bytes) → {}", wasm_path, code.len(), receiver);

    let mut actions = vec![Action::DeployContract(DeployContractAction { code })];

    // Optional init call
    if let Some(init_method) = args.get("init-method") {
        let init_args = args.get("init-args").map(|s| s.as_bytes().to_vec()).unwrap_or_default();
        let deposit_yocto = args.get("init-deposit")
            .and_then(|d| d.parse::<f64>().ok())
            .map(|f| NearToken::from_yoctonear((f * YOCTO_PER_FLC as f64) as u128))
            .unwrap_or(NearToken::from_yoctonear(0));
        eprintln!("  + init call: {}({})", init_method, args.get("init-args").map(|s| s.as_str()).unwrap_or(""));
        actions.push(Action::FunctionCall(Box::new(FunctionCallAction {
            method_name: init_method.clone(),
            args: init_args,
            gas: default_gas(),
            deposit: deposit_yocto,
        })));
    }

    let signer = InMemorySigner::from_file(&key_file)?;
    let result = build_and_send(rpc_url, &signer, receiver, actions)?;
    print_result(&result);
    Ok(())
}

fn cmd_call(args: &std::collections::HashMap<String, String>) -> anyhow::Result<()> {
    let key_file = PathBuf::from(args.get("key-file").ok_or_else(|| anyhow::anyhow!("--key-file required"))?);
    let receiver = args.get("receiver").ok_or_else(|| anyhow::anyhow!("--receiver required"))?;
    let method = args.get("method").ok_or_else(|| anyhow::anyhow!("--method required"))?;
    let call_args = args.get("args").map(|s| s.as_bytes().to_vec()).unwrap_or_default();
    let rpc_url = args.get("rpc").map(|s| s.as_str()).unwrap_or(DEFAULT_RPC);
    // --deposit-yocto: exact yoctoFLC u128 string (avoids f64 precision loss)
    // --deposit: FLC amount as f64 (legacy)
    let deposit_yocto = if let Some(yocto_str) = args.get("deposit-yocto") {
        let yocto_u128: u128 = yocto_str.parse()
            .map_err(|_| anyhow::anyhow!("--deposit-yocto must be a u128 integer string"))?;
        NearToken::from_yoctonear(yocto_u128)
    } else {
        args.get("deposit")
            .and_then(|d| d.parse::<f64>().ok())
            .map(|f| NearToken::from_yoctonear((f * YOCTO_PER_FLC as f64) as u128))
            .unwrap_or(NearToken::from_yoctonear(0))
    };
    let gas: Gas = args.get("gas").and_then(|g| g.parse::<u64>().ok().map(Gas::from_teragas)).unwrap_or_else(default_gas);

    eprintln!("Call {}.{}({}) deposit={}", receiver, method, args.get("args").map(|s| s.as_str()).unwrap_or(""), deposit_yocto);

    let signer = InMemorySigner::from_file(&key_file)?;
    let result = build_and_send(rpc_url, &signer, receiver, vec![
        Action::FunctionCall(Box::new(FunctionCallAction {
            method_name: method.clone(),
            args: call_args,
            gas,
            deposit: deposit_yocto,
        })),
    ])?;
    print_result(&result);
    Ok(())
}

fn cmd_stake(args: &std::collections::HashMap<String, String>) -> anyhow::Result<()> {
    let key_file = PathBuf::from(args.get("key-file").ok_or_else(|| anyhow::anyhow!("--key-file required"))?);
    let amount_flc: f64 = args.get("amount").ok_or_else(|| anyhow::anyhow!("--amount required"))?.parse()?;
    let rpc_url = args.get("rpc").map(|s| s.as_str()).unwrap_or(DEFAULT_RPC);

    let signer = InMemorySigner::from_file(&key_file)?;
    let public_key = signer.public_key();
    let amount_yocto = NearToken::from_yoctonear((amount_flc * YOCTO_PER_FLC as f64) as u128);
    let signer_id = signer.get_account_id().to_string();

    eprintln!("Stake {} FLC from {} with key {}", amount_flc, signer_id, public_key);

    let result = build_and_send(rpc_url, &signer, &signer_id.clone(), vec![
        Action::Stake(Box::new(StakeAction { stake: amount_yocto, public_key })),
    ])?;
    print_result(&result);
    Ok(())
}

fn cmd_view(args: &std::collections::HashMap<String, String>) -> anyhow::Result<()> {
    let account_id = args.get("account").ok_or_else(|| anyhow::anyhow!("--account required"))?;
    let rpc_url = args.get("rpc").map(|s| s.as_str()).unwrap_or(DEFAULT_RPC);

    let result = rpc_call(rpc_url, "query", serde_json::json!({
        "request_type": "view_account",
        "finality": "final",
        "account_id": account_id
    }))?;

    let amount = result["amount"].as_str().unwrap_or("0");
    let locked = result["locked"].as_str().unwrap_or("0");
    let yocto: u128 = amount.parse().unwrap_or(0);
    let locked_yocto: u128 = locked.parse().unwrap_or(0);
    let flc = yocto / YOCTO_PER_FLC;
    let locked_flc = locked_yocto / YOCTO_PER_FLC;

    println!("Account:  {}", account_id);
    println!("Balance:  {} FLC  ({} yocto)", flc, amount);
    println!("Staked:   {} FLC  ({} yocto)", locked_flc, locked);
    println!("Code hash: {}", result["code_hash"].as_str().unwrap_or("none"));

    // Also show validators if staked
    let validators = rpc_call(rpc_url, "validators", serde_json::json!([null]))?;
    if let Some(current) = validators["current_validators"].as_array() {
        for v in current {
            if v["account_id"].as_str() == Some(account_id) {
                println!("\n✓ ACTIVE VALIDATOR");
                println!("  Stake: {} FLC", v["stake"].as_str().unwrap_or("?").parse::<u128>().unwrap_or(0) / YOCTO_PER_FLC);
                println!("  Shards: {:?}", v["shards"]);
            }
        }
    }

    Ok(())
}

fn cmd_view_call(args: &std::collections::HashMap<String, String>) -> anyhow::Result<()> {
    let receiver = args.get("receiver").ok_or_else(|| anyhow::anyhow!("--receiver required"))?;
    let method = args.get("method").ok_or_else(|| anyhow::anyhow!("--method required"))?;
    let call_args = args.get("args").map(|s| {
        base64::engine::general_purpose::STANDARD.encode(s)
    }).unwrap_or_default();
    let rpc_url = args.get("rpc").map(|s| s.as_str()).unwrap_or(DEFAULT_RPC);

    let result = rpc_call(rpc_url, "query", serde_json::json!({
        "request_type": "call_function",
        "finality": "final",
        "account_id": receiver,
        "method_name": method,
        "args_base64": call_args
    }))?;

    if let Some(result_b64) = result["result"].as_array() {
        let bytes: Vec<u8> = result_b64.iter()
            .filter_map(|v| v.as_u64().map(|n| n as u8))
            .collect();
        if let Ok(s) = std::str::from_utf8(&bytes) {
            println!("{}", s);
        } else {
            println!("{:?}", bytes);
        }
    } else {
        println!("{}", serde_json::to_string_pretty(&result)?);
    }
    Ok(())
}


fn cmd_deploy_global(args: &std::collections::HashMap<String, String>) -> anyhow::Result<()> {
    let key_file = PathBuf::from(args.get("key-file").ok_or_else(|| anyhow::anyhow!("--key-file required"))?);
    let wasm_path = args.get("wasm").ok_or_else(|| anyhow::anyhow!("--wasm required"))?;
    let rpc_url = args.get("rpc").map(|s| s.as_str()).unwrap_or(DEFAULT_RPC);
    // --mode: "code-hash" (default, immutable) or "account-id" (mutable, updatable by owner)
    let deploy_mode = match args.get("mode").map(|s| s.as_str()) {
        Some("account-id") => near_primitives::action::GlobalContractDeployMode::AccountId,
        _ => near_primitives::action::GlobalContractDeployMode::CodeHash,
    };

    let code = std::fs::read(wasm_path)?;
    let code_hash = near_primitives::hash::hash(&code);
    eprintln!("DeployGlobalContract: {} ({} bytes)", wasm_path, code.len());
    eprintln!("Code hash (sha256): {}", code_hash);
    eprintln!("Deploy mode: {:?}", deploy_mode);

    let signer = InMemorySigner::from_file(&key_file)?;
    let signer_id = signer.get_account_id().to_string();

    let result = build_and_send(rpc_url, &signer, &signer_id, vec![
        Action::DeployGlobalContract(near_primitives::action::DeployGlobalContractAction {
            code: code.into(),
            deploy_mode,
        }),
    ])?;
    print_result(&result);
    Ok(())
}

fn cmd_use_global(args: &std::collections::HashMap<String, String>) -> anyhow::Result<()> {
    let key_file  = PathBuf::from(args.get("key-file").ok_or_else(|| anyhow::anyhow!("--key-file required"))?);
    let rpc_url   = args.get("rpc").map(|s| s.as_str()).unwrap_or(DEFAULT_RPC);

    let identifier = if let Some(code_hash_str) = args.get("code-hash") {
        let hash_bytes = bs58::decode(code_hash_str)
            .into_vec()
            .map_err(|e| anyhow::anyhow!("Invalid code-hash: {}", e))?;
        let hash_arr: [u8; 32] = hash_bytes.try_into()
            .map_err(|_| anyhow::anyhow!("code-hash must decode to 32 bytes"))?;
        near_primitives::action::GlobalContractIdentifier::CodeHash(
            near_primitives::hash::CryptoHash(hash_arr)
        )
    } else if let Some(account_id_str) = args.get("account-id") {
        let account_id = near_account_id::AccountId::from_str(account_id_str)
            .map_err(|e| anyhow::anyhow!("Invalid account-id: {}", e))?;
        near_primitives::action::GlobalContractIdentifier::AccountId(account_id)
    } else {
        anyhow::bail!("--code-hash <base58> or --account-id <id> required");
    };

    eprintln!("UseGlobalContract identifier={:?}", identifier);

    let signer = InMemorySigner::from_file(&key_file)?;
    let signer_id = signer.get_account_id().to_string();

    let result = build_and_send(rpc_url, &signer, &signer_id, vec![
        Action::UseGlobalContract(Box::new(near_primitives::action::UseGlobalContractAction {
            contract_identifier: identifier,
        })),
    ])?;
    print_result(&result);
    Ok(())
}

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: fl-send-tx <command> [options]");
        eprintln!("Commands: transfer, deploy, call, view-call, stake, view");
        eprintln!("Options: --key-file, --receiver, --amount, --wasm, --method, --args,");
        eprintln!("         --init-method, --init-args, --deposit, --gas, --account, --rpc");
        std::process::exit(1);
    }

    let command = args[1].clone();
    let mut opts: std::collections::HashMap<String, String> = std::collections::HashMap::new();

    let mut i = 2;
    while i < args.len() {
        if let Some(key) = args[i].strip_prefix("--") {
            if i + 1 < args.len() && !args[i + 1].starts_with("--") {
                opts.insert(key.to_string(), args[i + 1].clone());
                i += 2;
            } else {
                opts.insert(key.to_string(), "true".to_string());
                i += 1;
            }
        } else {
            i += 1;
        }
    }

    match command.as_str() {
        "transfer"       => cmd_transfer(&opts),
        "create-account" => cmd_create_account(&opts),
        "add-key"        => cmd_add_key(&opts),
        "delete-key"     => cmd_delete_key(&opts),
        "deploy"         => cmd_deploy(&opts),
        "call"     => cmd_call(&opts),
        "view-call" => cmd_view_call(&opts),
        "stake"    => cmd_stake(&opts),
        "view"     => cmd_view(&opts),
        "deploy-global" => cmd_deploy_global(&opts),
        "use-global"    => cmd_use_global(&opts),
        _ => {
            eprintln!("Unknown command: {}. Use: transfer, create-account, add-key, delete-key, deploy, call, view-call, stake, view", command);
            std::process::exit(1);
        }
    }
}
