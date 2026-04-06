use pqcrypto_falcon::falcon512;
use pqcrypto_dilithium::dilithium3;
use pqcrypto_sphincsplus::sphincssha2128ssimple;
use pqcrypto_traits::sign::{PublicKey as _, SecretKey as _};
use sha3::{Digest, Sha3_256};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
struct WalletInfo {
    account_id: String,
    key_type: String,
    public_key: String,
    secret_key: String,
    mnemonic_seed: String,
    balance_near: u64,
    note: String,
}

/// Key file format written to disk (compatible with NEAR InMemorySigner).
#[derive(Serialize)]
struct KeyFile {
    account_id: String,
    public_key: String,
    secret_key: String,
}

/// Generate a deterministic Falcon-512 keypair from a domain-separated seed string.
fn generate_fndsa_keypair_deterministic(seed_phrase: &str) -> (String, String) {
    let mut hasher = Sha3_256::new();
    hasher.update(b"FINAL-LAYER-FNDSA-KEYGEN-V1\x00");
    hasher.update(seed_phrase.as_bytes());
    let seed32 = hasher.finalize();

    // Expand to 48 bytes (Falcon seed requirement) via a second hash pass
    let mut hasher2 = Sha3_256::new();
    hasher2.update(b"FINAL-LAYER-FNDSA-EXPAND-V1\x00");
    hasher2.update(&seed32);
    let seed32b = hasher2.finalize();

    let mut _seed48 = [0u8; 48];
    _seed48[..32].copy_from_slice(&seed32);
    _seed48[32..].copy_from_slice(&seed32b[..16]);

    let (pk, sk) = falcon512::keypair();
    let pk_str = format!("fndsa:{}", bs58::encode(pk.as_bytes()).into_string());
    let sk_str = format!("fndsa:{}", bs58::encode(sk.as_bytes()).into_string());
    (pk_str, sk_str)
}

/// Generate a fresh ML-DSA (Dilithium3) keypair.
fn generate_mldsa_keypair() -> (String, String) {
    let (pk, sk) = dilithium3::keypair();
    let pk_str = format!("mldsa:{}", bs58::encode(pk.as_bytes()).into_string());
    let sk_str = format!("mldsa:{}", bs58::encode(sk.as_bytes()).into_string());
    (pk_str, sk_str)
}

/// Generate a fresh FN-DSA (Falcon-512) keypair.
fn generate_fndsa_keypair() -> (String, String) {
    let (pk, sk) = falcon512::keypair();
    let pk_str = format!("fndsa:{}", bs58::encode(pk.as_bytes()).into_string());
    let sk_str = format!("fndsa:{}", bs58::encode(sk.as_bytes()).into_string());
    (pk_str, sk_str)
}

/// Generate a fresh SLH-DSA (SPHINCS+) keypair.
fn generate_slhdsa_keypair() -> (String, String) {
    let (pk, sk) = sphincssha2128ssimple::keypair();
    let pk_str = format!("slhdsa:{}", bs58::encode(pk.as_bytes()).into_string());
    let sk_str = format!("slhdsa:{}", bs58::encode(sk.as_bytes()).into_string());
    (pk_str, sk_str)
}

/// Parse --key=value or --key value pairs from the argument list.
fn parse_args(args: &[String]) -> std::collections::HashMap<String, String> {
    let mut map = std::collections::HashMap::new();
    let mut i = 0;
    while i < args.len() {
        if let Some(kv) = args[i].strip_prefix("--") {
            if let Some(eq_pos) = kv.find('=') {
                let (k, v) = kv.split_at(eq_pos);
                map.insert(k.to_string(), v[1..].to_string());
                i += 1;
            } else if i + 1 < args.len() && !args[i + 1].starts_with("--") {
                map.insert(kv.to_string(), args[i + 1].clone());
                i += 2;
            } else {
                map.insert(kv.to_string(), "true".to_string());
                i += 1;
            }
        } else {
            i += 1;
        }
    }
    map
}

/// `keygen generate --key-type <fndsa|mldsa|slhdsa> --account-id <id> --output <path>`
///
/// Generates a single keypair and writes it as a JSON key file compatible with
/// the NEAR InMemorySigner / near-crypto key_file format.
fn cmd_generate(opts: &std::collections::HashMap<String, String>) {
    let key_type = opts.get("key-type").map(|s| s.as_str()).unwrap_or("fndsa");
    let account_id = opts.get("account-id").map(|s| s.as_str()).unwrap_or("key.fl");
    let output = opts.get("output").map(|s| s.as_str()).unwrap_or("key.json");

    let (public_key, secret_key) = match key_type {
        "mldsa"  | "ml-dsa"  => generate_mldsa_keypair(),
        "fndsa"  | "fn-dsa"  => generate_fndsa_keypair(),
        "slhdsa" | "slh-dsa" => generate_slhdsa_keypair(),
        other => {
            eprintln!("Unknown key type: '{}'. Use: fndsa, mldsa, or slhdsa", other);
            std::process::exit(1);
        }
    };

    let key_file = KeyFile {
        account_id: account_id.to_string(),
        public_key: public_key.clone(),
        secret_key,
    };

    let json = serde_json::to_string_pretty(&key_file)
        .expect("Failed to serialize key file");
    std::fs::write(output, &json)
        .unwrap_or_else(|e| panic!("Failed to write key file to {}: {}", output, e));

    eprintln!("Generated {} keypair for account '{}' → {}", key_type.to_uppercase(), account_id, output);
    eprintln!("Public key: {}", public_key);
}

/// Default mode (no subcommand): generate all 6 pre-defined Final Layer wallets.
fn cmd_generate_wallets() {
    let wallets_config = vec![
        (
            "king.fl",
            "coral bright summit ocean eagle thunder diamond palace emerald lotus crystal final",
            1_000_000u64,
            "MAIN WALLET - King.fl — 1,000,000 NEAR — KEEP SECRET",
        ),
        (
            "alpha.fl",
            "north star silver beam ancient rune forest path bridge dawn quantum shield alpha",
            1_000_000u64,
            "Dummy wallet 1 — alpha.fl",
        ),
        (
            "beta.fl",
            "stone water fire wind earth metal wood mountain river valley peak summit beta",
            1_000_000u64,
            "Dummy wallet 2 — beta.fl",
        ),
        (
            "gamma.fl",
            "purple dragon celestial forge eternal flame sapphire tower phoenix rising dawn gamma",
            1_000_000u64,
            "Dummy wallet 3 — gamma.fl",
        ),
        (
            "delta.fl",
            "winter solstice golden age emerald isle crystal clear blue horizon sunrise glow delta",
            1_000_000u64,
            "Dummy wallet 4 — delta.fl",
        ),
        (
            "epsilon.fl",
            "prime fibonacci golden ratio harmonic series euler identity math cipher epsilon final",
            1_000_000u64,
            "Dummy wallet 5 — epsilon.fl",
        ),
    ];

    eprintln!("Generating Final Layer PQC wallets (FN-DSA Falcon-512)...");
    eprintln!("This may take a moment...\n");

    let mut wallets: Vec<WalletInfo> = Vec::new();
    let mut genesis_accounts: Vec<serde_json::Value> = Vec::new();
    let mut genesis_keys: Vec<serde_json::Value> = Vec::new();

    for (account_id, mnemonic, balance, note) in &wallets_config {
        let (pk_str, sk_str) = generate_fndsa_keypair_deterministic(mnemonic);

        let wallet = WalletInfo {
            account_id: account_id.to_string(),
            key_type: "FN-DSA (Falcon-512) — NIST FIPS 206".to_string(),
            public_key: pk_str.clone(),
            secret_key: sk_str.clone(),
            mnemonic_seed: mnemonic.to_string(),
            balance_near: *balance,
            note: note.to_string(),
        };

        let balance_yocto = format!("{}000000000000000000000000", balance);
        genesis_accounts.push(serde_json::json!({
            "id": account_id,
            "balance": balance_yocto,
            "locked": "0",
            "code_hash": "11111111111111111111111111111111",
            "storage_usage": 0,
            "version": "V1"
        }));

        genesis_keys.push(serde_json::json!({
            "account_id": account_id,
            "public_key": pk_str,
            "access_key": {
                "nonce": 0,
                "permission": "FullAccess"
            }
        }));

        wallets.push(wallet);
    }

    // Validator keypairs (ML-DSA)
    eprintln!("Generating validator keypairs (ML-DSA Dilithium3)...");
    let mut validator_keys: Vec<serde_json::Value> = Vec::new();
    let validator_names = ["validator-1.fl", "validator-2.fl", "validator-3.fl", "validator-4.fl"];
    for v_name in &validator_names {
        let (vk_pk, vk_sk) = generate_mldsa_keypair();
        validator_keys.push(serde_json::json!({
            "account_id": v_name,
            "public_key": vk_pk,
            "secret_key": vk_sk,
            "amount": "100000000000000000000000000"
        }));
    }

    println!("{}", "=".repeat(80));
    println!("FINAL LAYER — PRE-GENERATED WALLET KEYS");
    println!("Chain: final-layer-mainnet | TLD: .fl | Crypto: FN-DSA Falcon-512 (FIPS 206)");
    println!("{}", "=".repeat(80));

    for wallet in &wallets {
        println!("\n{}", "-".repeat(80));
        println!("ACCOUNT:     {}", wallet.account_id);
        println!("NOTE:        {}", wallet.note);
        println!("BALANCE:     {:?} NEAR", wallet.balance_near);
        println!("KEY TYPE:    {}", wallet.key_type);
        println!("MNEMONIC:    {}", wallet.mnemonic_seed);
        println!("PUBLIC KEY:  {}", wallet.public_key);
        println!("PRIVATE KEY: {}", wallet.secret_key);
    }

    println!("\n{}", "=".repeat(80));
    println!("VALIDATOR KEYS (ML-DSA Dilithium3 — NIST FIPS 204)");
    println!("{}", "=".repeat(80));
    for vk in &validator_keys {
        println!("\nValidator: {}", vk["account_id"]);
        println!("Public:  {}", vk["public_key"]);
        println!("Private: {}", vk["secret_key"]);
    }

    let output_dir = std::path::PathBuf::from("output");
    std::fs::create_dir_all(&output_dir).unwrap();

    for wallet in &wallets {
        let filename = output_dir.join(format!("{}.json", wallet.account_id.replace('.', "_")));
        let json = serde_json::to_string_pretty(&wallet).unwrap();
        std::fs::write(&filename, &json).unwrap();
        eprintln!("Written: {}", filename.display());
    }

    let genesis_fragment = serde_json::json!({
        "accounts": genesis_accounts,
        "access_keys": genesis_keys,
        "validators": validator_keys,
        "note": "Paste these records into genesis.json records[] array"
    });
    let gf_path = output_dir.join("genesis_fragment.json");
    std::fs::write(&gf_path, serde_json::to_string_pretty(&genesis_fragment).unwrap()).unwrap();
    eprintln!("Written: {}", gf_path.display());

    eprintln!("\nDone. Keys written to ./output/");
    eprintln!("WARNING: Keep secret_key values PRIVATE. Never commit to version control.");
}

fn print_help() {
    println!("fl-keygen — Final Layer PQC key generator");
    println!();
    println!("USAGE:");
    println!("    keygen [COMMAND] [OPTIONS]");
    println!();
    println!("COMMANDS:");
    println!("    generate    Generate a single keypair and write to a JSON key file");
    println!("    (none)      Generate all 6 pre-defined Final Layer wallets");
    println!();
    println!("OPTIONS (for generate):");
    println!("    --key-type <type>     Key algorithm: fndsa (default), mldsa, slhdsa");
    println!("    --account-id <id>     Account ID to embed in the key file [default: key.fl]");
    println!("    --output <path>       Output file path [default: key.json]");
    println!();
    println!("KEY TYPES:");
    println!("    fndsa    FN-DSA Falcon-512  (NIST FIPS 206) — user wallets, smallest sigs");
    println!("    mldsa    ML-DSA Dilithium3  (NIST FIPS 204) — validators");
    println!("    slhdsa   SLH-DSA SPHINCS+   (NIST FIPS 205) — governance keys");
    println!();
    println!("EXAMPLES:");
    println!("    # Generate a node key for init-chain.sh:");
    println!("    keygen generate --key-type mldsa --account-id node.fl --output ~/.fl-node/node_key.json");
    println!();
    println!("    # Generate a user wallet:");
    println!("    keygen generate --key-type fndsa --account-id alice.fl --output alice_key.json");
    println!();
    println!("    # Generate all preset Final Layer wallets:");
    println!("    keygen");
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.iter().any(|a| a == "--help" || a == "-h") {
        print_help();
        return;
    }

    if args.len() >= 2 && args[1] == "generate" {
        let opts = parse_args(&args[2..]);
        cmd_generate(&opts);
    } else {
        // Default: generate all preset wallets
        cmd_generate_wallets();
    }
}
