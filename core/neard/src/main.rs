//! # neard — Final Layer Node Daemon
//!
//! This is the main entry point for the Final Layer blockchain node.
//! Final Layer is a quantum-resistant fork of NEAR Protocol.
//!
//! ## Version
//!
//! Version: 1.0.0-final-layer+pqc-enabled
//!
//! ## Cryptography
//!
//! All classical cryptography (Ed25519, secp256k1) has been replaced with
//! NIST-standardized post-quantum algorithms:
//!
//! | Algorithm           | Standard   | Use Case                  |
//! |---------------------|------------|---------------------------|
//! | ML-DSA Dilithium3   | FIPS 204   | Validator signing         |
//! | FN-DSA Falcon-512   | FIPS 206   | User wallet signing       |
//! | SLH-DSA SPHINCS+    | FIPS 205   | Governance keys           |
//! | ML-KEM-768 Kyber    | FIPS 203   | P2P key encapsulation     |
//! | AES-256-GCM         | FIPS 197   | P2P session encryption    |
//!
//! ## Usage
//!
//! ```shell
//! # Initialize node data directory
//! neard init --home ~/.fl-node
//!
//! # Run the node
//! neard run --home ~/.fl-node
//!
//! # Print version and build info
//! neard --version
//! ```

/// Embedded version string. The build metadata "+pqc-enabled" is appended
/// to signal to peers that this node uses the PQC protocol fork.
const VERSION: &str = "1.0.0-final-layer+pqc-enabled";

/// Chain ID this binary is built for.
const CHAIN_ID: &str = near_chain_configs::genesis_config::CHAIN_ID;

fn main() {
    let args: Vec<String> = std::env::args().collect();

    // Handle --version / -V
    if args.iter().any(|a| a == "--version" || a == "-V") {
        print_version();
        return;
    }

    // Handle --help / -h
    if args.iter().any(|a| a == "--help" || a == "-h") || args.len() < 2 {
        print_help();
        return;
    }

    match args[1].as_str() {
        "init" => cmd_init(&args[2..]),
        "run"  => cmd_run(&args[2..]),
        "info" => cmd_info(),
        other  => {
            eprintln!("neard: unknown command '{}'. Run 'neard --help' for usage.", other);
            std::process::exit(1);
        }
    }
}

fn print_version() {
    println!("neard {}", VERSION);
    println!("chain: {}", CHAIN_ID);
    println!("crypto: ML-DSA (FIPS 204) + FN-DSA (FIPS 206) + SLH-DSA (FIPS 205) + ML-KEM (FIPS 203)");
    println!("build: pqc-enabled");
}

fn print_help() {
    println!("neard {} — Final Layer Node Daemon", VERSION);
    println!();
    println!("USAGE:");
    println!("    neard <COMMAND> [OPTIONS]");
    println!();
    println!("COMMANDS:");
    println!("    init    Initialize the node data directory");
    println!("    run     Start the node");
    println!("    info    Print node and chain info");
    println!();
    println!("OPTIONS:");
    println!("    --home <DIR>     Node data directory [default: ~/.fl-node]");
    println!("    --version, -V    Print version information");
    println!("    --help, -h       Print this help message");
    println!();
    println!("ENVIRONMENT:");
    println!("    NEAR_HOME        Overrides --home default");
    println!();
    println!("CHAIN:   {}", CHAIN_ID);
    println!("CRYPTO:  Post-quantum (NIST FIPS 203/204/205/206)");
}

fn cmd_init(args: &[String]) {
    let home_dir = parse_home(args).unwrap_or_else(default_home_dir);
    println!("Initializing Final Layer node at: {}", home_dir);

    // Create home directory
    std::fs::create_dir_all(&home_dir)
        .unwrap_or_else(|e| panic!("Failed to create home dir {}: {}", home_dir, e));

    // Copy genesis.json and config.json if they don't already exist
    let config_src  = find_config_file("config.json");
    let genesis_src = find_config_file("genesis.json");

    let config_dst  = format!("{}/config.json",  home_dir);
    let genesis_dst = format!("{}/genesis.json", home_dir);

    if let Some(src) = config_src {
        if !std::path::Path::new(&config_dst).exists() {
            std::fs::copy(&src, &config_dst)
                .unwrap_or_else(|e| panic!("Failed to copy config.json: {}", e));
            println!("  Copied config.json");
        } else {
            println!("  config.json already exists, skipping.");
        }
    } else {
        eprintln!("  Warning: config.json not found. Copy it manually to {}", config_dst);
    }

    if let Some(src) = genesis_src {
        if !std::path::Path::new(&genesis_dst).exists() {
            std::fs::copy(&src, &genesis_dst)
                .unwrap_or_else(|e| panic!("Failed to copy genesis.json: {}", e));
            println!("  Copied genesis.json");
        } else {
            println!("  genesis.json already exists, skipping.");
        }
    } else {
        eprintln!("  Warning: genesis.json not found. Copy it manually to {}", genesis_dst);
    }

    // Generate a node_key.json using ML-DSA (validator key type)
    let node_key_path = format!("{}/node_key.json", home_dir);
    if !std::path::Path::new(&node_key_path).exists() {
        generate_node_key(&node_key_path);
        println!("  Generated node_key.json (ML-DSA Dilithium3)");
    } else {
        println!("  node_key.json already exists, skipping.");
    }

    println!();
    println!("Final Layer node initialized.");
    println!("Run 'neard run --home {}' to start the node.", home_dir);
}

fn cmd_run(args: &[String]) {
    let home_dir = parse_home(args).unwrap_or_else(default_home_dir);
    println!("Starting Final Layer node from: {}", home_dir);
    println!("Chain:   {}", CHAIN_ID);
    println!("Version: {}", VERSION);
    println!();

    // Validate required files exist
    let required = ["config.json", "genesis.json", "node_key.json"];
    let mut missing = false;
    for f in &required {
        let path = format!("{}/{}", home_dir, f);
        if !std::path::Path::new(&path).exists() {
            eprintln!("  Missing required file: {}", path);
            missing = true;
        }
    }

    if missing {
        eprintln!();
        eprintln!("Run 'neard init --home {}' to initialize the node first.", home_dir);
        std::process::exit(1);
    }

    // Load and validate genesis config
    let genesis_path = format!("{}/genesis.json", home_dir);
    let genesis_json = std::fs::read_to_string(&genesis_path)
        .unwrap_or_else(|e| panic!("Failed to read genesis.json: {}", e));
    let genesis: serde_json::Value = serde_json::from_str(&genesis_json)
        .unwrap_or_else(|e| panic!("Failed to parse genesis.json: {}", e));

    let chain_id = genesis.get("chain_id")
        .and_then(|v| v.as_str())
        .unwrap_or("<unknown>");

    if chain_id != CHAIN_ID {
        eprintln!("Error: genesis.json chain_id '{}' does not match expected '{}'",
                  chain_id, CHAIN_ID);
        std::process::exit(1);
    }

    println!("Genesis: chain_id={}", chain_id);
    println!("Status: Node running (this is a stub — full node implementation pending).");
    println!();
    println!("Final Layer node started successfully.");
    println!("P2P port:  24567");
    println!("RPC port:  3030");
}

fn cmd_info() {
    println!("=== Final Layer Node Info ===");
    println!();
    println!("Version:          {}", VERSION);
    println!("Chain ID:         {}", CHAIN_ID);
    println!("Protocol version: {}", near_chain_configs::genesis_config::PROTOCOL_VERSION);
    println!("Block time:       ~1.5 seconds");
    println!("Epoch length:     {} blocks (~12 hours)", near_chain_configs::genesis_config::EPOCH_LENGTH);
    println!("Active shards:    {}", near_chain_configs::genesis_config::NUM_SHARDS);
    println!("Block producers:  {} seats", near_chain_configs::genesis_config::NUM_BLOCK_PRODUCER_SEATS);
    println!("Chunk producers:  {} seats", near_chain_configs::genesis_config::NUM_CHUNK_PRODUCER_SEATS);
    println!();
    println!("=== Cryptography ===");
    println!("User wallets:     FN-DSA Falcon-512       (NIST FIPS 206)");
    println!("Validators:       ML-DSA Dilithium3        (NIST FIPS 204)");
    println!("Governance:       SLH-DSA SPHINCS+         (NIST FIPS 205)");
    println!("P2P encryption:   ML-KEM-768 + AES-256-GCM (NIST FIPS 203)");
    println!("Randomness:       RANDAO commit-reveal      (post-quantum safe)");
    println!();
    println!("=== Network ===");
    println!("P2P port:         24567");
    println!("RPC port:         3030");
    println!("TLD:              .fl");
    println!("Native token:     NEAR (yoctoNEAR = 10^-24 NEAR)");
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn parse_home(args: &[String]) -> Option<String> {
    // Look for --home <dir> in args
    for i in 0..args.len() {
        if args[i] == "--home" || args[i] == "-H" {
            return args.get(i + 1).cloned();
        }
        if let Some(dir) = args[i].strip_prefix("--home=") {
            return Some(dir.to_string());
        }
    }
    // Check NEAR_HOME environment variable
    std::env::var("NEAR_HOME").ok()
}

fn default_home_dir() -> String {
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .unwrap_or_else(|_| ".".to_string());
    format!("{}/.fl-node", home)
}

fn find_config_file(filename: &str) -> Option<String> {
    // Search common locations for the config files
    let candidates = [
        format!("../../config/{}", filename),          // from core/neard/
        format!("../../../config/{}", filename),       // from deeper nesting
        format!("config/{}", filename),                // from project root
        format!("/etc/final-layer/{}", filename),      // system install
    ];
    for candidate in &candidates {
        if std::path::Path::new(candidate).exists() {
            return Some(candidate.clone());
        }
    }
    None
}

fn generate_node_key(path: &str) {
    // Generate a fresh ML-DSA keypair for the node's network identity.
    // This key is used for P2P authentication (in conjunction with ML-KEM for
    // the actual session encryption).
    use near_account_id::AccountId;
    use near_crypto::{InMemorySigner, KeyType};
    use std::str::FromStr;

    let account_id = AccountId::from_str("node.fl")
        .expect("'node.fl' is a valid account ID");
    let signer = InMemorySigner::from_random(account_id, KeyType::MlDsa);
    signer.write_to_file(std::path::Path::new(path))
        .unwrap_or_else(|e| panic!("Failed to write node_key.json: {}", e));
}
