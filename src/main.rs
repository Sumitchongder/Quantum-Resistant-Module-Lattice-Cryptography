// src/main.rs (FINAL CORRECTED VERSION)

#![warn(rust_2018_idioms)]

use anyhow::{anyhow, Context, Result};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};

use std::{
    fs,
    io::{BufRead, Write},
    net::{TcpListener, TcpStream},
    path::PathBuf,
    thread,
    time::Duration,
};

use tracing::{error, info};
use tracing_subscriber;

// FIX: Corrected chacha20poly1312 to chacha20poly1305
use chacha20poly1305::{
    aead::{Aead, KeyInit, OsRng},
    XChaCha20Poly1305, XNonce,
};
use chacha20poly1305::aead::rand_core::RngCore;

use pqcrypto_kyber::kyber768;
use pqcrypto_dilithium::dilithium2;

use pqcrypto_traits::kem::{Ciphertext as KemCiphertextTrait, PublicKey as KemPublicKeyTrait, SecretKey as KemSecretKeyTrait, SharedSecret as KemSharedSecretTrait};
use pqcrypto_traits::sign::{PublicKey as SignPublicKeyTrait, SecretKey as SignSecretKeyTrait, DetachedSignature as SignDetachedSignatureTrait};

// FIX: Use the trait name 'App' directly from eframe
use eframe::{egui, App};
use rfd::FileDialog;

use serde::{Deserialize, Serialize};
use base64::{engine::general_purpose, Engine as _};
use uuid::Uuid;
use chrono::Utc;

// Imports for User Authentication/Derivation
use argon2::{
    password_hash::{SaltString}, 
    Argon2, PasswordHasher,
};
use rand::thread_rng; 
use hex;

// New Module Import
mod wallet;
use wallet::Wallet;

// FIX: Standard loopback address
const SERVER_ADDR: &str = "127.0.0.1:40000";

// --- PROFESSIONAL STORAGE PATH MODIFICATION ---
fn ensure_storage_dir() -> PathBuf {
    let dir = PathBuf::from("./storage");
    if !dir.exists() {
        let _ = fs::create_dir_all(&dir);
    }
    dir
}
// --- END PROFESSIONAL STORAGE PATH MODIFICATION ---


// ----------------- Utilities -----------------
fn hkdf_derive_key(shared_secret: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, shared_secret);
    let mut okm = [0u8; 32];
    hk.expand(b"pqbank session key", &mut okm)
        .expect("hkdf expand");
    okm
}

// Utility: Hash the user's password using Argon2id
fn hash_password(password: &str) -> Result<String> {
    let mut rng = thread_rng();
    let salt = SaltString::generate(&mut rng);
    let argon2 = Argon2::default(); 
    let password_hash = argon2.hash_password(password.as_bytes(), &salt)
        .map_err(|e| anyhow!("Argon2 hash error: {:?}", e))?
        .to_string();
    Ok(password_hash)
}

// Helper: encrypt bytes with XChaCha20-Poly1305
fn encrypt_bytes(key_bytes: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>> {
    let key = chacha20poly1305::Key::from_slice(key_bytes); 
    let cipher = XChaCha20Poly1305::new(key); 

    let mut nonce_bytes = [0u8; 24];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = XNonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| anyhow!("symmetric encrypt error: {:?}", e))?;

    let mut out = Vec::with_capacity(24 + ciphertext.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

#[allow(dead_code)]
fn decrypt_bytes(key_bytes: &[u8; 32], blob: &[u8]) -> Result<Vec<u8>> {
    if blob.len() < 24 {
        return Err(anyhow!("ciphertext too short"));
    }
    let (nonce_bytes, ct) = blob.split_at(24);
    let key = chacha20poly1305::Key::from_slice(key_bytes); 
    let cipher = XChaCha20Poly1305::new(key); 
    let nonce = XNonce::from_slice(nonce_bytes);

    let pt = cipher
        .decrypt(nonce, ct)
        .map_err(|e| anyhow!("symmetric decrypt error: {:?}", e))?;
    Ok(pt)
}

// ----------------- Server storage / key management -----------------
#[derive(Serialize, Deserialize, Clone)]
struct ServerKeys {
    kyber_pk: Vec<u8>,
    kyber_sk: Vec<u8>,
    dilithium_pk: Vec<u8>,
    dilithium_sk: Vec<u8>,
}

impl ServerKeys {
    fn load_or_create(path: &PathBuf) -> Result<Self> {
        if path.exists() {
            let bytes = fs::read(path).context("read key file")?;
            let s: ServerKeys = serde_json::from_slice(&bytes).context("parse keys")?;
            return Ok(s);
        }

        // generate keys
        let (pk, sk) = kyber768::keypair();
        let (dpk, dsk) = dilithium2::keypair();

        // convert to bytes via trait method (trait is in scope)
        let s = ServerKeys {
            kyber_pk: pk.as_bytes().to_vec(),
            kyber_sk: sk.as_bytes().to_vec(),
            dilithium_pk: dpk.as_bytes().to_vec(),
            dilithium_sk: dsk.as_bytes().to_vec(),
        };
        let j = serde_json::to_vec_pretty(&s)?;
        fs::write(path, j)?;
        Ok(s)
    }
}

// Secure Storage Envelope (for files/transactions)
#[derive(Serialize, Deserialize)]
struct CryptoEnvelope {
    ciphertext: String, 
    signature: String,  
    signer_pubkey: String, 
    meta: serde_json::Value,
}

// Tamper-Proof Audit Log Block
#[derive(Serialize, Deserialize, Clone, Debug)]
struct AuditBlock {
    hash_prev: String,       // Hex hash of the previous block's *content*
    timestamp: String,
    action: String,          // e.g., "TX_SENT", "FILE_UPLOADED"
    user_id: String,
    payload_id: String,      // ID of the transaction/file record
    signature: Option<String>, // Server Dilithium signature over the block content (excluding this field)
}

// Save CryptoEnvelope on server
fn server_store_encrypted_envelope(storage_dir: &PathBuf, envelope: &CryptoEnvelope) -> Result<()> {
    // For simplicity, derive a fixed hash from the username for pathing
    let user_id_hash = Sha256::digest(envelope.meta["sender"].to_string());
    let filename = format!("{}_{}.pqenc", Utc::now().timestamp(), hex::encode(user_id_hash));
    
    let path = storage_dir.join("encrypted").join(&filename);
    let parent = path.parent().context("get parent dir")?;
    if !parent.exists() {
        fs::create_dir_all(parent)?;
    }

    let j = serde_json::to_vec_pretty(envelope)?;
    fs::write(path, j)?;
    Ok(())
}

// Append a new block to the audit log chain (Tamper-Proof)
fn append_audit_log(storage_dir: &PathBuf, keys: &ServerKeys, action: &str, user_id: &str, payload_id: &str) -> Result<()> {
    let audit_dir = storage_dir.join("audit");
    if !audit_dir.exists() {
        fs::create_dir_all(&audit_dir)?;
    }
    let log_path = audit_dir.join("log_chain.json");

    // 1. Get the hash of the previous block
    let hash_prev = if log_path.exists() {
        let content = fs::read_to_string(&log_path)?;
        // Split by newline and take the last non-empty line
        let last_line = content.trim().split('\n').last().context("Audit log empty")?.trim_matches(',');
        let last_block: AuditBlock = serde_json::from_str(last_line)?;
        
        // Block to hash: clone, remove signature, serialize, hash.
        let mut content_to_hash = last_block.clone();
        content_to_hash.signature = None;
        let serialized_content = serde_json::to_string(&content_to_hash)?;
        hex::encode(Sha256::digest(serialized_content))
    } else {
        // First block hash is always all zeros
        hex::encode([0u8; 32])
    };

    // 2. Create the new block structure (without signature)
    let mut new_block = AuditBlock {
        hash_prev,
        timestamp: Utc::now().to_rfc3339(),
        action: action.to_string(),
        user_id: user_id.to_string(),
        payload_id: payload_id.to_string(),
        signature: None,
    };

    // 3. Serialize and sign the block content
    let content_to_sign = serde_json::to_string(&new_block)?;
    let server_sk = dilithium2::SecretKey::from_bytes(&keys.dilithium_sk)
        .map_err(|_| anyhow!("invalid server sk"))?;
    let server_sig = dilithium2::detached_sign(content_to_sign.as_bytes(), &server_sk);
    let server_sig_b64 = general_purpose::STANDARD.encode(server_sig.as_bytes());

    // 4. Add the signature and serialize the final block
    new_block.signature = Some(server_sig_b64);
    let final_block_json = serde_json::to_string(&new_block)?;

    // 5. Append to the log file (JSON Lines format)
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)?;
        
    writeln!(file, "{},", final_block_json)?;
    
    info!("AUDIT: Logged action '{}' for user '{}'", action, user_id);
    Ok(())
}

// ----------------- Server: handle simple protocol -----------------

fn server_worker(storage_dir: PathBuf, keys_path: PathBuf) -> Result<()> {
    // load or create keys
    let keys = ServerKeys::load_or_create(&keys_path).context("loading server keys")?;

    let listener = TcpListener::bind(SERVER_ADDR).context("bind server")?;
    info!("Server listening on {}", SERVER_ADDR);
    for stream in listener.incoming() {
        match stream {
            Ok(s) => {
                let storage_dir = storage_dir.clone();
                let keys = keys.clone();
                // Note: Still using threads for stability before full async migration
                thread::spawn(move || {
                    if let Err(e) = handle_connection(s, storage_dir, keys) {
                        error!("connection handler error: {:?}", e);
                    }
                });
            }
            Err(e) => {
                error!("incoming connection error: {:?}", e);
                thread::sleep(Duration::from_millis(100));
            }
        }
    }
    Ok(())
}

fn handle_connection(stream: TcpStream, storage_dir: PathBuf, keys: ServerKeys) -> Result<()> {
    use std::io::{BufReader, BufWriter};

    let mut reader = BufReader::new(stream.try_clone()?);
    let mut writer = BufWriter::new(stream.try_clone()?);

    let mut line = String::new();
    reader.read_line(&mut line)?;
    let line = line.trim_end().to_string();

    if line == "GETPK" {
        let b64 = general_purpose::STANDARD.encode(&keys.kyber_pk);
        writeln!(writer, "OK:{}", b64)?;
        writer.flush()?;
        return Ok(());
    }

    if line.starts_with("KEM:") {
        let parts: Vec<&str> = line.splitn(4, ':').collect();
        if parts.len() < 4 {
            writeln!(writer, "ERR:bad format")?;
            writer.flush()?;
            return Ok(());
        }
        let ct_b64 = parts[1];
        let sig_b64 = parts[2];
        let payload_b64 = parts[3];
        let ct = general_purpose::STANDARD.decode(ct_b64)?;
        let sig_bytes = general_purpose::STANDARD.decode(sig_b64)?;
        let _payload_bytes = general_purpose::STANDARD.decode(payload_b64)?;

        // KEM Decapsulation
        let sk = kyber768::SecretKey::from_bytes(&keys.kyber_sk)
            .map_err(|_| anyhow!("invalid kyber sk"))?;
        let ct_struct = kyber768::Ciphertext::from_bytes(&ct)
            .map_err(|_| anyhow!("invalid ciphertext"))?;
        let shared = kyber768::decapsulate(&ct_struct, &sk);
        let key_bytes = hkdf_derive_key(shared.as_bytes());

        #[derive(Deserialize)]
        struct ClientPayload {
            id: String,
            client_dilithium_pk_b64: String,
            inner_b64: String, 
        }
        let cp: ClientPayload = serde_json::from_slice(&_payload_bytes)?;
        let client_dilithium_pk_bytes = general_purpose::STANDARD.decode(&cp.client_dilithium_pk_b64)?;
        let inner = general_purpose::STANDARD.decode(&cp.inner_b64)?;

        // Signature Verification (Dilithium)
        let detached_sig = dilithium2::DetachedSignature::from_bytes(&sig_bytes)
            .map_err(|_| anyhow!("invalid detached signature"))?;
        let client_pk = dilithium2::PublicKey::from_bytes(&client_dilithium_pk_bytes)
            .map_err(|_| anyhow!("invalid client public key"))?;

        if dilithium2::verify_detached_signature(&detached_sig, &inner, &client_pk).is_err() {
            writeln!(writer, "ERR:invalid signature")?;
            writer.flush()?;
            return Ok(());
        }

        // --- STORAGE & AUDIT ---
        let inner_json: serde_json::Value = serde_json::from_slice(&inner)?;
        let store_blob = encrypt_bytes(&key_bytes, &inner)?;
        let sender = inner_json.get("sender").map(|s| s.as_str().unwrap_or("unknown")).unwrap_or("unknown");
        let action = if inner_json.get("data_b64").is_some() { "FILE_UPLOADED" } else { "TX_SENT" };

        let envelope = CryptoEnvelope {
            ciphertext: general_purpose::STANDARD.encode(&store_blob),
            signature: sig_b64.to_string(),
            signer_pubkey: cp.client_dilithium_pk_b64.clone(),
            meta: serde_json::json!({
                "id": cp.id,
                "kyber_ciphertext_b64": ct_b64,
                "type": action,
                "sender": sender,
                "timestamp": Utc::now().to_rfc3339(),
            })
        };
        server_store_encrypted_envelope(&storage_dir, &envelope)?;
        
        // CRITICAL: Log the action to the tamper-proof chain
        append_audit_log(&storage_dir, &keys, action, sender, &cp.id)?;
        // --- END STORAGE & AUDIT ---

        // Server Response Signature
        let server_sk = dilithium2::SecretKey::from_bytes(&keys.dilithium_sk)
            .map_err(|_| anyhow!("invalid server sk"))?;
        let confirmation = format!("stored:{}", cp.id);
        let server_sig = dilithium2::detached_sign(confirmation.as_bytes(), &server_sk);
        let server_sig_b64 = general_purpose::STANDARD.encode(server_sig.as_bytes());

        writeln!(writer, "OK:{}:{}", cp.id, server_sig_b64)?;
        writer.flush()?;
        return Ok(());
    }

    writeln!(writer, "ERR:unknown command")?;
    writer.flush()?;
    Ok(())
}

// ----------------- Client GUI and network operations -----------------

#[derive(Debug, PartialEq)]
enum CurrentView {
    Dashboard,
    EncryptedFiles,
    WalletKeys,
    AuditLogs,
}

struct AppState {
    // GUI state
    username: String,
    password: String,
    tx_amount: String,
    tx_receiver: String,
    last_status: String,
    current_view: CurrentView, 
    
    // Dedicated password field for Wallet operations
    wallet_password: String, 
    
    // NEW: Security Cache for the correct Argon2 hash
    // This removes the need to re-hash on every click within the session
    wallet_password_hash_cache: Option<String>,
    
    // Wallet storage
    wallets: Vec<Wallet>,
    new_wallet_name: String,
    decrypted_data: Option<String>, 
    active_wallet_data: Option<wallet::WalletData>, 
    
    // Phase 7: Audit Log fields
    server_dilithium_pk: Option<dilithium2::PublicKey>, // Server's public key for signature verification
    audit_log_status: String,
    audit_log_data: String,
}

impl Default for AppState {
    fn default() -> Self {
        let storage_dir = ensure_storage_dir();
        let keys_path = storage_dir.join("server_keys.json");
        let wallets_path = storage_dir.join("wallets");
        
        let server_keys = ServerKeys::load_or_create(&keys_path).ok();
        
        let server_dilithium_pk = server_keys
            .and_then(|keys| dilithium2::PublicKey::from_bytes(&keys.dilithium_pk).ok());
            
        let wallets = Wallet::load_all(wallets_path).unwrap_or_default();
        
        let initial_username = wallets.first().map(|w| w.name.clone()).unwrap_or_default();

        Self {
            username: initial_username, 
            password: String::new(),
            tx_amount: String::new(),
            tx_receiver: String::new(),
            last_status: "Ready".to_string(),
            current_view: CurrentView::Dashboard, 
            
            wallet_password: String::new(), 
            wallet_password_hash_cache: None, // Initialize cache
            
            wallets, 
            new_wallet_name: String::new(),
            decrypted_data: None,
            active_wallet_data: None,
            
            server_dilithium_pk,
            audit_log_status: "Press 'Verify Chain' to check integrity.".to_string(),
            audit_log_data: String::new(),
        }
    }
}

impl AppState {
    // Helper function to get the correct password hash for wallet operations
    fn get_wallet_hash_or_derive(&mut self) -> Result<String> {
        // 1. Check if hash is cached
        if let Some(cached_hash) = &self.wallet_password_hash_cache {
            return Ok(cached_hash.clone());
        }

        // 2. If not cached, check if password input is empty
        if self.wallet_password.is_empty() {
            return Err(anyhow!("Wallet password field is empty. Please enter your password."));
        }

        // 3. If present, derive the hash (this takes time)
        match hash_password(&self.wallet_password) {
            Ok(hash) => {
                // 4. Cache the hash for session use and clear the sensitive string
                self.wallet_password_hash_cache = Some(hash.clone());
                // SECURITY NOTE: We DO NOT clear the wallet_password string itself, 
                // allowing the user to make small edits if the first attempt fails.
                
                return Ok(hash);
            }
            Err(e) => {
                // Hashing failed (e.g., system error)
                Err(e)
            }
        }
    }
    
    // perform the KEM + sign + send flow
    fn perform_send(&mut self, tx_json: &str, id: &str) -> Result<String> {
        if self.username.is_empty() {
            return Err(anyhow!("Username field must be filled for demo metadata."));
        }
        
        let active_wallet = self.active_wallet_data
            .as_ref()
            .context("No active decrypted wallet found. Please decrypt a wallet first.")?;

        let client_pk_b64 = &active_wallet.dilithium_pk_b64;
        let client_sk_b64 = &active_wallet.dilithium_sk_b64;

        let client_sk_bytes = general_purpose::STANDARD.decode(client_sk_b64)?;

        // --- Network and Crypto Setup ---
        let mut stream = TcpStream::connect(SERVER_ADDR).context("connect server")?;
        stream.write_all(b"GETPK\n").context("request pk")?;
        stream.flush()?;
        let mut buf = String::new();
        std::io::BufReader::new(stream.try_clone()?).read_line(&mut buf)?;
        if !buf.starts_with("OK:") {
            anyhow::bail!("server returned error for GETPK: {}", buf);
        }
        let server_pk_b64 = buf.trim_start_matches("OK:").trim();
        let server_pk_bytes = general_purpose::STANDARD.decode(server_pk_b64)?;

        // Encapsulate (Kyber)
        let pk_struct = kyber768::PublicKey::from_bytes(&server_pk_bytes)
            .map_err(|_| anyhow!("invalid server kyber pk"))?;
        let (_shared, ct) = kyber768::encapsulate(&pk_struct);

        // Sign (Dilithium) - using the wallet's SK
        let sk_obj = dilithium2::SecretKey::from_bytes(&client_sk_bytes)
            .map_err(|_| anyhow!("invalid client secret key"))?;
        
        let sig_detached = dilithium2::detached_sign(tx_json.as_bytes(), &sk_obj);
        let sig_bytes = sig_detached.as_bytes();

        // Construct Encapsulation Payload
        #[derive(Serialize)]
        struct ClientPayload<'a> {
            id: &'a str,
            client_dilithium_pk_b64: String, // Public key to be sent with the signature for server verification
            inner_b64: String,
        }
        let cp = ClientPayload {
            id,
            client_dilithium_pk_b64: client_pk_b64.clone(),
            inner_b64: general_purpose::STANDARD.encode(tx_json.as_bytes()),
        };
        let cp_bytes = serde_json::to_vec(&cp)?;
        let cp_b64 = general_purpose::STANDARD.encode(&cp_bytes);
        let ct_b64 = general_purpose::STANDARD.encode(ct.as_bytes());
        let sig_b64 = general_purpose::STANDARD.encode(sig_bytes);

        // send line: KEM:<ct_b64>:<sig_b64>:<payload_b64>\n
        let mut s2 = TcpStream::connect(SERVER_ADDR)?;
        let line = format!("KEM:{}:{}:{}\n", ct_b64, sig_b64, cp_b64);
        s2.write_all(line.as_bytes())?;
        s2.flush()?;

        // read server response
        let mut resp = String::new();
        std::io::BufReader::new(s2).read_line(&mut resp)?;
        Ok(resp.trim().to_string())
    }
    
    // Phase 7: Core verification logic (Fixed unused variable warnings)
    fn verify_audit_log(&mut self) {
        self.audit_log_data.clear();
        let log_path = ensure_storage_dir().join("audit").join("log_chain.json");

        let server_pk = match &self.server_dilithium_pk {
            Some(pk) => pk,
            None => {
                self.audit_log_status = "❌ Verification Failed: Server Dilithium Public Key not loaded.".to_string();
                return;
            }
        };

        if !log_path.exists() {
            self.audit_log_status = "✅ Audit log file not found. No logs yet, but chain is conceptually sound.".to_string();
            return;
        }

        let content = match fs::read_to_string(&log_path) {
            Ok(c) => c,
            Err(e) => {
                self.audit_log_status = format!("❌ Verification Failed: Could not read log file: {:?}", e);
                return;
            }
        };

        let lines = content.trim().split('\n'); 
        let mut prev_block_hash = hex::encode([0u8; 32]);
        let mut overall_integrity_ok = true;
        let mut display_log = String::new();
        let mut line_num = 0;

        // Iterate through each block in the JSON Lines format
        for line_str in lines.filter(|s| !s.trim().is_empty()) {
            line_num += 1;
            let current_line = line_str.trim_end_matches(',');
            
            let current_block: AuditBlock = match serde_json::from_str(current_line) {
                Ok(b) => b,
                Err(e) => {
                    overall_integrity_ok = false;
                    display_log.push_str(&format!("[{}] ❌ JSON Parse Error: {}\n", line_num, e));
                    break; 
                }
            };
            
            let mut status = egui::RichText::new("✅ OK").color(egui::Color32::GREEN);

            // --- 1. Hash Linkage Check ---
            if current_block.hash_prev != prev_block_hash {
                status = egui::RichText::new("❌ HASH FAILURE (Tampered Preceding Block)").color(egui::Color32::RED);
                overall_integrity_ok = false;
            }

            // --- 2. Signature Verification ---
            if let Some(sig_b64) = &current_block.signature {
                let sig_bytes = match general_purpose::STANDARD.decode(sig_b64) {
                    Ok(b) => b,
                    Err(_) => {
                        status = egui::RichText::new("❌ SIG FAILURE (Decode)").color(egui::Color32::RED);
                        overall_integrity_ok = false;
                        // Skip signature check if bytes are bad, but continue hashing
                        vec![] 
                    }
                };
                
                // Block content to sign (must match logic in server handler: content excluding signature)
                let mut content_to_verify = current_block.clone();
                content_to_verify.signature = None;
                let content_bytes = serde_json::to_string(&content_to_verify).unwrap().into_bytes();
                
                // Only proceed if sig_bytes are valid and overall integrity is still OK 
                if overall_integrity_ok && !sig_bytes.is_empty() {
                    let detached_sig = match dilithium2::DetachedSignature::from_bytes(&sig_bytes) {
                        Ok(s) => s,
                        Err(_) => {
                            status = egui::RichText::new("❌ SIG FAILURE (Struct)").color(egui::Color32::RED);
                            overall_integrity_ok = false;
                            
                            // Log and continue to the next block, no need to return
                            display_log.push_str(&format!(
                                "[{}] {} | Time: {} | Action: {} | User: {} | Prev Hash: {}...\n", 
                                line_num, 
                                status.text(), 
                                current_block.timestamp,
                                current_block.action,
                                current_block.user_id,
                                &current_block.hash_prev[..10]
                            ));
                            
                            // Update for next block before 'continue'
                            let mut content_to_hash = current_block.clone();
                            content_to_hash.signature = None; // Exclude signature from hashing
                            let serialized_content = serde_json::to_string(&content_to_hash).unwrap();
                            prev_block_hash = hex::encode(Sha256::digest(serialized_content));
                            continue;
                        }
                    };
                    
                    if dilithium2::verify_detached_signature(&detached_sig, &content_bytes, server_pk).is_err() {
                        status = egui::RichText::new("❌ SIG FAILURE (Verify)").color(egui::Color32::RED);
                        overall_integrity_ok = false;
                    }
                }
            } else {
                status = egui::RichText::new("❌ SIG MISSING").color(egui::Color32::RED);
                overall_integrity_ok = false;
            };

            // Append to display log
            display_log.push_str(&format!(
                "[{}] {} | Time: {} | Action: {} | User: {} | Prev Hash: {}...\n", 
                line_num, 
                status.text(), 
                current_block.timestamp,
                current_block.action,
                current_block.user_id,
                &current_block.hash_prev[..10]
            ));

            // Update for next block
            let mut content_to_hash = current_block.clone();
            content_to_hash.signature = None; // Exclude signature from hashing
            let serialized_content = serde_json::to_string(&content_to_hash).unwrap();
            prev_block_hash = hex::encode(Sha256::digest(serialized_content));
        }

        self.audit_log_data = display_log;

        if overall_integrity_ok {
            self.audit_log_status = format!("✅ Log Chain Verified Successfully! Total blocks: {}.", line_num);
        } else {
            self.audit_log_status = format!("🚨🚨🚨 Verification FAILED! Tampering detected or structural error at block {}.", line_num);
        }
    }
}

// GUI implementation (eframe 0.24: implement App trait)
// RE-INSERTED THE MISSING TRAIT IMPLEMENTATION
impl App for AppState {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        
        // 1. Top Bar
        egui::TopBottomPanel::top("top").show(ctx, |ui| {
            ui.heading("PQBank — Post-Quantum Banking Demo");
        });
        
        // 2. Left Side Navigation 
        egui::SidePanel::left("navigation_panel").show(ctx, |ui| {
            ui.heading("Navigation");
            ui.separator();
            
            ui.selectable_value(&mut self.current_view, CurrentView::Dashboard, "📊 Dashboard");
            ui.selectable_value(&mut self.current_view, CurrentView::EncryptedFiles, "🔒 Encrypted Files");
            ui.selectable_value(&mut self.current_view, CurrentView::WalletKeys, "🔑 Wallet Keys");
            ui.selectable_value(&mut self.current_view, CurrentView::AuditLogs, "📝 Audit Logs");
            
            ui.separator();
            
            // UX Enhancement: Color status feedback
            let status_text = if self.last_status.starts_with("Error") || self.last_status.starts_with("FAILED") {
                egui::RichText::new(format!("Status: {}", self.last_status)).color(egui::Color32::RED).strong()
            } else if self.last_status.starts_with("Ready") || self.last_status.starts_with("Success") || self.last_status.starts_with("Verified") {
                egui::RichText::new(format!("Status: {}", self.last_status)).color(egui::Color32::GREEN).strong()
            } else {
                egui::RichText::new(format!("Status: {}", self.last_status))
            };
            ui.label(status_text);
        });

        // 3. Central Panel (Dynamic Content)
        egui::CentralPanel::default().show(ctx, |ui| {
            match self.current_view {
                CurrentView::Dashboard => self.render_dashboard(ui),
                CurrentView::EncryptedFiles => self.render_encrypted_files(ui),
                CurrentView::WalletKeys => self.render_wallet_keys(ui),
                CurrentView::AuditLogs => self.render_audit_logs(ui),
            }
        });
    }
}

// Renderer functions for each view
impl AppState {
    fn render_dashboard(&mut self, ui: &mut egui::Ui) {
        ui.heading("📊 Dashboard (Transaction & File Send)");
        ui.separator();

        // User Auth (General Login/Metadata - Password is now optional here)
        ui.horizontal(|ui| {
            ui.label(egui::RichText::new("Username:").strong());
            ui.text_edit_singleline(&mut self.username);
            ui.label(egui::RichText::new("Password (Not used for Wallets):").strong());
            ui.add(egui::TextEdit::singleline(&mut self.password).password(true));
            
            if ui.button("Hash Password (Argon2 Demo)").clicked() {
                match hash_password(&self.password) {
                    Ok(hash) => self.last_status = format!("Success: Password Hashed (Argon2id): {}", &hash[0..40]),
                    Err(e) => self.last_status = format!("Error: Hashing Error: {:?}", e),
                }
            }
        });
        ui.label("Note: Wallet operations use the dedicated password field on the 'Wallet Keys' tab.");

        ui.separator();
        
        // Active Wallet Check
        if let Some(data) = &self.active_wallet_data {
            ui.label(egui::RichText::new("✅ Active Signing Key (Dilithium)").color(egui::Color32::GREEN).strong());
            ui.label(format!("Wallet: {} | PK Hash: {}...", data.name, &data.dilithium_pk_b64[..40]));
            ui.separator();
        } else {
            ui.label(egui::RichText::new("🔴 Signing Disabled: Decrypt a wallet on the '🔑 Wallet Keys' tab.").color(egui::Color32::RED).strong());
            ui.separator();
            return; 
        }

        // Transaction Form
        ui.label(egui::RichText::new("Create a transaction and send to local server (Kyber KEM + Dilithium signature):").strong());
        ui.horizontal(|ui| {
            ui.label("Amount:");
            ui.text_edit_singleline(&mut self.tx_amount);
            ui.label("Receiver:");
            ui.text_edit_singleline(&mut self.tx_receiver);
        });

        if ui.button("Send Transaction").clicked() {
            let tx = serde_json::json!({
                "amount": self.tx_amount,
                "receiver": self.tx_receiver,
                "sender": self.username,
                "timestamp": Utc::now().to_rfc3339(),
            });
            let id = format!("tx-{}", Uuid::new_v4());
            match self.perform_send(&tx.to_string(), &id) {
                Ok(resp) => {
                    self.last_status = format!("Success: Transaction sent and acknowledged by server. Response: {}", resp);
                    self.tx_amount.clear();
                    self.tx_receiver.clear();
                }
                Err(e) => {
                    self.last_status = format!("Error: Failed to send transaction: {:?}", e);
                }
            }
        }

        ui.separator();
        // File Upload
        ui.label(egui::RichText::new("Upload File to Encrypt and Send:").strong());
        if ui.button("Pick & Send File").clicked() {
            if let Some(path) = FileDialog::new().pick_file() {
                match fs::read(&path) {
                    Ok(bytes) => {
                        let meta = serde_json::json!({
                            "filename": path.file_name().unwrap().to_string_lossy(),
                            "len": bytes.len(),
                            "timestamp": Utc::now().to_rfc3339()
                        });
                        let payload_obj = serde_json::json!({
                            "meta": meta,
                            "data_b64": general_purpose::STANDARD.encode(&bytes),
                            "sender": self.username,
                            "timestamp": Utc::now().to_rfc3339(),
                        });
                        let id = format!("file-{}", Uuid::new_v4());
                        match self.perform_send(&payload_obj.to_string(), &id) {
                            Ok(resp) => {
                                self.last_status = format!("Success: File sent and Kyber-KEM protected. Server response: {}", resp);
                            }
                            Err(e) => {
                                self.last_status = format!("Error: Failed sending file: {:?}", e);
                            }
                        }
                    }
                    Err(e) => {
                        self.last_status = format!("Error: Failed reading file: {:?}", e);
                    }
                }
            }
        }
    }

    fn render_encrypted_files(&mut self, ui: &mut egui::Ui) {
        ui.heading("🗄️Encrypted File Vault (Server Data)");
        ui.separator();
        ui.label(egui::RichText::new("This panel represents the server's data storage.").strong());
        ui.label("Every record is secured by **Kyber KEM** and verified by a **Dilithium signature**.");
        
        ui.group(|ui| {
            ui.heading("Server Storage Location (Professional Demo Path)");
            ui.label(r"Location: [Project Root]\storage\encrypted\ ");
            ui.label("This folder contains the post-quantum encrypted CryptoEnvelope JSON files.");
        });
    }

    fn render_wallet_keys(&mut self, ui: &mut egui::Ui) {
        ui.heading("🔑Crypto Wallet Module (Local Security Demo)");
        ui.separator();

        // UX/Security Status Panel
        ui.group(|ui| {
            ui.label(egui::RichText::new("Wallet Password Status:").strong());
            
            let password_status = if self.wallet_password_hash_cache.is_some() {
                egui::RichText::new("✅ Decryption Key Derived & Cached (Session Active)").color(egui::Color32::GREEN).strong()
            } else if !self.wallet_password.is_empty() {
                egui::RichText::new("🟡 Password Entered. Click Decrypt/Create to derive key.").color(egui::Color32::YELLOW)
            } else {
                egui::RichText::new("🔴 Enter password below.").color(egui::Color32::RED).strong()
            };
            ui.label(password_status);
            
            ui.separator();
            
            ui.label(egui::RichText::new("Dedicated Wallet Password:").strong());
            ui.horizontal(|ui| {
                ui.add(egui::TextEdit::singleline(&mut self.wallet_password).password(true).desired_width(200.0));
                
                // Clear Hash Button
                if ui.button("Clear Key Cache").clicked() {
                    self.wallet_password_hash_cache = None;
                    self.decrypted_data = None;
                    self.active_wallet_data = None;
                    self.last_status = "Status: Key cache cleared. Re-enter password to continue.".to_string();
                }
            });
            ui.label("Note: Key cache is destroyed on app restart or by clicking 'Clear Key Cache'.");
        });

        ui.separator();

        // --- 1. Create New Wallet ---
        ui.group(|ui| {
            ui.label(egui::RichText::new("Create New Wallet").strong());

            let is_ready = self.wallet_password_hash_cache.is_some() || !self.wallet_password.is_empty();

            if !is_ready {
                ui.colored_label(egui::Color32::RED, "🔴 Enter and successfully decrypt/create a wallet first to cache the key.");
            } else {
                ui.horizontal(|ui| {
                    ui.label("Name:");
                    ui.text_edit_singleline(&mut self.new_wallet_name);
                    
                    if ui.button("Create & Encrypt").clicked() {
                        // --- START NEW DUPLICATE CHECK ---
                        if self.wallets.iter().any(|w| w.name == self.new_wallet_name) {
                            self.last_status = format!("Error: A wallet named '{}' already exists. Please choose a different name.", self.new_wallet_name);
                            return; // Exit the click handler
                        }
                        // --- END NEW DUPLICATE CHECK ---

                        match self.get_wallet_hash_or_derive() {
                            Ok(hash) => {
                                let wallet_storage_path = ensure_storage_dir().join("wallets");
                                match wallet::Wallet::create_and_save(&self.new_wallet_name, &hash, wallet_storage_path) {
                                    Ok(w) => {
                                        self.wallets.push(w);
                                        self.last_status = format!("Success: Wallet '{}' created, ENCRYPTED, and saved. Key derived from password hash.", self.new_wallet_name);
                                        self.new_wallet_name.clear();
                                    }
                                    Err(e) => {
                                        self.last_status = format!("Error: Wallet creation/encryption failure: {:?}", e);
                                    }
                                }
                            },
                            Err(e) => self.last_status = format!("Error: Cannot create. Password hash missing: {:?}", e),
                        }
                    }
                });
            }
            ui.label(r"Location: [Project Root]\storage\wallets\");
        });

        ui.separator();

        // --- 2. List, Decrypt, Activate, and DELETE Wallets ---
        ui.heading(egui::RichText::new("Your Wallets (Decrypt, Activate, or Delete)").strong());
        
        // We use a temporary clone to iterate over, but use indices for deletion/activation
        let wallet_indices: Vec<(usize, Wallet)> = self.wallets.iter().cloned().enumerate().collect(); 
        
        if self.wallets.is_empty() {
            ui.label("No wallets found. Create one above.");
        } else {
            egui::ScrollArea::vertical().max_height(200.0).show(ui, |ui| {
                let mut index_to_delete = None;
                
                for (index, wallet) in wallet_indices { 
                    ui.horizontal(|ui| {
                        let active_indicator = if self.active_wallet_data.as_ref().map(|d| d.name.as_str()) == Some(&wallet.name) {
                            egui::RichText::new("(ACTIVE)").color(egui::Color32::GREEN).strong()
                        } else {
                            egui::RichText::new("")
                        };
                        ui.label(format!("- {} (ID: {}...) [Salt: {}...]", wallet.name, &wallet.id.to_string()[..8], &wallet.salt_hex[..8]));
                        ui.label(active_indicator);
                        
                        if ui.button("Decrypt & Activate").clicked() {
                            match self.get_wallet_hash_or_derive() {
                                Ok(hash) => {
                                    // Use the obtained hash (cached or freshly derived) for decryption
                                    match wallet.decrypt_data(&hash) {
                                        Ok(data) => {
                                            self.active_wallet_data = Some(data.clone());
                                            self.username = data.name.clone(); 
                                            self.decrypted_data = Some(format!(
                                                "Name: {}\n\n--- Post-Quantum Keys ---\n\
                                                Kyber PK (KEM): {}...\n\
                                                Kyber SK (KEM): {}...\n\
                                                Dilithium PK (Sign): {}...\n\
                                                Dilithium SK (Sign): {}...",
                                                data.name, 
                                                &data.kyber_pk_b64[..40], 
                                                &data.kyber_sk_b64[..40], 
                                                &data.dilithium_pk_b64[..40], 
                                                &data.dilithium_sk_b64[..40]
                                            ));
                                            self.last_status = format!("Success: Wallet '{}' decrypted using session hash. PQC keys loaded.", wallet.name);
                                        }
                                        Err(e) => {
                                            self.decrypted_data = None;
                                            self.active_wallet_data = None;
                                            self.wallet_password_hash_cache = None; // Invalidate cache on decryption failure
                                            self.last_status = format!("Error: Decryption FAILED for '{}': {}. Key cache cleared. Check password and try again.", wallet.name, e);
                                        }
                                    }
                                },
                                Err(e) => self.last_status = format!("Error: Cannot decrypt. Password hash not available: {:?}", e),
                            }
                        }
                        
                        // --- DELETE WALLET BUTTON ---
                        if ui.button(egui::RichText::new("❌ Delete").color(egui::Color32::RED)).clicked() {
                            index_to_delete = Some(index);
                        }
                        // --- END DELETE BUTTON ---
                    });
                }
                
                // Process Deletion outside of the iteration
                if let Some(index) = index_to_delete {
                    let wallet_to_remove = &self.wallets[index];
                    let wallet_path = ensure_storage_dir().join("wallets").join(format!("{}.json", wallet_to_remove.id));
                    let name = wallet_to_remove.name.clone();
                    
                    // 1. Delete the file from the disk
                    match fs::remove_file(&wallet_path) {
                        Ok(_) => {
                            // 2. Remove the wallet from the in-memory list
                            self.wallets.remove(index);
                            
                            // 3. Clear active wallet if the deleted wallet was active
                            if self.active_wallet_data.as_ref().map(|d| d.name.as_str()) == Some(&name) {
                                self.active_wallet_data = None;
                                self.decrypted_data = None;
                            }
                            self.last_status = format!("Success: Wallet '{}' deleted permanently from disk.", name);
                        }
                        Err(e) => {
                            self.last_status = format!("Error: Failed to delete wallet file for '{}': {:?}", name, e);
                        }
                    }
                }
            });
        }
        
        ui.separator();
        
        // --- 3. Decrypted View (no change needed) ---
        ui.group(|ui| {
            ui.heading(egui::RichText::new("Decrypted Wallet Data (Raw Keys)").strong());
            if let Some(data) = &self.decrypted_data {
                ui.text_edit_multiline(&mut data.clone()); 
                ui.colored_label(egui::Color32::YELLOW, "⚠️ Kyber SK and Dilithium SK are the sensitive keys. Shown here *only* after decryption.");
            } else {
                ui.label("Select a wallet and click 'Decrypt & Activate' to view its contents.");
            }
        });
    }

    // Phase 7: GUI for Audit Logs (no change needed)
    fn render_audit_logs(&mut self, ui: &mut egui::Ui) {
        ui.heading("📝 Tamper-Proof Audit Logs (Blockchain Style)");
        ui.separator();
        
        let pk_status = if self.server_dilithium_pk.is_some() {
            egui::RichText::new("✅ Server Dilithium PK Loaded").color(egui::Color32::GREEN).strong()
        } else {
            egui::RichText::new("🔴 Server Dilithium PK NOT Loaded").color(egui::Color32::RED).strong()
        };
        ui.label(pk_status);

        ui.horizontal(|ui| {
            if ui.button(egui::RichText::new("Verify Chain Integrity").strong()).clicked() {
                self.verify_audit_log();
            }
            ui.add_space(20.0);
            
            let log_status_text = if self.audit_log_status.starts_with("🚨") {
                egui::RichText::new(self.audit_log_status.clone()).color(egui::Color32::RED).strong()
            } else if self.audit_log_status.starts_with("✅") {
                egui::RichText::new(self.audit_log_status.clone()).color(egui::Color32::GREEN).strong()
            } else {
                egui::RichText::new(self.audit_log_status.clone()).strong()
            };
            ui.label(log_status_text);
        });

        ui.separator();
        
        ui.group(|ui| {
            ui.heading(egui::RichText::new("Log Chain Location").strong());
            ui.label(r"Location: [Project Root]\storage\audit\log_chain.json");
            ui.label("This file is read by the client. If edited manually, Hash/Signature verification above will fail.");
        });

        ui.separator();

        ui.heading(egui::RichText::new("Verification Output:").strong());
        
        egui::ScrollArea::vertical().max_height(400.0).show(ui, |ui| {
            if self.audit_log_data.is_empty() {
                ui.label("Click 'Verify Chain Integrity' to load and check the log.");
            } else {
                ui.add(egui::TextEdit::multiline(&mut self.audit_log_data.clone())
                    .desired_width(f32::INFINITY)
                    .font(egui::TextStyle::Monospace));
            }
        });
    }
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let storage_dir = ensure_storage_dir();
    let keys_path = storage_dir.join("server_keys.json");

    // Spin up the server worker in a background thread
    let server_storage = storage_dir.clone();
    let server_keys_path = keys_path.clone();
    thread::spawn(move || {
        if let Err(e) = server_worker(server_storage, server_keys_path) {
            eprintln!("Server worker error: {:?}", e);
        }
    });

    // Wait a tiny bit for server to bind
    std::thread::sleep(Duration::from_millis(300));

    // Run GUI app
    let app = AppState::default();
    let native_options = eframe::NativeOptions::default();
    // FIX: Using eframe::App as the trait bound is now satisfied
    eframe::run_native("PQBank Demo", native_options, Box::new(|_cc| Box::new(app))).map_err(|e| anyhow!("eframe error: {}", e))?;

    Ok(())
}