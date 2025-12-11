// src/wallet.rs

use anyhow::{anyhow, Result, Context};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use std::{fs, path::PathBuf};
use sha2::{Digest, Sha256};
use hex;

use base64::Engine; 
use base64::engine::general_purpose;

use chacha20poly1305::{
    aead::{Aead, KeyInit, OsRng},
    XChaCha20Poly1305, XNonce,
};
use chacha20poly1305::aead::rand_core::RngCore;

// --- PQC Imports ---
use pqcrypto_kyber::kyber768;
use pqcrypto_dilithium::dilithium2;
use pqcrypto_traits::kem::{PublicKey as KemPublicKeyTrait, SecretKey as KemSecretKeyTrait};
use pqcrypto_traits::sign::{PublicKey as SignPublicKeyTrait, SecretKey as SignSecretKeyTrait};

// Removed WALLET_DIR constant: Path is now passed from main.rs

/// Struct containing the actual sensitive data we want to encrypt.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct WalletData { 
    pub name: String,
    // --- PQC Keypairs Stored Here ---
    pub kyber_pk_b64: String,    // Kyber Public Key (KEM: Key Encapsulation Mechanism)
    pub kyber_sk_b64: String,    // Kyber Secret Key (Must be kept secure!)
    pub dilithium_pk_b64: String, // Dilithium Public Key (Signature)
    pub dilithium_sk_b64: String, // Dilithium Secret Key (Must be kept secure!)
}

/// The encrypted structure saved to disk.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Wallet {
    pub id: Uuid,
    pub name: String,
    pub salt_hex: String,        // Unique salt used for password derivation
    pub ciphertext_b64: String,  // Encrypted WalletData
}

// Utility: Simple function to derive a fixed 32-byte key from a stable hash/password
fn derive_key(hash: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(hash);
    hasher.finalize().into()
}

// --- PQC Key Generation ---
fn generate_pqc_keypairs() -> WalletData {
    // Generate Kyber (KEM) keypair
    let (kyber_pk, kyber_sk) = kyber768::keypair();
    
    // Generate Dilithium (Signature) keypair
    let (dilithium_pk, dilithium_sk) = dilithium2::keypair();

    // Convert to Base64 strings for easy JSON serialization
    WalletData {
        name: "New Wallet".to_string(), // Placeholder name, updated later
        kyber_pk_b64: general_purpose::STANDARD.encode(kyber_pk.as_bytes()),
        kyber_sk_b64: general_purpose::STANDARD.encode(kyber_sk.as_bytes()),
        dilithium_pk_b64: general_purpose::STANDARD.encode(dilithium_pk.as_bytes()),
        dilithium_sk_b64: general_purpose::STANDARD.encode(dilithium_sk.as_bytes()),
    }
}
// ----------------------------------------


impl Wallet {
    // MODIFIED: Takes the specific wallet path now
    fn get_wallet_path(id: Uuid, wallet_dir: &PathBuf) -> PathBuf {
        if !wallet_dir.exists() {
            let _ = fs::create_dir_all(wallet_dir);
        }
        wallet_dir.join(format!("{}.json", id))
    }

    /// Creates a new wallet instance, generates PQC keys, encrypts them, and saves it to disk.
    // MODIFIED: Takes wallet_dir PathBuf
    pub fn create_and_save(name: &str, password_hash: &str, wallet_dir: PathBuf) -> Result<Self> {
        let id = Uuid::new_v4();
        
        // 1. Generate a unique salt for this wallet (essential for KDF)
        let mut salt_bytes = [0u8; 16];
        OsRng.fill_bytes(&mut salt_bytes);
        let salt_hex = hex::encode(salt_bytes);
        
        // 2. Derive the Master Encryption Key (MEK)
        let key_input = format!("{}_{}", password_hash, salt_hex); 
        let mek = derive_key(&key_input);
        
        // 3. Generate PQC Keys and Create the inner data structure
        let mut data = generate_pqc_keypairs();
        data.name = name.to_string(); // Set the user-provided name
        
        let data_json = serde_json::to_vec(&data)?;

        // 4. Encrypt the data using XChaCha20-Poly1305
        let key = chacha20poly1305::Key::from_slice(&mek);
        let cipher = XChaCha20Poly1305::new(key);
        let mut nonce_bytes = [0u8; 24];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = XNonce::from_slice(&nonce_bytes);
        
        let ciphertext = cipher
            .encrypt(nonce, data_json.as_ref())
            .map_err(|e| anyhow!("symmetric encrypt error: {:?}", e))?;

        // Prepend nonce to ciphertext
        let mut encrypted_blob = Vec::with_capacity(24 + ciphertext.len());
        encrypted_blob.extend_from_slice(&nonce_bytes);
        encrypted_blob.extend_from_slice(&ciphertext);
        
        let wallet = Wallet {
            id,
            name: name.to_string(),
            salt_hex,
            ciphertext_b64: general_purpose::STANDARD.encode(encrypted_blob),
        };

        // 5. Save the Wallet struct (containing encrypted data) to disk
        let path = Self::get_wallet_path(id, &wallet_dir);
        let j = serde_json::to_vec_pretty(&wallet)?;
        fs::write(path, j).context("Failed to write wallet to disk")?;

        Ok(wallet)
    }

    /// Loads all wallets from the local directory.
    // MODIFIED: Takes wallet_dir PathBuf
    pub fn load_all(wallet_dir: PathBuf) -> Result<Vec<Self>> {
        if !wallet_dir.exists() {
            return Ok(vec![]);
        }

        let mut wallets = Vec::new();
        for entry in fs::read_dir(wallet_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().map_or(false, |ext| ext == "json") {
                let bytes = fs::read(&path)?;
                let wallet: Wallet = serde_json::from_slice(&bytes).context(format!("Failed to parse wallet file: {:?}", path))?;
                wallets.push(wallet);
            }
        }
        Ok(wallets)
    }

    /// Decrypts and returns the inner WalletData using the password hash.
    pub fn decrypt_data(&self, password_hash: &str) -> Result<WalletData> {
        // 1. Derive the MEK using the password hash and the stored salt
        let key_input = format!("{}_{}", password_hash, self.salt_hex);
        let mek = derive_key(&key_input);
        
        // 2. Decode the encrypted blob
        let encrypted_blob = general_purpose::STANDARD.decode(&self.ciphertext_b64)?;
        
        if encrypted_blob.len() < 24 {
            return Err(anyhow!("Ciphertext too short"));
        }
        let (nonce_bytes, ct) = encrypted_blob.split_at(24);
        
        // 3. Decrypt the data
        let key = chacha20poly1305::Key::from_slice(&mek);
        let cipher = XChaCha20Poly1305::new(key);
        let nonce = XNonce::from_slice(nonce_bytes);

        let pt = cipher
            .decrypt(nonce, ct)
            .map_err(|_| anyhow!("Decryption failed! Check password."))?;

        // 4. Deserialize the inner data
        let data: WalletData = serde_json::from_slice(&pt)?;
        Ok(data)
    }
}