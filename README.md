# 🛡️ PQ-BANK: Quantum-Resistant Wallet & Key Management System

[![GitHub Stars](https://img.shields.io/github/stars/Sumitchongder/Quantum-Resistant-Module-Lattice-Cryptography?style=social)](https://github.com/Sumitchongder/Quantum-Resistant-Module-Lattice-Cryptography)
[![Rust](https://img.shields.io/badge/Rust-1.91+-orange.svg)](https://www.rust-lang.org/)
[![PQC](https://img.shields.io/badge/Post--Quantum-Kyber%20%2B%20Dilithium-green.svg)](https://csrc.nist.gov/projects/post-quantum-cryptography)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)


## A Modern Demonstration of Module-Lattice Cryptography in Rust

> **A production-minded, recruiter-grade demonstration of lattice-based Post-Quantum Cryptography (PQC)** — Kyber KEM for key exchange and Dilithium for signatures — combined with modern symmetric envelopes, secure wallet storage, and a tamper-proof audit chain.
> Built in **Rust** with an `eframe/egui` GUI and a local server thread for realistic workflows.

---

<img width="3104" height="1011" alt="Image" src="https://github.com/user-attachments/assets/c73e858c-1077-4f44-b3d5-7a6dcf20a993" />

<img width="3462" height="1826" alt="Image" src="https://github.com/user-attachments/assets/42cfe73d-6dbf-45ed-9ff8-4dd4886a5ad5" />

<img width="3168" height="1340" alt="Image" src="https://github.com/user-attachments/assets/ff77d376-947a-4cca-b8cd-507e0eb6e7e5" />

<img width="3421" height="1631" alt="Image" src="https://github.com/user-attachments/assets/687499b7-d71f-4725-a83f-781fab73404a" />


---

## ✨ Executive summary

**PQ-BANK** is a real-world Rust application demonstrating how to protect banking records, transaction payloads and crypto wallets against future quantum threats using lattice-based PQC (Kyber + Dilithium), AEAD envelopes (XChaCha20-Poly1305) and secure key handling patterns with a polished GUI and auditability baked in.

---

## Table of contents

1. Motivation & Value
2. Architecture & Components
3. Cryptography Deep-Dive (intuitive + technical)
   * PQC: what & why
   * Lattice-based cryptography (intuitive)
   * Kyber (KEM) & Dilithium (signatures) — how we use them
   * Hybrid envelope pattern (HKDF + XChaCha20-Poly1305)
   * Password/wallet protection (Argon2id)
4. Threat model & security considerations
5. Project layout & files to include in repo
6. Quickstart: build & run (copy-paste commands)
7. How to test & example inputs
8. Developer notes: extend to production
9. FAQ / common troubleshooting
10. License & contribution

---

## Motivation & Value

Quantum computers pose a threat to common asymmetric cryptography (RSA, ECC). Organisations that handle financial or identity data must be **crypto-agile** and begin integrating PQC now. This project demonstrates practical engineering, showcasing how PQC primitives integrate into a secure application stack, how to combine them with symmetric primitives, and how to enhance user experience and auditability through cryptography.

---

## Architecture & Components

<img width="1891" height="1375" alt="Image" src="https://github.com/user-attachments/assets/c82da106-5e98-448f-80f1-5f8953e2697c" />

Key flows:

* Wallet creation: generates **Kyber** + **Dilithium** keypairs, encrypts them with password-derived key (Argon2id + HKDF) and stores as encrypted wallet JSON.
* Transaction/file upload: client obtains server Kyber PK, encapsulates to produce ciphertext + shared secret → derives session key via HKDF → encrypts payload with XChaCha20-Poly1305 → signs payload with Dilithium → sends envelope to server.
* Server: decapsulates to session key, verifies signature, re-encrypts envelope for storage, appends signed audit block.

---

## Cryptography deep-dive — intuitive + technical

This section explains the primitives, why they were chosen, and how they're applied.

### 1) Post-Quantum Cryptography (PQC) — what & why (intuitive)

* Traditional public-key algorithms (RSA, ECDSA) rely on number-theoretic hardness (factoring, discrete log). Quantum computers using **Shor's algorithm** can break these efficiently.
* **PQC** algorithms are designed to resist quantum attacks. NIST standardized several PQC algorithms (Kyber, Dilithium, etc.) after an open competition.
* PQC is *not* a silver bullet — it requires careful composition and migration planning. This project demonstrates a safe, pragmatic composition pattern.

<img width="1024" height="1024" alt="Image" src="https://github.com/user-attachments/assets/bd802e9f-1396-4142-bc35-ba1948462843" />

---

### 2) Lattice-Based Cryptography 

* A lattice is a regular grid of points in high-dimensional space. Lattice problems (e.g., Learning With Errors — LWE) are hard to solve with both classical and quantum algorithms when dimensions are large and noise is present.
* **Module-LWE / Module-LWR** (module-lattice) are efficient variants using polynomial structures — they give strong security per key size and are the foundation of Kyber & Dilithium.

**Analogy:** imagine trying to find the smallest indentation in a huge, noisy multi-dimensional mattress — that’s computationally expensive, and quantum computers don’t give an arithmetic shortcut as they do for factoring.

<img width="1024" height="1024" alt="Image" src="https://github.com/user-attachments/assets/e096cf54-4b50-47b0-9fd0-9c3efcd4cc10" />

---

### 3) Kyber (KEM) — how it’s used

* **KEM** = Key Encapsulation Mechanism. Kyber is a module-lattice KEM standardized by NIST.
* Flow (client/server):

  1. Server publishes Kyber public key PK_S.
  2. Client calls `encapsulate(PK_S)` → gets (CT, shared_secret).
  3. Client sends CT to server.
  4. Server does `decapsulate(CT, SK_S)` → recovers the same shared_secret.
* We derive a symmetric session key from shared_secret using **HKDF-SHA256**.

**Why KEM?** It provides forward secrecy per session and avoids classical Diffie–Hellman constructs that are not quantum-safe.

---

### 4) Dilithium (Signatures) — how it’s used

* **Dilithium** is a lattice-based digital signature scheme standardized by NIST.
* We use **detached signatures**:

  * Client signs payload (transaction JSON or file digest).
  * Server verifies signature using the client’s public key (provided inside the payload).
  * Server signs audit blocks with its own Dilithium key to prove authenticity of logs.

**Why Dilithium?** It provides strong post-quantum message integrity and non-repudiation.

---

### 5) Hybrid envelope: HKDF + XChaCha20-Poly1305 

We follow the **envelope pattern**:

1. `shared_secret` (Kyber) → `session_key` by `HKDF(SHA256)`.
2. `session_key` (32 bytes) used with `XChaCha20-Poly1305` AEAD:

   * Nonce: 24 bytes (random XNonce).
   * Ciphertext = AEAD.encrypt(nonce, plaintext, associated_data)
   * Store `nonce||ct` + metadata in encrypted envelope.

Why this approach?

* KEM gives authenticated shared secret without transmitting the secret.
* HKDF is a robust KDF that avoids raw use of shared_secret bits.
* XChaCha20-Poly1305 is fast, secure (AEAD), and simpler to use than TLS primitives. XChaCha’s 24-byte nonce reduces nonce reuse risks.

---

### 6) Password & wallet protection (Argon2id + salt)

* Wallet encryption uses a strong password KDF: **Argon2id** (memory-hard) with per-wallet salt and recommended parameters.
* Derived key is then passed through HKDF to finalize the symmetric key used to encrypt the wallet blob (Kyber + Dilithium private data).
* **Why Argon2id:** resists GPU/ASIC brute forcing and balances time/memory cost.

---

## Threat model & security considerations

**Assumptions**

* Local demo: server runs on `127.0.0.1`. Network exposure is off by default.
* User provides passwords only for local wallet unlocking.

**Adversary capabilities considered**

* Disk compromise (attacker can read encrypted wallets / envelopes).
* Network eavesdropping on local TCP (client/server messages are AEAD-encrypted — attacker sees ciphertext & Kyber CT but cannot derive shared_secret).
* Malicious file replacement (countered by Dilithium signatures & audit chain).

**What this design defends**

* Confidentiality: file contents & private keys encrypted at rest and in transit.
* Integrity/Authenticity: Dilithium signatures on transactions and signed audit logs.
* Forward secrecy for sessions: Kyber per-session KEM.

**Limitations / what we do NOT claim**

* This demo is not production-hardened: key backup, HSM/TPM integration, network TLS (mTLS/QUIC), hardened authentication, and formal audit are *required* for production. See [Production Roadmap](#developer-notes-extend-to-production).

---

## Project layout & files to include in the repo

```
pqbank/
├─ Cargo.toml                # dependency manifest (stable versions only)
├─ README.md                 # this file
├─ LICENSE
├─ .gitignore
├─ src/
   ├─ main.rs                # GUI, app lifecycle, server thread
   └─ wallet.rs              # wallet creation, encrypt/decrypt API

```

**IMPORTANT:** add `storage/` to `.gitignore`. Runtime files are created under `storage/` only.

---

## Quickstart — build & run (copy-paste)

> Tested on Rust **1.91.1** (MSVC toolchain on Windows recommended).

```bash
# 1. clone
git clone https://github.com/<your-username>/pqbank.git
cd pqbank

# 2. ensure Cargo.toml uses stable versions (no -rc)
# (the repo already contains a tested Cargo.toml)

# 3. clean then build
cargo clean
cargo build --release

# 4. run (GUI)
# Linux / macOS
./target/release/pqbank

# Windows (PowerShell)
.\target\release\pqbank.exe
```

When launched:

* GUI opens
* background server thread starts and listens on `127.0.0.1:40000`
* storage directory `./storage/` is created automatically

---

## How to test & example inputs

### 1. Create a wallet (Wallet Manager)

* Wallet name: `demo_wallet`
* Password: `Test@1234!` *(use dummy data for public repos)*

### 2. Unlock the wallet

* Use the same password to decrypt; GUI shows Dilithium public key (b64) and Kyber public key (b64).

### 3. Send a transaction

* Amount: `2500`
* Receiver: `ACC5566778899`
* Click **Send Transaction** — the sequence:

  * GETPK → encapsulate → sign → send
  * Server decapsulates → verifies signature → stores envelope → writes signed audit block

### 4. Upload a sample file

* Create `receipt.csv`:

  ```
  time,desc,amount
  2025-12-10 14:32,NEFT,4500
  ```
* Click **Pick & Send File** → select `receipt.csv`.

### 5. Verify logs

* Open **Audit Logs** → click **Verify Chain**. Should report chain integrity OK and list actions.

---

## Example data formats

**Transaction JSON**

```json
{
  "amount": 2500,
  "currency": "INR",
  "sender": "sumit_demo",
  "receiver": "ACC5566778899",
  "timestamp": "2025-12-10T14:32:12+05:30"
}
```

**Encrypted envelope (stored on server) — conceptual**

```json
{
  "id": "file-uuid",
  "nonce": "<base64>",
  "ciphertext": "<base64>",
  "signature": "<base64>",
  "signer_pubkey": "<b64>",
  "meta": { "filename": "receipt.csv", "uploaded_at": "..." }
}
```

---

## Developer notes — how to extend to production (roadmap for reviewers)

A recruiter reading this will want to know you understand the gaps. Suggested roadmap:

1. **Replace local server thread with axum/quinn server** (mutual auth + QUIC).
2. **HSM / TPM**: move server private keys into hardware keystore (TPM sealed keys or cloud KMS).
3. **Auth layer**: OAuth2 / OpenID Connect for users; integrate CSRF/XSRF protections for web clients.
4. **Persistent DB**: Postgres for metadata; object store for blobs (S3). Use envelope encryption; only store ciphertext.
5. **TLS / mTLS + hardened networking**: apply DDoS protections, rate limiting, TLS cert rotation.
6. **CI/CD + SCA**: run cargo audit, clippy, fmt, unit tests, fuzz tests.
7. **Third-party crypto audit + formal verification** before any real funds.
8. **Key rotation & backup** strategy + secure escrow for emergency recovery.

---

## FAQ & Troubleshooting

**Q: I see build errors on Windows related to `winapi` or `eframe`**
A: Make sure `Cargo.toml` pins `eframe = "0.24.1"` and includes a `winapi` override enabling `"winuser"` features (the repo provides a tested `Cargo.toml`). Run `cargo clean` then `cargo build`.

**Q: Why store server keys locally?**
A: This is a demo. In production, use an HSM or KMS.

**Q: Is this production ready?**
A: No — it demonstrates design and implementation patterns. Production requires audits, HSMs, hardened auth and deployment.

---

## Contributing / Code of Conduct

Contributions welcome! If you contribute:

* Add tests for any crypto/network code you change
* Keep private keys out of commits
* Follow Rustfmt and Clippy suggestions

---

## License

**MIT License** — see `LICENSE` for full text.

