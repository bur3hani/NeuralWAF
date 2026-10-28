# NeuralWAF by BuruOps

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Zero Secrets](https://img.shields.io/badge/Zero--Secrets-Compliant-emerald.svg)](.github/SECURITY.md)
[![Argon2id](https://img.shields.io/badge/Hashing-Argon2id%20(RFC%209106)-violet.svg)](#cryptographic-vault-architecture)
[![Vault Encryption](https://img.shields.io/badge/Vault-AES--256--GCM-cyan.svg)](#cryptographic-vault-architecture)
[![PHP Ingress](https://img.shields.io/badge/PHP-7.4%20--%208.3+-777BB4.svg)](#root-directory-architecture)
[![Node Ingress](https://img.shields.io/badge/Node.js-18%20--%2022+-339933.svg)](#root-directory-architecture)
[![Author](https://img.shields.io/badge/Attribution-BuruOps%20Engineering-orange.svg)](mailto:engr.buru@gmail.com)

**NeuralWAF** is an enterprise-grade, root-level Web Application Firewall developed by **BuruOps** (`engr.buru@gmail.com`). Engineered to install directly into any website root directory (`public_html/` or `/`), it intercepts incoming HTTP requests before CMS platforms (WordPress, Laravel, Drupal) or application code execute. 

Unlike traditional WAFs that rely on brittle, bypassable static regular expressions, NeuralWAF converts raw HTTP streams into high-dimensional numerical token sequences and evaluates them against an external **LSTM Autoencoder** for microsecond behavioral anomaly detection.

---

## Key Highlights

- **BuruOps Zero-Secrets Guarantee**: No hardcoded passwords, private keys, or API tokens exist in this repository. All operator accounts are provisioned at install-time, hashed via **Argon2id** (`m=64MB, t=4, p=2`), and encrypted inside an **AES-256-GCM** vault (`chmod 0600`) untracked by Git.
- **Root Directory Drop-In**: Operates directly in standard web server environments (Apache, LiteSpeed, Nginx, cPanel). Pre-execution is enforced via `auto_prepend_file` in `.user.ini` or `.htaccess`.
- **Zero Regex Vulnerabilities**: Replaces static rule maintenance with deep learning sequence reconstruction loss ($MSE \ge \tau = 0.65 \implies 403\text{ Forbidden}$).
- **Role-Based Access Control (RBAC)**: Enterprise operator management with `SuperAdmin`, `SecurityOperator`, and `Auditor` scopes.
- **Tamper-Evident Audit Trail**: Every privilege elevation and credential rotation is linked via a backward **SHA-256 cryptographic hash-chain**.
- **Microsecond Ingress SLA**: PHP ingress overhead is $\le 0.28\text{ms}$; deep learning inference round-trip is $\le 1.20\text{ms}$.

---

## Architecture Topology

```
                         [ Ingress HTTP/S Traffic ]
                                     │
                                     ▼
        ┌────────────────────────────────────────────────────────┐
        │  WEBSITE ROOT DIRECTORY (public_html/ or /)            │
        │  1. Ingress Interceptor Hook (auto_prepend_file)      │
        │     - neuralwaf/bootstrap.php (PHP 7.4 - 8.3+)         │
        │     - neuralwaf/engine.js (Node.js 18 - 22+)           │
        │     - Zero-alloc stream tokenizer (capped at 64KB)     │
        │     - In-memory sliding-window IP rate limiter         │
        └──────────────────────────┬─────────────────────────────┘
                                   │
              (Unix Domain Socket / Local IPC :8081)
                                   │
                                   ▼
        ┌────────────────────────────────────────────────────────┐
        │  NEURALWAF DAEMON & RBAC VAULT                         │
        │  - neuralwaf/data/credentials.enc (AES-256-GCM)        │
        │  - Argon2id CSPRNG password verification               │
        │  - SHA-256 tamper-evident cryptographic audit chain    │
        └──────────────────────────┬─────────────────────────────┘
                                   │
                       (Pooled gRPC / HTTP/2)
                                   │
                                   ▼
        ┌────────────────────────────────────────────────────────┐
        │  LSTM AUTOENCODER INFERENCE ENGINE                     │
        │  - 256-dim token embeddings                            │
        │  - 2-layer Bidirectional LSTM                          │
        │  - Mean Squared Error (MSE) reconstruction loss        │
        │  - Asynchronous Kafka streaming to Zima MDR            │
        └────────────────────────────────────────────────────────┘
```

---

## Interactive Installation & Credential Setup

NeuralWAF includes an automated interactive installation script that provisions your initial SuperAdmin credentials, derives cryptographic master keys, and locks down permissions.

### Option 1: Automated Bash Installer (Recommended)

From your website root directory:

```bash
# Clone the open-source repository
git clone https://github.com/buruops/neuralwaf.git .

# Execute the interactive credential setup script
bash scripts/install.sh
```

During execution, the installer will:
1. Validate runtime prerequisites (PHP, OpenSSL, Node.js).
2. Prompt for your **SuperAdmin Username** and **Email** (`engr.buru@gmail.com`).
3. Offer to generate a cryptographically strong 28-character password using `/dev/urandom`.
4. Derive a **256-bit AES Master Key** and **HMAC JWT Secret**.
5. Hash the password with **Argon2id** and seal the vault inside `neuralwaf/data/credentials.enc` with `chmod 0600`.
6. Write master secrets to `neuralwaf/config.secure.php` (`chmod 0600`, ignored by `.gitignore`).
7. Append `auto_prepend_file = "neuralwaf/bootstrap.php"` into `.user.ini` and `.htaccess`.
8. Execute a decryption self-test to verify vault integrity.

---

## User Management & Role-Based Access Control (RBAC)

NeuralWAF enforces least-privilege role boundaries across three tiers:

| Role | Scope & Permissions | Key Privileges |
| :--- | :--- | :--- |
| **`SuperAdmin`** | Full root authority | User provisioning, AES master key rotation, anomaly threshold tuning ($\tau$), bypass list management. |
| **`SecurityOperator`** | Tactical defense | Live traffic inspection, D3 IP heatmap monitoring, active DDoS mitigation triggers, IP ban/unban. |
| **`Auditor`** | Compliance & oversight | Read-only inspection of SHA-256 cryptographic audit logs and forensic payload exports. |

### CLI User Administration

Manage operators directly from the command line without web access:

```bash
# List all registered operators and roles
php neuralwaf/bin/waf-user.php list

# Provision a new Security Operator interactively
php neuralwaf/bin/waf-user.php add --user soc_lead --email soc@company.com --role SecurityOperator

# Rotate an operator password & re-encrypt the vault
php neuralwaf/bin/waf-user.php reset-password --user buru_admin

# Rotate the AES-256-GCM master key across all stored credentials
php neuralwaf/bin/waf-user.php rotate-master-key
```

---

## Cryptographic Vault Architecture

NeuralWAF adheres to **NIST SP 800-132** and **OWASP ASVS 4.0 Level 3**:

- **Symmetric Cipher**: AES-256-GCM authenticated encryption with 96-bit unique CSPRNG Initialization Vectors (IV) and 128-bit authentication tags.
- **Key Derivation & Hashing**: Argon2id (RFC 9106) configured with `memory_cost=65536` (64 MB), `time_cost=4`, `parallelism=2`, and 256-bit unique salts.
- **Tamper-Evident Audit Chain**: Security events are linked via backward cryptographic pointers:
  $$\text{Hash}_n = \text{HMAC-SHA256}(\text{Hash}_{n-1} \parallel \text{Event} \parallel \text{Actor} \parallel \text{Timestamp})$$
- **Zero Git Secrets Policy**: The `.gitignore` file strictly blocks all credential stores (`*.enc`), secret configuration files (`config.secure.php`), and private keys.

---

## Running the Interactive Control Center & Simulator

To run the interactive React/D3 architecture cockpit, real-time traffic simulator, and user management console locally:

```bash
# Install dependencies
npm install

# Run unit tests (includes RBAC & crypto tests)
npm test

# Start the local development server on port 3000
npm run dev
```

Open `http://localhost:3000` in your browser. Use the sidebar to toggle between **Developer View** and **Executive View**, test the **Data Plane Simulator**, stress-test with the **L7 DDoS Testbench**, or manage operators in the **User Management & RBAC** tab.

---

## Security & Responsible Disclosure

If you identify a security defect or potential vulnerability in NeuralWAF:
- **Do not open a public GitHub issue.**
- Email details directly to the lead architect: **`engr.buru@gmail.com`**.
- Encrypted reports are welcome via PGP. Initial response guaranteed within 24 hours.

See [.github/SECURITY.md](.github/SECURITY.md) for full vulnerability handling terms.

---

## License & Attribution

Distributed under the **MIT License**. See [LICENSE](LICENSE) for details.

Developed and maintained by **BuruOps** (`engr.buru@gmail.com`).  
Contributions, issues, and feature proposals are welcome via pull requests!
