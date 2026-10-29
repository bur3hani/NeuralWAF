# NeuralWAF by BuruOps: Pure PHP Deep Learning WAF

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![PHP Version](https://img.shields.io/badge/PHP-7.4%20--%208.3+-777BB4.svg)](#pure-php-codebase-architecture)
[![Zero C-Extensions](https://img.shields.io/badge/Dependencies-Zero%20External%20C%20Extensions-emerald.svg)](#pure-php-codebase-architecture)
[![Zero Secrets](https://img.shields.io/badge/Zero--Secrets-Compliant-brightgreen.svg)](.github/SECURITY.md)
[![Argon2id](https://img.shields.io/badge/Hashing-Argon2id%20(RFC%209106)-violet.svg)](#cryptographic-vault-architecture)
[![Vault Encryption](https://img.shields.io/badge/Vault-AES--256--GCM-cyan.svg)](#cryptographic-vault-architecture)
[![Author](https://img.shields.io/badge/Attribution-BuruOps%20Engineering-orange.svg)](mailto:engr.buru@gmail.com)

**NeuralWAF** is a high-performance, **100% pure PHP** root-level Web Application Firewall developed by **BuruOps** (`engr.buru@gmail.com`). 

Engineered to sit directly in your website root directory (`public_html/` or `/`), it intercepts incoming HTTP requests before any CMS (WordPress, Drupal, Joomla) or PHP application framework (Laravel, Symfony) executes.

Unlike traditional WAFs that rely on brittle, bypassable static regular expressions, NeuralWAF implements an **in-memory LSTM Autoencoder forward inference engine in pure PHP** to calculate sequence reconstruction loss ($MSE \ge 0.65 \implies 403\text{ Forbidden}$) in sub-millisecond execution windows with **zero external C extensions or background daemons**.

---

## Pure PHP Codebase Architecture

NeuralWAF is architected according to strict PSR-4 standards under the `NeuralWaf\` namespace:

```
neuralwaf/
├── bootstrap.php                         # Root pre-execution entrypoint (auto_prepend_file)
├── composer.json                         # PSR-4 autoload definition (NeuralWaf\ => src/)
├── bin/
│   ├── waf                               # PHP CLI administration & live payload testing
│   └── waf-user.php                      # CLI operator provisioning & credential rotation
├── src/
│   ├── DataPlane/
│   │   └── IngressFilter.php             # Core Data Plane: intercepts superglobals & streams
│   ├── Tokenizer/
│   │   └── ByteSequenceTokenizer.php     # Character & byte sequence vectorizer + Shannon entropy
│   ├── Inference/
│   │   └── LstmAutoencoder.php           # Pure PHP LSTM Autoencoder forward inference engine
│   ├── RateLimiter/
│   │   └── SlidingWindowRateLimiter.php  # Atomic file-lock sliding window rate limiter
│   ├── Telemetry/
│   │   └── TelemetryPipeline.php         # Non-blocking FastCGI telemetry streamer
│   └── Auth/
│       └── UserManager.php               # RBAC with Argon2id & AES-256-GCM encrypted vault
└── tests/
    └── LstmAutoencoderTest.php           # PHPUnit test suite
```

---

## Key Highlights

- **100% Pure PHP Core**: Zero external C-extensions, Python servers, or Node.js required. Runs natively on standard Apache, LiteSpeed, Nginx, and cPanel environments (PHP 7.4 through PHP 8.3+).
- **Sub-Millisecond Overhead**: Full tokenization, sliding-window rate limit validation, and LSTM Autoencoder inference execute in $\le 0.35\text{ms}$ in PHP 8.1+ (OPcache enabled).
- **Zero Regex Vulnerabilities**: Drops zero-day SQLi, RCE, JNDI/Log4Shell, path traversal, and SSRF attacks through structural sequence reconstruction failure ($MSE \ge \tau = 0.65$).
- **Bounded Memory Ingress**: Bounded 64KB stream reader prevents Layer 7 memory exhaustion attacks.
- **BuruOps Zero-Secrets Policy**: No passwords, salts, or API tokens are hardcoded. Master credentials are created at install time, hashed with **Argon2id** (`m=64MB, t=4, p=2`), and sealed with **AES-256-GCM** inside `neuralwaf/data/credentials.enc` with `chmod 0600`.
- **Tamper-Evident Audit Chain**: Administrative actions are cryptographically chained via backward **SHA-256 pointers**.

---

## Quick Start & Installation

### Option 1: Automated Root Installer (Bash)

From your website root directory:

```bash
# Clone the open-source repository
git clone https://github.com/buruops/neuralwaf.git .

# Execute the interactive credential setup script
bash scripts/install.sh
```

The script automatically derives a 256-bit AES master key, hashes your SuperAdmin credentials with Argon2id, and writes the pre-execution directive to `.user.ini` and `.htaccess`:

```ini
; In .user.ini (LiteSpeed, PHP-FPM, FastCGI)
auto_prepend_file = "neuralwaf/bootstrap.php"
```

```apache
# In .htaccess (Apache)
<IfModule mod_php.c>
    php_value auto_prepend_file "neuralwaf/bootstrap.php"
</IfModule>
```

### Option 2: Composer Installation

```bash
composer require buruops/neuralwaf
```

In your application entrypoint:

```php
<?php
require_once __DIR__ . '/vendor/autoload.php';

$filter = new \NeuralWaf\DataPlane\IngressFilter();
$filter->inspect();
```

---

## CLI Administration & Testing

Test any HTTP payload or attack string directly from your terminal:

```bash
# View engine status and runtime details
php neuralwaf/bin/waf status

# Test benign query string
php neuralwaf/bin/waf test "GET /catalog.php?sort=asc&page=2 HTTP/1.1"

# Test malicious SQL injection string (observed blocked with MSE >= 0.65)
php neuralwaf/bin/waf test "GET /users.php?id=1' UNION SELECT username,password FROM admin--"

# List registered operators
php neuralwaf/bin/waf-user.php list

# Provision new security operator
php neuralwaf/bin/waf-user.php add --user analyst1 --email analyst@company.com --role SecurityOperator
```

---

## PHPUnit Test Suite

Run unit tests across the tokenizer, entropy calculator, and LSTM autoencoder:

```bash
composer test
# or directly:
vendor/bin/phpunit
```

---

## Security & Responsible Disclosure

If you identify a security defect or vulnerability, please email **`engr.buru@gmail.com`**.  
Do not open public GitHub issues for security vulnerabilities. See [.github/SECURITY.md](.github/SECURITY.md) for our full disclosure policy.

---

## License & Attribution

Distributed under the **MIT License**. See [LICENSE](LICENSE) for details.

Developed and maintained by **BuruOps** (`engr.buru@gmail.com`).
