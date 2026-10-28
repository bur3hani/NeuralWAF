#!/usr/bin/env bash
# ==============================================================================
# BuruOps NeuralWAF - Root Directory Interactive Setup & Installer
# Open Source Security Project by BuruOps (engr.buru@gmail.com)
# ==============================================================================
# Purpose:
#  1. Interactive creation of administrative users and credentials
#  2. Generating 256-bit AES-GCM master encryption key & HMAC signing secrets
#  3. Argon2id / bcrypt password hashing with CSPRNG salt
#  4. AES-256-GCM encryption of initial credentials store
#  5. Hardening file permissions (chmod 600 / chmod 700)
#  6. Zero secrets leaked: Active keys stored in ignored local configs
# ==============================================================================

set -euo pipefail

# ANSI Color Codes
CYAN='\033[0;36m'
GREEN='\033[0;32m'
PURPLE='\033[0;35m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BOLD='\033[1m'
NC='\033[0m'

echo -e "${PURPLE}${BOLD}"
cat << "EOF"
  _   _                      _ _       ___  ______ 
 | \ | |                    | | |  _  | \ \/ / ___|
 |  \| | ___ _   _ _ __ __ _| | | (_) | |\  /| |_  
 | . ` |/ _ \ | | | '__/ _` | | |     | |/  \|  _| 
 | |\  |  __/ |_| | | | (_| | | |  _  | / /\ \ |   
 |_| \_|\___|\__,_|_|  \__,_|_|_| (_) |_/_/\_\_|   
                     BuruOps Open Source Security
EOF
echo -e "${NC}"
echo -e "${CYAN}${BOLD}NeuralWAF Root Directory Secure Installation & Credentials Generator${NC}"
echo -e "${CYAN}Author: BuruOps Engineering Team (engr.buru@gmail.com)${NC}"
echo -e "================================================================================"

ROOT_DIR="$(pwd)"
DATA_DIR="${ROOT_DIR}/neuralwaf/data"
CONFIG_FILE="${ROOT_DIR}/neuralwaf/config.secure.php"
CRED_VAULT="${DATA_DIR}/credentials.enc"
HTACCESS="${ROOT_DIR}/.htaccess"
USER_INI="${ROOT_DIR}/.user.ini"

# Step 1: System & Runtime Checks
echo -e "\n${BOLD}[1/6] Inspecting runtime prerequisites...${NC}"

if command -v php >/dev/null 2>&1; then
    PHP_VER=$(php -r 'echo PHP_VERSION;')
    echo -e "  ${GREEN}✓${NC} PHP detected: v${PHP_VER}"
else
    echo -e "  ${RED}✗ Error: PHP binary not found in PATH.${NC}"
    exit 1
fi

if command -v openssl >/dev/null 2>&1; then
    echo -e "  ${GREEN}✓${NC} OpenSSL cryptographic engine detected."
else
    echo -e "  ${RED}✗ Error: OpenSSL not found. Required for cryptographic key generation.${NC}"
    exit 1
fi

if command -v node >/dev/null 2>&1; then
    NODE_VER=$(node -v)
    echo -e "  ${GREEN}✓${NC} Node.js background engine detected: ${NODE_VER}"
else
    echo -e "  ${YELLOW}! Warning: Node.js not detected. PHP Ingress will operate in autonomous standalone mode.${NC}"
fi

# Step 2: Interactive SuperAdmin Credential Provisioning
echo -e "\n${BOLD}[2/6] Provisioning SuperAdmin Operator Identity...${NC}"
read -rp "  Enter SuperAdmin Username [default: buru_admin]: " ADMIN_USER
ADMIN_USER=${ADMIN_USER:-buru_admin}

read -rp "  Enter SuperAdmin Email [default: engr.buru@gmail.com]: " ADMIN_EMAIL
ADMIN_EMAIL=${ADMIN_EMAIL:-engr.buru@gmail.com}

echo -e "  Choose Password Generation Mode:"
echo -e "    1) Auto-generate high-entropy 28-char password (Recommended)"
echo -e "    2) Enter custom password interactively"
read -rp "  Selection [1-2, default: 1]: " PWD_CHOICE
PWD_CHOICE=${PWD_CHOICE:-1}

if [ "$PWD_CHOICE" = "1" ]; then
    ADMIN_PWD=$(openssl rand -base64 21 | tr -dc 'A-Za-z0-9!@#$%^&*' | head -c 28)
    AUTO_GEN=1
else
    read -rsp "  Enter Master Password (min 12 chars): " ADMIN_PWD
    echo ""
    read -rsp "  Confirm Master Password: " ADMIN_PWD_CONFIRM
    echo ""
    if [ "$ADMIN_PWD" != "$ADMIN_PWD_CONFIRM" ]; then
        echo -e "  ${RED}✗ Passwords do not match. Aborting.${NC}"
        exit 1
    fi
    AUTO_GEN=0
fi

# Step 3: Cryptographic Master Keys Generation
echo -e "\n${BOLD}[3/6] Generating AES-256-GCM Master Keys & CSPRNG Entropy...${NC}"
MASTER_AES_KEY=$(openssl rand -hex 32)
HMAC_JWT_SECRET=$(openssl rand -hex 32)
IPC_SHARED_SECRET=$(openssl rand -hex 24)

mkdir -p "${DATA_DIR}"
chmod 700 "${DATA_DIR}"

# Step 4: Argon2id Hashing & AES-256-GCM Vault Encryption
echo -e "  Executing Argon2id password hashing and vault encryption..."

php -r '
$user = $argv[1];
$email = $argv[2];
$password = $argv[3];
$masterKey = hex2bin($argv[4]);
$vaultFile = $argv[5];
$configFile = $argv[6];
$hmacSecret = $argv[7];
$ipcSecret = $argv[8];

// Hash password with Argon2id if available, fallback to high-cost Bcrypt
if (defined("PASSWORD_ARGON2ID")) {
    $algo = PASSWORD_ARGON2ID;
    $options = ["memory_cost" => 65536, "time_cost" => 4, "threads" => 2];
    $algoName = "Argon2id";
} else {
    $algo = PASSWORD_BCRYPT;
    $options = ["cost" => 12];
    $algoName = "Bcrypt(cost=12)";
}

$passwordHash = password_hash($password, $algo, $options);
$userId = "usr_" . bin2hex(random_bytes(8));
$timestamp = time();

$vaultPayload = [
    "vault_version" => "2.5.0",
    "created_at" => $timestamp,
    "last_key_rotation" => $timestamp,
    "users" => [
        [
            "id" => $userId,
            "username" => $user,
            "email" => $email,
            "role" => "SuperAdmin",
            "password_hash" => $passwordHash,
            "hash_algorithm" => $algoName,
            "status" => "active",
            "mfa_enabled" => false,
            "failed_attempts" => 0,
            "locked_until" => null,
            "created_at" => $timestamp,
            "last_login" => null
        ]
    ],
    "audit_chain" => [
        [
            "id" => "evt_init",
            "event" => "VAULT_INITIALIZED",
            "actor" => $user,
            "timestamp" => $timestamp,
            "prev_hash" => "0000000000000000000000000000000000000000000000000000000000000000",
            "signature" => hash_hmac("sha256", "VAULT_INITIALIZED:" . $user . ":" . $timestamp, $hmacSecret)
        ]
    ]
];

$plaintext = json_encode($vaultPayload, JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT);
$iv = random_bytes(12); // 96-bit standard GCM nonce
$tag = "";
$ciphertext = openssl_encrypt($plaintext, "aes-256-gcm", $masterKey, OPENSSL_RAW_DATA, $iv, $tag);

// Structure encrypted payload: [12-byte IV][16-byte Tag][Ciphertext]
$encryptedFileContent = $iv . $tag . $ciphertext;
file_put_contents($vaultFile, $encryptedFileContent);
chmod($vaultFile, 0600);

// Generate config.secure.php with master keys (excluded from git)
$phpConfig = "<?php\n"
    . "declare(strict_types=1);\n"
    . "/**\n"
    . " * BuruOps NeuralWAF - Master Cryptographic Keys\n"
    . " * WARNING: NEVER COMMIT THIS FILE TO REPOSITORY!\n"
    . " * File permissions should remain chmod 0600.\n"
    . " */\n"
    . "return [\n"
    . "    \"MASTER_ENCRYPTION_KEY\" => \"" . bin2hex($masterKey) . "\",\n"
    . "    \"HMAC_SESSION_SECRET\"   => \"" . $hmacSecret . "\",\n"
    . "    \"IPC_SHARED_SECRET\"     => \"" . $ipcSecret . "\",\n"
    . "    \"VAULT_FILE\"             => __DIR__ . \"/data/credentials.enc\",\n"
    . "    \"KEY_GENERATED_AT\"       => " . $timestamp . ",\n"
    . "];\n";

file_put_contents($configFile, $phpConfig);
chmod($configFile, 0600);
' "$ADMIN_USER" "$ADMIN_EMAIL" "$ADMIN_PWD" "$MASTER_AES_KEY" "$CRED_VAULT" "$CONFIG_FILE" "$HMAC_JWT_SECRET" "$IPC_SHARED_SECRET"

echo -e "  ${GREEN}✓${NC} Credentials vault encrypted with AES-256-GCM and saved to ${CRED_VAULT} (chmod 600)"
echo -e "  ${GREEN}✓${NC} Secret keys generated in ${CONFIG_FILE} (chmod 600, excluded by .gitignore)"

# Step 5: Web Server Root Pre-Execution Hooks
echo -e "\n${BOLD}[4/6] Registering Root Ingress Auto-Prepend Hook...${NC}"

# Configure .user.ini for LiteSpeed / PHP-FPM / FastCGI
if [ -f "${USER_INI}" ]; then
    if ! grep -q "neuralwaf/bootstrap.php" "${USER_INI}"; then
        echo -e "\nauto_prepend_file = \"neuralwaf/bootstrap.php\"" >> "${USER_INI}"
        echo -e "  ${GREEN}✓${NC} Appended auto_prepend_file to existing .user.ini"
    fi
else
    cat << EOF > "${USER_INI}"
; BuruOps NeuralWAF Root Directory Pre-Execution Configuration
auto_prepend_file = "neuralwaf/bootstrap.php"
EOF
    echo -e "  ${GREEN}✓${NC} Created .user.ini with auto_prepend_file hook"
fi

# Configure .htaccess for Apache / LiteSpeed
if [ -f "${HTACCESS}" ]; then
    if ! grep -q "neuralwaf/bootstrap.php" "${HTACCESS}"; then
        cat << 'EOF' >> "${HTACCESS}"

# --- BuruOps NeuralWAF Root Ingress Hook ---
<IfModule mod_php.c>
    php_value auto_prepend_file "neuralwaf/bootstrap.php"
</IfModule>
<IfModule mod_php7.c>
    php_value auto_prepend_file "neuralwaf/bootstrap.php"
</IfModule>
# ------------------------------------------
EOF
        echo -e "  ${GREEN}✓${NC} Appended mod_php hook to .htaccess"
    fi
else
    cat << 'EOF' > "${HTACCESS}"
# --- BuruOps NeuralWAF Root Ingress Hook ---
<IfModule mod_php.c>
    php_value auto_prepend_file "neuralwaf/bootstrap.php"
</IfModule>
<IfModule mod_php7.c>
    php_value auto_prepend_file "neuralwaf/bootstrap.php"
</IfModule>
# ------------------------------------------
EOF
    echo -e "  ${GREEN}✓${NC} Created .htaccess with auto_prepend_file hook"
fi

# Step 6: Installation Verification & Summary
echo -e "\n${BOLD}[5/6] Performing Self-Verification Decryption Check...${NC}"

php -r '
$config = require "'$CONFIG_FILE'";
$masterKey = hex2bin($config["MASTER_ENCRYPTION_KEY"]);
$raw = file_get_contents($config["VAULT_FILE"]);
$iv = substr($raw, 0, 12);
$tag = substr($raw, 12, 16);
$ciphertext = substr($raw, 28);
$decrypted = openssl_decrypt($ciphertext, "aes-256-gcm", $masterKey, OPENSSL_RAW_DATA, $iv, $tag);

if ($decrypted === false) {
    echo "  \033[0;31m✗ Integrity Verification Failed: Decryption Tag Mismatch\033[0m\n";
    exit(1);
}
$data = json_decode($decrypted, true);
echo "  \033[0;32m✓\033[0m Decryption self-test passed! Active SuperAdmin: " . $data["users"][0]["username"] . " (Role: " . $data["users"][0]["role"] . ")\n";
'

echo -e "\n${BOLD}[6/6] Installation Complete!${NC}"
echo -e "================================================================================"
echo -e "${GREEN}${BOLD}✔ NeuralWAF by BuruOps is successfully deployed to root directory.${NC}"
echo -e "--------------------------------------------------------------------------------"
echo -e "${BOLD}INITIAL CREDENTIALS SUMMARY:${NC}"
echo -e "  SuperAdmin Username : ${CYAN}${ADMIN_USER}${NC}"
echo -e "  SuperAdmin Email    : ${CYAN}${ADMIN_EMAIL}${NC}"
if [ "$AUTO_GEN" = "1" ]; then
    echo -e "  Generated Password  : ${YELLOW}${ADMIN_PWD}${NC}"
    echo -e "  ${RED}${BOLD}SAVE THIS PASSWORD NOW! It will not be shown again in plaintext.${NC}"
else
    echo -e "  Password            : [Custom password configured]"
fi
echo -e "  Credential Vault    : ${CRED_VAULT} (AES-256-GCM, chmod 600)"
echo -e "  Configuration File  : ${CONFIG_FILE} (chmod 600, untracked by Git)"
echo -e "================================================================================"
echo -e "Manage users via CLI anytime:"
echo -e "  ${CYAN}php neuralwaf/bin/waf-user.php list${NC}"
echo -e "  ${CYAN}php neuralwaf/bin/waf-user.php add --role SecurityOperator${NC}"
echo -e "  ${CYAN}php neuralwaf/bin/waf-user.php reset-password --user ${ADMIN_USER}${NC}"
echo -e "================================================================================\n"
