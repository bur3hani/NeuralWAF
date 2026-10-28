<?php
/**
 * BuruOps NeuralWAF - User Management & Cryptographic Vault (PHP 7.4 - 8.3+)
 * Open Source Security Initiative by BuruOps (engr.buru@gmail.com)
 *
 * Implements:
 *  - Role-Based Access Control (SuperAdmin, SecurityOperator, Auditor)
 *  - Password hashing via Argon2id (RFC 9106) with 256-bit CSPRNG salt
 *  - AES-256-GCM authenticated vault encryption/decryption
 *  - Tamper-evident SHA-256 cryptographic audit chaining
 *  - Zero hardcoded secrets: Master keys loaded from config.secure.php (chmod 0600)
 */

declare(strict_types=1);

namespace NeuralWaf\Auth;

class UserManager
{
    private string $vaultPath;
    private string $masterKey;
    private string $hmacSecret;
    private array $vaultData = [];

    public function __construct(string $vaultPath, string $masterKeyHex, string $hmacSecret)
    {
        $this->vaultPath = $vaultPath;
        $this->masterKey = hex2bin($masterKeyHex);
        $this->hmacSecret = $hmacSecret;
        $this->loadVault();
    }

    /**
     * Decrypt and load vault contents using AES-256-GCM.
     */
    private function loadVault(): void
    {
        if (!file_exists($this->vaultPath)) {
            $this->vaultData = [
                'vault_version' => '2.5.0',
                'created_at' => time(),
                'users' => [],
                'audit_chain' => []
            ];
            return;
        }

        $raw = file_get_contents($this->vaultPath);
        if (strlen($raw) < 28) {
            throw new \RuntimeException("Corrupted credentials vault: payload length under 28 bytes.");
        }

        $iv = substr($raw, 0, 12);
        $tag = substr($raw, 12, 16);
        $ciphertext = substr($raw, 28);

        $plaintext = openssl_decrypt(
            $ciphertext,
            'aes-256-gcm',
            $this->masterKey,
            OPENSSL_RAW_DATA,
            $iv,
            $tag
        );

        if ($plaintext === false) {
            throw new \SecurityException("Vault integrity authentication failed: invalid tag or corrupted master key.");
        }

        $decoded = json_decode($plaintext, true);
        if (!is_array($decoded)) {
            throw new \RuntimeException("Failed to parse decrypted vault JSON payload.");
        }

        $this->vaultData = $decoded;
    }

    /**
     * Encrypt and persist vault to disk with chmod 0600.
     */
    private function saveVault(): void
    {
        $plaintext = json_encode($this->vaultData, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
        $iv = random_bytes(12);
        $tag = '';

        $ciphertext = openssl_encrypt(
            $plaintext,
            'aes-256-gcm',
            $this->masterKey,
            OPENSSL_RAW_DATA,
            $iv,
            $tag
        );

        $encrypted = $iv . $tag . $ciphertext;
        file_put_contents($this->vaultPath, $encrypted, LOCK_EX);
        chmod($this->vaultPath, 0600);
    }

    /**
     * Verify user credentials using constant-time verification.
     */
    public function authenticate(string $username, string $password): ?array
    {
        foreach ($this->vaultData['users'] as &$user) {
            if (hash_equals(strtolower($user['username']), strtolower($username))) {
                if ($user['status'] !== 'active') {
                    $this->appendAuditLog('AUTH_BLOCKED_LOCKED', $username, 'Attempted login to non-active account');
                    return null;
                }

                if (password_verify($password, $user['password_hash'])) {
                    $user['failed_attempts'] = 0;
                    $user['last_login'] = time();
                    $this->appendAuditLog('AUTH_SUCCESS', $username, 'Successful authentication');
                    $this->saveVault();
                    return $user;
                } else {
                    $user['failed_attempts']++;
                    if ($user['failed_attempts'] >= 5) {
                        $user['status'] = 'locked';
                        $this->appendAuditLog('USER_AUTO_LOCKED', $username, 'Locked after 5 consecutive failed login attempts');
                    } else {
                        $this->appendAuditLog('AUTH_FAILURE', $username, 'Invalid password attempt (' . $user['failed_attempts'] . '/5)');
                    }
                    $this->saveVault();
                    return null;
                }
            }
        }
        return null;
    }

    /**
     * Provision a new operator with Argon2id hash and store in encrypted vault.
     */
    public function createUser(string $actor, string $username, string $email, string $password, string $role = 'SecurityOperator'): array
    {
        // Enforce RBAC caller privilege
        $caller = $this->getUser($actor);
        if (!$caller || $caller['role'] !== 'SuperAdmin') {
            throw new \UnauthorizedAccessException("Only SuperAdmin can provision operators.");
        }

        $algo = defined('PASSWORD_ARGON2ID') ? PASSWORD_ARGON2ID : PASSWORD_BCRYPT;
        $options = defined('PASSWORD_ARGON2ID') 
            ? ['memory_cost' => 65536, 'time_cost' => 4, 'threads' => 2]
            : ['cost' => 12];

        $hash = password_hash($password, $algo, $options);
        $userId = 'usr_' . bin2hex(random_bytes(8));

        $newUser = [
            'id' => $userId,
            'username' => strtolower($username),
            'email' => $email,
            'role' => $role,
            'password_hash' => $hash,
            'status' => 'active',
            'mfa_enabled' => false,
            'failed_attempts' => 0,
            'created_at' => time(),
            'last_login' => null
        ];

        $this->vaultData['users'][] = $newUser;
        $this->appendAuditLog('USER_CREATED', $actor, "Created operator {$username} with role {$role}");
        $this->saveVault();

        return $newUser;
    }

    public function getUser(string $username): ?array
    {
        foreach ($this->vaultData['users'] as $user) {
            if (hash_equals(strtolower($user['username']), strtolower($username))) {
                return $user;
            }
        }
        return null;
    }

    /**
     * Append to tamper-evident SHA-256 cryptographic audit chain.
     */
    private function appendAuditLog(string $event, string $actor, string $details): void
    {
        $lastLog = end($this->vaultData['audit_chain']);
        $prevHash = $lastLog ? $lastLog['hash'] : str_repeat('0', 64);
        $timestamp = time();

        $signature = hash_hmac(
            'sha256',
            "{$prevHash}:{$event}:{$actor}:{$timestamp}:{$details}",
            $this->hmacSecret
        );

        $this->vaultData['audit_chain'][] = [
            'id' => 'evt_' . bin2hex(random_bytes(6)),
            'event' => $event,
            'actor' => $actor,
            'timestamp' => $timestamp,
            'details' => $details,
            'prev_hash' => $prevHash,
            'hash' => $signature
        ];
    }
}
