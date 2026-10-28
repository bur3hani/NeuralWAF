#!/usr/bin/env php
<?php
/**
 * BuruOps NeuralWAF CLI User Management Utility
 * Attribution: BuruOps Engineering Team (engr.buru@gmail.com)
 *
 * Usage:
 *   php neuralwaf/bin/waf-user.php list
 *   php neuralwaf/bin/waf-user.php add --user <username> --email <email> --role <role>
 *   php neuralwaf/bin/waf-user.php reset-password --user <username>
 */

declare(strict_types=1);

require_once __DIR__ . '/../auth/UserManager.php';

$configFile = __DIR__ . '/../config.secure.php';
if (!file_exists($configFile)) {
    echo "\033[0;31mError: config.secure.php not found. Run 'bash scripts/install.sh' first.\033[0m\n";
    exit(1);
}

$config = require $configFile;
$userManager = new \NeuralWaf\Auth\UserManager(
    $config['VAULT_FILE'],
    $config['MASTER_ENCRYPTION_KEY'],
    $config['HMAC_SESSION_SECRET']
);

$action = $argv[1] ?? 'help';

switch ($action) {
    case 'list':
        echo "=== BuruOps NeuralWAF Registered Operators ===\n";
        // list users
        break;
    case 'add':
        echo "=== Provision New Operator ===\n";
        break;
    default:
        echo "Usage: php neuralwaf/bin/waf-user.php [list|add|reset-password]\n";
        exit(0);
}
