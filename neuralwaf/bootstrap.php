<?php
/**
 * BuruOps NeuralWAF - Root Auto-Prepend Hook (PHP 7.4 - 8.3+)
 * Open Source Security by BuruOps (engr.buru@gmail.com)
 *
 * Deployment: Installed in the website root directory (public_html/neuralwaf/bootstrap.php).
 * Trigger: Automatically invoked via .user.ini or .htaccess before index.php or any CMS executes.
 *
 * Zero external extensions or dependencies required.
 */

declare(strict_types=1);

namespace NeuralWaf;

if (defined('NEURALWAF_BOOTSTRAPPED')) {
    return;
}
define('NEURALWAF_BOOTSTRAPPED', true);

// Skip CLI execution (cron jobs, composer, artisan, phpunit) unless explicitly testing WAF
if (php_sapi_name() === 'cli' && empty(getenv('NEURALWAF_TEST_MODE'))) {
    return;
}

// Lightweight PSR-4 autoloader for standalone root installation without Composer
spl_autoload_register(function (string $class): void {
    $prefix = 'NeuralWaf\\';
    $baseDir = __DIR__ . '/src/';

    $len = strlen($prefix);
    if (strncmp($prefix, $class, $len) !== 0) {
        return;
    }

    $relativeClass = substr($class, $len);
    $file = $baseDir . str_replace('\\', '/', $relativeClass) . '.php';

    if (file_exists($file)) {
        require_once $file;
    }
});

// Execute the Root Ingress Filter
try {
    $filter = new \NeuralWaf\DataPlane\IngressFilter();
    $filter->inspect();
} catch (\Throwable $e) {
    // Fail-Safe policy: Log failure to PHP error log and allow legitimate traffic to continue
    error_log("[NeuralWAF Error] Ingress filter exception: " . $e->getMessage());
}
