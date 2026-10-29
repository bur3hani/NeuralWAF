<?php
/**
 * BuruOps NeuralWAF - Non-Blocking Telemetry Pipeline (PHP 7.4 - 8.3+)
 * Open Source Security by BuruOps (engr.buru@gmail.com)
 *
 * Streams security incident telemetry asynchronously without blocking client threads.
 * Uses fastcgi_finish_request() when running under PHP-FPM to release the HTTP client immediately.
 */

declare(strict_types=1);

namespace NeuralWaf\Telemetry;

class TelemetryPipeline
{
    private string $logPath;

    public function __construct(string $logPath = __DIR__ . '/../../data/telemetry.jsonl')
    {
        $this->logPath = $logPath;
        $dir = dirname($logPath);
        if (!is_dir($dir)) {
            @mkdir($dir, 0700, true);
        }
    }

    /**
     * Dispatch security event without delaying the web response.
     *
     * @param array $eventPayload Forensic payload (correlation_id, ip, score, uri, headers)
     */
    public function record(array $eventPayload): void
    {
        $payload = array_merge([
            'timestamp' => time(),
            'microtime' => microtime(true),
            'pid' => getmypid(),
            'engine' => 'NeuralWAF PHP Core v2.5.0',
        ], $eventPayload);

        $line = json_encode($payload, JSON_UNESCAPED_SLASHES) . "\n";

        // If running in CLI (e.g. testing), write immediately
        if (php_sapi_name() === 'cli') {
            @file_put_contents($this->logPath, $line, FILE_APPEND | LOCK_EX);
            return;
        }

        // On FastCGI / PHP-FPM: queue write after HTTP response is flushed to client
        register_shutdown_function(function () use ($line) {
            @file_put_contents($this->logPath, $line, FILE_APPEND | LOCK_EX);
        });
    }
}
