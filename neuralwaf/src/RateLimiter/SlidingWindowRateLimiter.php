<?php
/**
 * BuruOps NeuralWAF - Atomic Sliding Window Rate Limiter (PHP 7.4 - 8.3+)
 * Open Source Security by BuruOps (engr.buru@gmail.com)
 *
 * Enforces per-IP volumetric sliding-window rate limiting using atomic file locks.
 * Prevents L7 HTTP flood DDoS and brute force credential attacks with zero external daemons.
 */

declare(strict_types=1);

namespace NeuralWaf\RateLimiter;

class SlidingWindowRateLimiter
{
    private string $storageDir;
    private int $maxRequests;
    private int $windowSeconds;

    public function __construct(
        string $storageDir = __DIR__ . '/../../data/ratelimit',
        int $maxRequests = 120,
        int $windowSeconds = 60
    ) {
        $this->storageDir = rtrim($storageDir, '/');
        $this->maxRequests = $maxRequests;
        $this->windowSeconds = $windowSeconds;

        if (!is_dir($this->storageDir)) {
            @mkdir($this->storageDir, 0700, true);
        }
    }

    /**
     * Check if a client IP is allowed or should be dropped.
     *
     * @param string $clientIp
     * @return array ['allowed' => bool, 'current_count' => int, 'limit' => int, 'retry_after' => int]
     */
    public function check(string $clientIp): array
    {
        $sanitizedIp = preg_replace('/[^a-zA-Z0-9_\-]/', '_', $clientIp);
        $filePath = "{$this->storageDir}/rl_{$sanitizedIp}.lock";
        $now = time();
        $cutoff = $now - $this->windowSeconds;

        $fp = @fopen($filePath, 'c+');
        if (!$fp) {
            // Fail open if filesystem is read-only
            return ['allowed' => true, 'current_count' => 1, 'limit' => $this->maxRequests, 'retry_after' => 0];
        }

        // Acquire exclusive lock to prevent race conditions during high concurrency
        flock($fp, LOCK_EX);

        $contents = stream_get_contents($fp);
        $timestamps = [];

        if (!empty($contents)) {
            $raw = explode(',', trim($contents));
            foreach ($raw as $ts) {
                $t = (int)$ts;
                if ($t > $cutoff) {
                    $timestamps[] = $t;
                }
            }
        }

        $currentCount = count($timestamps);
        $allowed = $currentCount < $this->maxRequests;

        if ($allowed) {
            $timestamps[] = $now;
            ftruncate($fp, 0);
            rewind($fp);
            fwrite($fp, implode(',', $timestamps));
        }

        fflush($fp);
        flock($fp, LOCK_UN);
        fclose($fp);

        return [
            'allowed' => $allowed,
            'current_count' => $allowed ? ($currentCount + 1) : $currentCount,
            'limit' => $this->maxRequests,
            'retry_after' => $allowed ? 0 : ($timestamps[0] + $this->windowSeconds - $now),
        ];
    }
}
