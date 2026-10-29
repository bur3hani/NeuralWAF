<?php
/**
 * BuruOps NeuralWAF - Root Ingress Filter (PHP 7.4 - 8.3+)
 * Open Source Security by BuruOps (engr.buru@gmail.com)
 *
 * Core Data Plane interceptor. Evaluates HTTP traffic at the root boundary
 * before any framework or CMS code executes.
 */

declare(strict_types=1);

namespace NeuralWaf\DataPlane;

use NeuralWaf\Tokenizer\ByteSequenceTokenizer;
use NeuralWaf\Inference\LstmAutoencoder;
use NeuralWaf\RateLimiter\SlidingWindowRateLimiter;
use NeuralWaf\Telemetry\TelemetryPipeline;

class IngressFilter
{
    public const MAX_BODY_BYTES = 65536; // 64KB strict bounded memory cap

    private ByteSequenceTokenizer $tokenizer;
    private LstmAutoencoder $inferenceEngine;
    private SlidingWindowRateLimiter $rateLimiter;
    private TelemetryPipeline $telemetry;

    public function __construct(
        ?ByteSequenceTokenizer $tokenizer = null,
        ?LstmAutoencoder $inferenceEngine = null,
        ?SlidingWindowRateLimiter $rateLimiter = null,
        ?TelemetryPipeline $telemetry = null
    ) {
        $this->tokenizer = $tokenizer ?? new ByteSequenceTokenizer();
        $this->inferenceEngine = $inferenceEngine ?? new LstmAutoencoder();
        $this->rateLimiter = $rateLimiter ?? new SlidingWindowRateLimiter();
        $this->telemetry = $telemetry ?? new TelemetryPipeline();
    }

    /**
     * Inspect active HTTP request from superglobals and input stream.
     * Drops anomalous or rate-exceeded requests immediately.
     */
    public function inspect(): void
    {
        $clientIp = $this->getClientIp();

        // 1. Sliding Window Rate Limiting Check
        $rlResult = $this->rateLimiter->check($clientIp);
        if (!$rlResult['allowed']) {
            $this->blockRequest(
                429,
                'RATE_LIMIT_EXCEEDED',
                $clientIp,
                0.99,
                ['retry_after' => $rlResult['retry_after']]
            );
            return;
        }

        // 2. Extract and Normalize Raw HTTP Ingress Stream
        $rawStream = $this->extractNormalizedStream();

        // 3. Tokenize Byte Stream into High-Dimensional Vector
        $tokens = $this->tokenizer->tokenize($rawStream);

        // 4. LSTM Autoencoder Forward Evaluation
        $eval = $this->inferenceEngine->evaluate($tokens);

        // 5. Decision Gate: Drop out-of-distribution exploits (MSE >= Threshold)
        if ($eval['is_anomaly']) {
            $this->blockRequest(
                403,
                'DEEP_LEARNING_ANOMALY_DETECTED',
                $clientIp,
                $eval['anomaly_score'],
                [
                    'reconstruction_mse' => $eval['reconstruction_mse'],
                    'threshold' => $eval['threshold'],
                    'stream_snippet' => substr($rawStream, 0, 160),
                ]
            );
            return;
        }

        // Benign traffic passes through seamlessly to CMS / application
        header('X-NeuralWAF-Status: Verified-Benign');
        header('X-NeuralWAF-Latency: ' . $eval['inference_time_ms'] . 'ms');
    }

    /**
     * Extract normalized string representation of HTTP request for tokenization.
     */
    public function extractNormalizedStream(): string
    {
        $method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
        $uri = $_SERVER['REQUEST_URI'] ?? '/';
        $protocol = $_SERVER['SERVER_PROTOCOL'] ?? 'HTTP/1.1';
        $headers = [];

        foreach ($_SERVER as $key => $val) {
            if (strpos($key, 'HTTP_') === 0 && is_string($val)) {
                $headerName = str_replace('_', '-', substr($key, 5));
                $headers[] = strtolower($headerName) . ': ' . $val;
            }
        }

        $rawHeaders = implode("\r\n", $headers);

        // Read bounded body stream (prevent L7 memory exhaustion)
        $body = '';
        if (in_array($method, ['POST', 'PUT', 'PATCH', 'DELETE'], true)) {
            $inputHandle = @fopen('php://input', 'rb');
            if ($inputHandle) {
                $body = (string)@stream_get_contents($inputHandle, self::MAX_BODY_BYTES);
                @fclose($inputHandle);
            }
        }

        return "{$method} {$uri} {$protocol}\r\n{$rawHeaders}\r\n\r\n{$body}";
    }

    /**
     * Terminate connection with 403/429 status and forensic incident page.
     */
    private function blockRequest(
        int $statusCode,
        string $reason,
        string $clientIp,
        float $anomalyScore,
        array $metadata = []
    ): void {
        $correlationId = 'nwaf_' . bin2hex(random_bytes(8));

        // Asynchronous telemetry dispatch (does not block client flush)
        $this->telemetry->record([
            'event' => 'REQUEST_BLOCKED',
            'correlation_id' => $correlationId,
            'status_code' => $statusCode,
            'reason' => $reason,
            'client_ip' => $clientIp,
            'anomaly_score' => $anomalyScore,
            'metadata' => $metadata,
            'uri' => $_SERVER['REQUEST_URI'] ?? '/',
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown',
        ]);

        // Send HTTP Response Headers
        http_response_code($statusCode);
        header('Content-Type: text/html; charset=UTF-8');
        header('X-NeuralWAF-Status: Blocked');
        header('X-NeuralWAF-Reference-ID: ' . $correlationId);
        if ($statusCode === 429 && isset($metadata['retry_after'])) {
            header('Retry-After: ' . (int)$metadata['retry_after']);
        }

        // Render clean, professional security incident notification
        echo '<!DOCTYPE html><html><head><meta charset="UTF-8"><title>403 Forbidden - NeuralWAF</title>';
        echo '<style>body{background:#020617;color:#f8fafc;font-family:monospace;display:flex;align-items:center;justify-content:center;height:100vh;margin:0}';
        echo '.box{background:#0f172a;border:1px solid #1e293b;border-radius:12px;padding:32px;max-width:560px;box-shadow:0 10px 25px rgba(0,0,0,0.5)}';
        echo 'h1{color:#f43f5e;font-size:18px;margin-top:0}p{font-size:13px;line-height:1.6;color:#94a3b8}';
        echo '.id{background:#020617;padding:8px 12px;border-radius:6px;border:1px solid #334155;color:#38bdf8;font-size:12px}';
        echo '</style></head><body><div class="box">';
        echo '<h1>403 Access Denied · NeuralWAF</h1>';
        echo '<p>Your request was identified as anomalous by deep learning sequence analysis and was neutralized before reaching the application.</p>';
        echo '<div class="id">Incident Reference: ' . htmlspecialchars($correlationId) . '<br>Client IP: ' . htmlspecialchars($clientIp) . '</div>';
        echo '<p style="margin-top:16px;font-size:11px;color:#64748b">Protected by BuruOps NeuralWAF (Zero Regex Pure Deep Learning Engine)</p>';
        echo '</div></body></html>';

        if (function_exists('fastcgi_finish_request')) {
            fastcgi_finish_request();
        }

        exit(0);
    }

    /**
     * Resolve actual client IP from proxy headers.
     */
    public function getClientIp(): string
    {
        $headers = [
            'HTTP_CF_CONNECTING_IP',
            'HTTP_X_REAL_IP',
            'HTTP_X_FORWARDED_FOR',
            'REMOTE_ADDR'
        ];

        foreach ($headers as $header) {
            if (!empty($_SERVER[$header])) {
                $ips = explode(',', (string)$_SERVER[$header]);
                $ip = trim($ips[0]);
                if (filter_var($ip, FILTER_VALIDATE_IP)) {
                    return $ip;
                }
            }
        }

        return $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';
    }
}
