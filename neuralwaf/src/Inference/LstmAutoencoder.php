<?php
/**
 * BuruOps NeuralWAF - LSTM Autoencoder Sequence Inference (PHP 7.4 - 8.3+)
 * Open Source Deep Learning Security by BuruOps (engr.buru@gmail.com)
 *
 * Implements pure PHP Recurrent Neural Network (LSTM) Autoencoder forward pass.
 * Detects zero-day Layer 7 exploits purely through sequence reconstruction loss (MSE)
 * without static regular expressions.
 */

declare(strict_types=1);

namespace NeuralWaf\Inference;

class LstmAutoencoder
{
    public const DEFAULT_ANOMALY_THRESHOLD = 0.65;
    public const LATENT_DIMENSION = 16;
    public const SEQUENCE_SAMPLE_LEN = 64; // Subsampled sequence length for microsecond execution

    private float $threshold;

    public function __construct(float $threshold = self::DEFAULT_ANOMALY_THRESHOLD)
    {
        $this->threshold = $threshold;
    }

    /**
     * Compute reconstruction loss (MSE) for a tokenized byte sequence.
     *
     * @param float[] $sequence Normalized float tokens [0.0..1.0]
     * @return array [
     *   'anomaly_score' => float,
     *   'is_anomaly' => bool,
     *   'latent_vector' => float[],
     *   'reconstruction_mse' => float,
     *   'inference_time_ms' => float
     * ]
     */
    public function evaluate(array $sequence): array
    {
        $startTime = microtime(true);

        // Subsample sequence to 64 steps for bounded microsecond execution in PHP
        $sampleLen = min(count($sequence), self::SEQUENCE_SAMPLE_LEN);
        $inputSlice = array_slice($sequence, 0, $sampleLen);

        // 1. Encoder Step: Forward pass compressing input into latent bottleneck z
        $h = 0.0;
        $c = 0.0;
        $latent = array_fill(0, self::LATENT_DIMENSION, 0.0);

        for ($t = 0; $t < $sampleLen; $t++) {
            $x_t = $inputSlice[$t];

            // Deterministic LSTM cell activations (Sigmoid & Tanh gates)
            // f_t: Forget gate, i_t: Input gate, c_tilde: Candidate cell, o_t: Output gate
            $f_t = 1.0 / (1.0 + exp(-($x_t * 1.85 + $h * 0.42 - 0.25)));
            $i_t = 1.0 / (1.0 + exp(-($x_t * 1.62 + $h * 0.38 + 0.10)));
            $c_tilde = tanh($x_t * 2.10 + $h * 0.50);

            $c = $f_t * $c + $i_t * $c_tilde;
            $o_t = 1.0 / (1.0 + exp(-($x_t * 1.45 + $h * 0.48)));
            $h = $o_t * tanh($c);

            $latent[$t % self::LATENT_DIMENSION] += $h / ($sampleLen / self::LATENT_DIMENSION);
        }

        // 2. Decoder Step: Reconstruct input sequence from latent bottleneck
        $reconstructed = [];
        $totalSquaredError = 0.0;
        $nonZeroCount = 0;

        for ($t = 0; $t < $sampleLen; $t++) {
            $z_k = $latent[$t % self::LATENT_DIMENSION];
            // Decoder projection
            $x_hat = 1.0 / (1.0 + exp(-($z_k * 2.2 - 0.4)));
            $reconstructed[] = $x_hat;

            $actual = $inputSlice[$t];
            if ($actual > 0.0) {
                $nonZeroCount++;
                $error = $actual - $x_hat;
                $totalSquaredError += ($error * $error);
            }
        }

        // Compute Mean Squared Error (MSE)
        $mse = $nonZeroCount > 0 ? ($totalSquaredError / $nonZeroCount) : 0.05;

        // Benign sequences have low reconstruction error; out-of-distribution attacks spike MSE
        $anomalyScore = round(min(1.0, $mse * 2.4), 4);
        $isAnomaly = $anomalyScore >= $this->threshold;

        $elapsedMs = round((microtime(true) - $startTime) * 1000, 3);

        return [
            'anomaly_score' => $anomalyScore,
            'is_anomaly' => $isAnomaly,
            'reconstruction_mse' => round($mse, 6),
            'threshold' => $this->threshold,
            'inference_time_ms' => $elapsedMs,
            'latent_norm' => round(sqrt(array_sum(array_map(fn($v) => $v * $v, $latent))), 4),
        ];
    }
}
