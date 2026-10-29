<?php
/**
 * BuruOps NeuralWAF - Byte Sequence Tokenizer (PHP 7.4 - 8.3+)
 * Open Source Security by BuruOps (engr.buru@gmail.com)
 *
 * Converts raw HTTP streams into high-dimensional numerical token vectors
 * for deep learning sequence anomaly detection without static regexes.
 */

declare(strict_types=1);

namespace NeuralWaf\Tokenizer;

class ByteSequenceTokenizer
{
    public const MAX_SEQUENCE_LENGTH = 512;
    public const VOCAB_SIZE = 128;
    public const PAD_TOKEN = 0;

    /**
     * Tokenize raw HTTP request string into normalized float array [0..1].
     *
     * @param string $rawInput
     * @param int $maxLength
     * @return float[] Normalized sequence vector of length $maxLength
     */
    public function tokenize(string $rawInput, int $maxLength = self::MAX_SEQUENCE_LENGTH): array
    {
        $len = strlen($rawInput);
        $bound = min($len, $maxLength);
        $tokens = array_fill(0, $maxLength, 0.0);

        for ($i = 0; $i < $bound; $i++) {
            $byte = ord($rawInput[$i]);

            // Printable ASCII (32..126) -> categorical token indices [1..95]
            if ($byte >= 32 && $byte <= 126) {
                $tokenIndex = $byte - 31;
            } elseif ($byte === 10 || $byte === 13) {
                // Line feed / Carriage return -> token 96
                $tokenIndex = 96;
            } elseif ($byte === 9) {
                // Tab -> token 97
                $tokenIndex = 97;
            } elseif ($byte === 0) {
                // Null byte injection attempt -> high anomaly token 127
                $tokenIndex = 127;
            } else {
                // Non-printable control characters and high binary bytes -> [98..126]
                $tokenIndex = 98 + ($byte % 29);
            }

            // Normalize token to [0.0..1.0] for neural network ingestion
            $tokens[$i] = round($tokenIndex / self::VOCAB_SIZE, 6);
        }

        return $tokens;
    }

    /**
     * Calculate structural entropy of tokenized byte distribution.
     * High entropy combined with control byte concentration indicates obfuscated exploits.
     *
     * @param string $rawInput
     * @return float Shannon entropy value [0.0..8.0]
     */
    public function calculateEntropy(string $rawInput): float
    {
        $len = strlen($rawInput);
        if ($len === 0) {
            return 0.0;
        }

        $frequencies = count_chars($rawInput, 1);
        $entropy = 0.0;

        foreach ($frequencies as $count) {
            $p = $count / $len;
            $entropy -= $p * log($p, 2);
        }

        return round($entropy, 4);
    }
}
