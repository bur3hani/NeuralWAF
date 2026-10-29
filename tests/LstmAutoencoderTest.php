<?php
/**
 * BuruOps NeuralWAF - LSTM Autoencoder PHPUnit Test Suite
 * Open Source Security by BuruOps (engr.buru@gmail.com)
 */

declare(strict_types=1);

namespace NeuralWaf\Tests;

use PHPUnit\Framework\TestCase;
use NeuralWaf\Tokenizer\ByteSequenceTokenizer;
use NeuralWaf\Inference\LstmAutoencoder;

final class LstmAutoencoderTest extends TestCase
{
    private ByteSequenceTokenizer $tokenizer;
    private LstmAutoencoder $autoencoder;

    protected function setUp(): void
    {
        $this->tokenizer = new ByteSequenceTokenizer();
        $this->autoencoder = new LstmAutoencoder(0.65);
    }

    public function testBenignRequestProducesLowAnomalyScore(): void
    {
        $benign = "GET /index.php?page=about&lang=en HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n";
        $tokens = $this->tokenizer->tokenize($benign);
        $result = $this->autoencoder->evaluate($tokens);

        $this->assertFalse($result['is_anomaly'], 'Benign request should not be flagged as an anomaly');
        $this->assertLessThan(0.65, $result['anomaly_score']);
        $this->assertLessThan(0.15, $result['reconstruction_mse']);
    }

    public function testSqlInjectionProducesHighReconstructionLoss(): void
    {
        $sqli = "GET /catalog.php?id=1'%20UNION%20ALL%20SELECT%20NULL,table_name,column_name%20FROM%20information_schema.columns-- HTTP/1.1\r\nHost: example.com\r\n\r\n";
        $tokens = $this->tokenizer->tokenize($sqli);
        $result = $this->autoencoder->evaluate($tokens);

        $this->assertTrue($result['is_anomaly'], 'SQL injection should trigger out-of-distribution anomaly');
        $this->assertGreaterThanOrEqual(0.65, $result['anomaly_score']);
    }

    public function testShannonEntropyCalculation(): void
    {
        $lowEntropy = "aaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        $highEntropy = "!@#\$%^&*()_+1234567890abcdefghijklmnopqrstuvwxyz";

        $entLow = $this->tokenizer->calculateEntropy($lowEntropy);
        $entHigh = $this->tokenizer->calculateEntropy($highEntropy);

        $this->assertLessThan($entHigh, $entLow, 'Random alphanumeric string must have higher entropy than uniform string');
    }
}
