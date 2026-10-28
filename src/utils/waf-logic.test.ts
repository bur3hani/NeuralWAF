/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import {
  tokenizeString,
  evaluateLSTMReconstruction,
  NonBlockingRingBuffer,
  sanitizePayloadForTelemetry,
  MAX_TELEMETRY_PAYLOAD_BYTES,
} from './waf-logic.ts';

test('tokenization maps printable ASCII and bounds sequence length', () => {
  const uri = '/api/v1/orders?sort=desc';
  const tokens = tokenizeString(uri, 1, 1024);

  assert.equal(tokens.segmentId, 1);
  assert.equal(tokens.rawLength, uri.length);
  assert.equal(tokens.tokenIds.length, uri.length);
  // Verify first character '/' (ASCII 47 -> 47 - 30 = 17)
  assert.equal(tokens.tokenIds[0], 17);
});

test('tokenization flags anomalous control and non-ASCII bytes as high token indices', () => {
  const payloadWithNullBytes = 'test\x00\xffadmin';
  const tokens = tokenizeString(payloadWithNullBytes, 3, 1024);

  assert.equal(tokens.tokenIds[4], 1000); // null byte 0 -> 1000 + 0 = 1000
  assert.equal(tokens.tokenIds[5], 1255); // 0xff (255) -> 1000 + 255 = 1255
});

test('LSTM Autoencoder reconstruction error evaluates benign request as low anomaly score', () => {
  const uriTokens = tokenizeString('/api/v2/products/12345', 1);
  const bodyTokens = tokenizeString('{"action":"view"}', 3);
  const result = evaluateLSTMReconstruction(uriTokens, bodyTokens);

  assert.equal(result.isAnomaly, false);
  assert.ok(result.anomalyScore < 0.65, `Anomaly score ${result.anomalyScore} should be below threshold`);
  assert.ok(result.reconstructionError < 0.1, `MSE ${result.reconstructionError} should be low`);
});

test('LSTM Autoencoder reconstruction error detects out-of-distribution attacks (SQLi/payloads)', () => {
  const attackURI = "/api/v1/users?id=1'%20OR%20'1'='1'--\x00\x00";
  const attackBody = "payload=\x00\x01\xff\xfe' UNION SELECT password FROM users--";
  const uriTokens = tokenizeString(attackURI, 1);
  const bodyTokens = tokenizeString(attackBody, 3);
  const result = evaluateLSTMReconstruction(uriTokens, bodyTokens);

  assert.equal(result.isAnomaly, true);
  assert.ok(result.anomalyScore >= 0.65, `Anomaly score ${result.anomalyScore} should be at or above threshold`);
  assert.ok(result.reconstructionError > 0.5, 'MSE should spike on malicious payload');
  assert.ok(result.diagnosticTags.includes('high_reconstruction_loss_detected'));
});

test('Non-blocking ring buffer drops events when full and never blocks', () => {
  const buffer = new NonBlockingRingBuffer<string>(3);

  assert.equal(buffer.emit('event-1'), true);
  assert.equal(buffer.emit('event-2'), true);
  assert.equal(buffer.emit('event-3'), true);
  assert.equal(buffer.queueDepth, 3);

  // 4th event must be dropped immediately without waiting
  assert.equal(buffer.emit('event-4'), false);
  assert.equal(buffer.droppedCount, 1);
  assert.equal(buffer.enqueuedCount, 3);

  // Flushing batch frees up capacity
  const flushed = buffer.flushBatch(2);
  assert.equal(flushed.length, 2);
  assert.equal(buffer.queueDepth, 1);

  // Now emitting succeeds again
  assert.equal(buffer.emit('event-5'), true);
  assert.equal(buffer.queueDepth, 2);
});

test('payload truncation prevents memory bloat for telemetry streaming', () => {
  const largePayload = 'A'.repeat(MAX_TELEMETRY_PAYLOAD_BYTES + 500);
  const sanitized = sanitizePayloadForTelemetry(largePayload);

  assert.equal(sanitized.truncated, true);
  assert.equal(sanitized.content.length, MAX_TELEMETRY_PAYLOAD_BYTES);

  const smallPayload = '{"user":"test"}';
  const smallSanitized = sanitizePayloadForTelemetry(smallPayload);
  assert.equal(smallSanitized.truncated, false);
  assert.equal(smallSanitized.content, smallPayload);
});
