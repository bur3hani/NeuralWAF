/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import {
  formatLatencyMetric,
  formatMemoryMetric,
  formatThreatMetric,
  translateThreatForNonDeveloper,
} from './metrics-transformer.ts';

test('formatLatencyMetric generates technical developer and executive business views', () => {
  const result = formatLatencyMetric(1200);

  // Developer view checks
  assert.equal(result.developer.primaryValue, '1,200 μs');
  assert.equal(result.developer.secondaryValue, 'P99: 1.20 ms');
  assert.equal(result.developer.status, 'optimal');

  // Executive view checks
  assert.equal(result.executive.primaryValue, 'Sub-Millisecond');
  assert.ok(result.executive.subtext.includes('10x faster'));
  assert.equal(result.executive.businessLabel, 'Customer Experience Speed');
});

test('formatLatencyMetric flags SLA warning when latency exceeds 3500us', () => {
  const result = formatLatencyMetric(4200);
  assert.equal(result.developer.status, 'warning');
  assert.ok(result.developer.subtext.includes('SLA Breached'));
  assert.equal(result.executive.primaryValue, 'Elevated');
});

test('formatMemoryMetric formats heap and sync.Pool metrics correctly', () => {
  const result = formatMemoryMetric(45, 120000);
  assert.equal(result.developer.primaryValue, '45 MB');
  assert.equal(result.developer.secondaryValue, '120k sync.Pool');
  assert.equal(result.executive.primaryValue, '100% Stable');
  assert.equal(result.executive.businessLabel, 'System Reliability Under Load');
});

test('translateThreatForNonDeveloper provides clear business impact instead of technical jargon', () => {
  const sqli = translateThreatForNonDeveloper('SQL Injection');
  assert.equal(sqli.headline, 'Customer Database Theft Attempt Blocked');
  assert.equal(sqli.riskLevel, 'Critical');

  const rce = translateThreatForNonDeveloper('log4j-rce');
  assert.equal(rce.headline, 'Server Hijacking & Malware Attempt Blocked');
  assert.equal(rce.riskLevel, 'Critical');

  const traversal = translateThreatForNonDeveloper('path-traversal');
  assert.equal(traversal.riskLevel, 'High');
});

test('formatThreatMetric formats clean operational threat counts', () => {
  const result = formatThreatMetric(1000, 10000);
  assert.equal(result.developer.primaryValue, '1,000');
  assert.equal(result.developer.secondaryValue, '10.00% block rate');
  assert.equal(result.executive.primaryValue, '1,000 Deflected');
  assert.equal(result.executive.secondaryValue, '100% Audit Logged');
});
