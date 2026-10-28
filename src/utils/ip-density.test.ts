/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { describe, it } from 'node:test';
import assert from 'node:assert';
import {
  MONITORED_SUBNETS,
  HOST_BUCKET_COUNT,
  getHostBucketIndex,
  buildSampleIp,
  generateIpDensityMatrix,
  computeHeatmapAggregates,
  ATTACK_PROFILES,
} from './ip-density.ts';

describe('IP Density & Subnet Aggregation Logic', () => {
  it('correctly maps 4th octet to host bucket index [0..7]', () => {
    assert.strictEqual(getHostBucketIndex(0), 0);
    assert.strictEqual(getHostBucketIndex(15), 0);
    assert.strictEqual(getHostBucketIndex(31), 0);
    assert.strictEqual(getHostBucketIndex(32), 1);
    assert.strictEqual(getHostBucketIndex(63), 1);
    assert.strictEqual(getHostBucketIndex(64), 2);
    assert.strictEqual(getHostBucketIndex(127), 3);
    assert.strictEqual(getHostBucketIndex(128), 4);
    assert.strictEqual(getHostBucketIndex(223), 6);
    assert.strictEqual(getHostBucketIndex(255), 7);
    // Boundary guards
    assert.strictEqual(getHostBucketIndex(-5), 0);
    assert.strictEqual(getHostBucketIndex(300), 7);
  });

  it('builds valid sample IP within target CIDR block', () => {
    const ip0 = buildSampleIp('198.51.100.0/24', 0);
    assert.strictEqual(ip0, '198.51.100.14');

    const ip4 = buildSampleIp('203.0.113.0/24', 4);
    assert.strictEqual(ip4, '203.0.113.142'); // 4 * 32 + 14 = 142
  });

  it('generates nominal 8x8 matrix (64 cells) with safe baseline metrics', () => {
    const cells = generateIpDensityMatrix('none', 1.0, 1000);
    assert.strictEqual(cells.length, MONITORED_SUBNETS.length * HOST_BUCKET_COUNT);

    const aggregates = computeHeatmapAggregates(cells);
    assert.ok(aggregates.totalRps > 500, 'Baseline RPS should be active');
    assert.strictEqual(aggregates.hotSubnetsCount, 0, 'No hot subnets under nominal traffic');
    assert.strictEqual(aggregates.highAnomalyCells, 0, 'No high anomaly cells under baseline');
  });

  it('triggers dramatic volumetric surge and automated mitigation under Mirai flood', () => {
    const nominal = generateIpDensityMatrix('none', 1.0, 1000);
    const attack = generateIpDensityMatrix('mirai_flood', 1.5, 1000);

    const nomAgg = computeHeatmapAggregates(nominal);
    const atkAgg = computeHeatmapAggregates(attack);

    assert.ok(atkAgg.totalRps > nomAgg.totalRps * 2, 'Total ingress RPS should spike during attack');
    assert.ok(atkAgg.mitigatedRps > 0, 'Mitigation should engage on high-density attack cells');
    assert.ok(atkAgg.hotSubnetsCount >= 1, 'At least 1 hot subnet identified');
    assert.ok(atkAgg.highAnomalyCells > 0, 'Anomaly cells detected');

    // Confirm target subnet received high RPS and DROP_L7 action
    const targetedCells = attack.filter((c) => c.subnetCidr === '203.0.113.0/24');
    const droppedCells = targetedCells.filter((c) => c.action === 'DROP_L7');
    assert.ok(droppedCells.length > 0, 'Targeted cells must trigger DROP_L7');
  });

  it('validates HTTP/2 Rapid Reset and Distributed Rotator profiles', () => {
    const rapidReset = generateIpDensityMatrix('http2_rapid_reset', 1.2, 5000);
    const rotator = generateIpDensityMatrix('distributed_rotator', 1.0, 5000);

    const rrAgg = computeHeatmapAggregates(rapidReset);
    const rotAgg = computeHeatmapAggregates(rotator);

    assert.ok(rrAgg.hotSubnetsCount >= 1);
    assert.ok(rotAgg.hotSubnetsCount >= 1);
    assert.ok(ATTACK_PROFILES.http2_rapid_reset.targetSubnets.length > 0);
  });
});
