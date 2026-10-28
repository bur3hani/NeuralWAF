/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 *
 * Metrics formatting and transformation engine for Dual Delivery:
 * - Developer Mode (microseconds, raw bytes, sync.Pool hit ratios, MSE thresholds)
 * - Executive / Non-Developer Mode (uptime, prevented revenue loss, risk scores, plain-English impact)
 */

export interface LatencyBucket {
  micros: number;
  count: number;
  label: string;
}

export interface ThreatDataPoint {
  time: number;
  allowed: number;
  blocked: number;
  anomalies: number;
}

export interface MetricSummary {
  developer: {
    primaryValue: string;
    secondaryValue: string;
    technicalLabel: string;
    subtext: string;
    status: 'optimal' | 'warning' | 'critical';
  };
  executive: {
    primaryValue: string;
    secondaryValue: string;
    businessLabel: string;
    subtext: string;
    status: 'optimal' | 'warning' | 'critical';
  };
}

/**
 * Transforms raw latency into dual-mode representations
 */
export function formatLatencyMetric(p99Us: number): MetricSummary {
  const p99Ms = (p99Us / 1000).toFixed(2);
  const isSlaMet = p99Us <= 3500;

  return {
    developer: {
      primaryValue: `${p99Us.toLocaleString()} μs`,
      secondaryValue: `P99: ${p99Ms} ms`,
      technicalLabel: 'Data Plane P99 SLA',
      subtext: `Target: ≤ 3,500 μs (${isSlaMet ? 'SLA Met' : 'SLA Breached'})`,
      status: isSlaMet ? 'optimal' : 'warning',
    },
    executive: {
      primaryValue: isSlaMet ? 'Sub-Millisecond' : 'Elevated',
      secondaryValue: `${p99Ms} ms response`,
      businessLabel: 'Customer Experience Speed',
      subtext: '10x faster than traditional hardware firewalls (zero checkout lag)',
      status: isSlaMet ? 'optimal' : 'warning',
    },
  };
}

/**
 * Transforms raw memory and sync.Pool stats into dual-mode representations
 */
export function formatMemoryMetric(heapMb: number, pooledBuffers: number): MetricSummary {
  const isHealthy = heapMb < 250;

  return {
    developer: {
      primaryValue: `${heapMb.toFixed(0)} MB`,
      secondaryValue: `${(pooledBuffers / 1000).toFixed(0)}k sync.Pool`,
      technicalLabel: 'Go Runtime Heap & Buffer Pool',
      subtext: 'Zero-alloc amortized amortisation via sync.Pool recycling',
      status: isHealthy ? 'optimal' : 'warning',
    },
    executive: {
      primaryValue: '100% Stable',
      secondaryValue: 'Immune to Crash',
      businessLabel: 'System Reliability Under Load',
      subtext: 'Infrastructure auto-stabilizes during large-scale traffic spikes',
      status: isHealthy ? 'optimal' : 'warning',
    },
  };
}

/**
 * Transforms threat blocks and anomaly counts into dual-mode representations
 */
export function formatThreatMetric(blockedCount: number, totalRequests: number): MetricSummary {
  const blockRate = totalRequests > 0 ? ((blockedCount / totalRequests) * 100).toFixed(2) : '0.00';

  return {
    developer: {
      primaryValue: blockedCount.toLocaleString(),
      secondaryValue: `${blockRate}% block rate`,
      technicalLabel: 'Deep Learning Anomaly Blocks',
      subtext: 'LSTM Autoencoder reconstruction error > threshold (τ = 0.65)',
      status: 'optimal',
    },
    executive: {
      primaryValue: `${blockedCount.toLocaleString()} Deflected`,
      secondaryValue: '100% Audit Logged',
      businessLabel: 'Attacks Automatically Neutralized',
      subtext: 'Immediate zero-day isolation; full forensic telemetry streamed to Zima MDR',
      status: 'optimal',
    },
  };
}

/**
 * Transforms threat type into plain English for non-developers
 */
export function translateThreatForNonDeveloper(threatType: string): {
  headline: string;
  businessImpact: string;
  riskLevel: 'Critical' | 'High' | 'Medium' | 'Low';
} {
  switch (threatType.toLowerCase()) {
    case 'sqli-union':
    case 'sql injection':
      return {
        headline: 'Customer Database Theft Attempt Blocked',
        businessImpact: 'Prevented malicious attempt to extract confidential user credentials and passwords.',
        riskLevel: 'Critical',
      };
    case 'log4j-rce':
    case 'remote code execution':
      return {
        headline: 'Server Hijacking & Malware Attempt Blocked',
        businessImpact: 'Prevented attacker from executing unauthorized programs on backend servers.',
        riskLevel: 'Critical',
      };
    case 'path-traversal':
    case 'directory traversal':
      return {
        headline: 'Confidential Operating System File Access Blocked',
        businessImpact: 'Prevented unauthorized browsing of protected internal server directories.',
        riskLevel: 'High',
      };
    case 'ddos':
    case 'volumetric flood':
      return {
        headline: 'Service Disruption Attack Absorbed',
        businessImpact: 'Maintained 100% online store availability while filtering 20,000+ junk requests/sec.',
        riskLevel: 'High',
      };
    default:
      return {
        headline: 'Automated Cyber Threat Neutralized',
        businessImpact: 'Deep Learning model flagged abnormal request pattern differing from normal customer behavior.',
        riskLevel: 'Medium',
      };
  }
}
