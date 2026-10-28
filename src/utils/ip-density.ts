/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 *
 * IP Origin Density & Subnet Aggregation Logic for L7 DDoS Visualization.
 */

export interface SubnetDefinition {
  cidr: string;
  name: string;
  execLabel: string;
  category: 'Legitimate ISP' | 'Public Cloud' | 'Compromised Botnet' | 'Tor / VPN Proxy' | 'Residential Bot';
  expectedBaseRPS: number;
  surgeSensitivity: number; // multiplier during volumetric attack
}

export const MONITORED_SUBNETS: SubnetDefinition[] = [
  {
    cidr: '198.51.100.0/24',
    name: 'TEST-NET-2 (Core Enterprise API)',
    execLabel: 'Verified Partner API Traffic',
    category: 'Legitimate ISP',
    expectedBaseRPS: 450,
    surgeSensitivity: 1.1,
  },
  {
    cidr: '203.0.113.0/24',
    name: 'TEST-NET-3 (Mirai / HTTP-2 Flood)',
    execLabel: 'IoT Device Botnet Cluster',
    category: 'Compromised Botnet',
    expectedBaseRPS: 40,
    surgeSensitivity: 35.0,
  },
  {
    cidr: '192.0.2.0/24',
    name: 'TEST-NET-1 (Credential Stuffing / Rotated)',
    execLabel: 'Residential Proxy Network',
    category: 'Residential Bot',
    expectedBaseRPS: 75,
    surgeSensitivity: 22.0,
  },
  {
    cidr: '198.18.0.0/15',
    name: 'Benchmarking Mesh (Rapid Reset L7)',
    execLabel: 'Cloud Server Zombie Farm',
    category: 'Compromised Botnet',
    expectedBaseRPS: 30,
    surgeSensitivity: 40.0,
  },
  {
    cidr: '185.220.101.0/24',
    name: 'Tor Anonymous Relays / Darknet',
    execLabel: 'Anonymized Evasion Proxies',
    category: 'Tor / VPN Proxy',
    expectedBaseRPS: 60,
    surgeSensitivity: 18.0,
  },
  {
    cidr: '104.244.42.0/24',
    name: 'Autonomous System Egress BGP',
    execLabel: 'Distributed CDN Origin Edge',
    category: 'Public Cloud',
    expectedBaseRPS: 380,
    surgeSensitivity: 1.2,
  },
  {
    cidr: '45.33.0.0/16',
    name: 'Virtual Private Server Cluster (Linode/VPS)',
    execLabel: 'Scraper / Automation Farm',
    category: 'Residential Bot',
    expectedBaseRPS: 90,
    surgeSensitivity: 15.0,
  },
  {
    cidr: '89.248.165.0/24',
    name: 'Bulletproof Hosting Scanner CIDR',
    execLabel: 'High-Volume Vulnerability Probes',
    category: 'Compromised Botnet',
    expectedBaseRPS: 25,
    surgeSensitivity: 30.0,
  },
];

export const HOST_BUCKET_COUNT = 8;
export const HOST_BUCKET_LABELS = [
  '.0-31',
  '.32-63',
  '.64-95',
  '.96-127',
  '.128-159',
  '.160-191',
  '.192-223',
  '.224-255',
];

export interface HeatmapCellData {
  subnetCidr: string;
  subnetName: string;
  execLabel: string;
  category: SubnetDefinition['category'];
  hostBucket: number;
  bucketLabel: string;
  sampleIp: string;
  rps: number;
  peakRps: number;
  anomalyScore: number;
  reconstructionMse: number;
  isMitigated: boolean;
  action: 'ALLOW' | 'RATE_LIMIT' | 'DROP_L7';
}

export type DdosAttackProfile = 'none' | 'mirai_flood' | 'http2_rapid_reset' | 'distributed_rotator';

export interface AttackConfig {
  id: DdosAttackProfile;
  name: string;
  execName: string;
  description: string;
  targetSubnets: string[];
  rpsMultiplier: number;
  targetBuckets?: number[];
}

export const ATTACK_PROFILES: Record<DdosAttackProfile, AttackConfig> = {
  none: {
    id: 'none',
    name: 'Nominal Traffic (Clean Baseline)',
    execName: 'Normal Business Traffic',
    description: 'Everyday customer traffic. Low anomaly scores, zero dropped packets, all subnets operating within capacity.',
    targetSubnets: [],
    rpsMultiplier: 1.0,
  },
  mirai_flood: {
    id: 'mirai_flood',
    name: 'Mirai IoT HTTP GET Volumetric Surge',
    execName: 'Smart-Device Botnet Flood (50x Surge)',
    description: 'High-density SYN & HTTP GET floods concentrated from compromised IP clusters in TEST-NET-3 and Bulletproof CIDRs.',
    targetSubnets: ['203.0.113.0/24', '89.248.165.0/24'],
    rpsMultiplier: 28.0,
    targetBuckets: [1, 2, 5, 6],
  },
  http2_rapid_reset: {
    id: 'http2_rapid_reset',
    name: 'HTTP/2 Rapid Reset & Multiplex Bomb',
    execName: 'Server Resource Exhaustion Attack',
    description: 'Stream RST frames sent in rapid sequence across cloud zombie nodes in 198.18.0.0/15, saturating connection state.',
    targetSubnets: ['198.18.0.0/15', '45.33.0.0/16'],
    rpsMultiplier: 35.0,
    targetBuckets: [3, 4, 7],
  },
  distributed_rotator: {
    id: 'distributed_rotator',
    name: 'Distributed Residential Proxy Credential Stuffing',
    execName: 'Stealth Credential Stuffing Campaign',
    description: 'Rotated source IP addresses hopping through residential gateways (192.0.2.0/24 & Tor Relays), evading naive rate limits.',
    targetSubnets: ['192.0.2.0/24', '185.220.101.0/24'],
    rpsMultiplier: 18.0,
  },
};

/**
 * Maps an IP string's 4th octet to one of the 8 host buckets (0..7)
 */
export function getHostBucketIndex(fourthOctet: number): number {
  if (fourthOctet < 0) return 0;
  if (fourthOctet > 255) return 7;
  return Math.min(7, Math.floor(fourthOctet / 32));
}

/**
 * Builds a deterministic sample IP for a given subnet and host bucket index
 */
export function buildSampleIp(cidr: string, bucketIdx: number): string {
  const prefix = cidr.split('/')[0];
  const parts = prefix.split('.');
  const base = bucketIdx * 32 + 14;
  return `${parts[0]}.${parts[1]}.${parts[2]}.${base}`;
}

/**
 * Generates the current snapshot of the 8x8 IP density matrix based on current attack profile and noise
 */
export function generateIpDensityMatrix(
  attackProfile: DdosAttackProfile,
  attackIntensity = 1.0,
  noiseSeed = Date.now()
): HeatmapCellData[] {
  const profile = ATTACK_PROFILES[attackProfile];
  const cells: HeatmapCellData[] = [];

  MONITORED_SUBNETS.forEach((subnet, subnetIdx) => {
    const isTargeted = profile.targetSubnets.includes(subnet.cidr);

    for (let b = 0; b < HOST_BUCKET_COUNT; b++) {
      // Deterministic pseudo-random variation
      const pseudoRand = Math.sin(noiseSeed * 0.001 + subnetIdx * 7 + b * 13) * 0.5 + 0.5;
      const baseRpsPerBucket = Math.round(subnet.expectedBaseRPS / HOST_BUCKET_COUNT);

      let rps = Math.round(baseRpsPerBucket * (0.8 + pseudoRand * 0.4));
      let anomalyScore = 0.08 + pseudoRand * 0.12;
      let reconstructionMse = 0.02 + pseudoRand * 0.03;

      if (isTargeted && profile.id !== 'none') {
        const isBucketTargeted =
          !profile.targetBuckets || profile.targetBuckets.includes(b);

        if (isBucketTargeted) {
          const surgeFactor = (subnet.surgeSensitivity * attackIntensity * (0.85 + pseudoRand * 0.3));
          rps = Math.round(baseRpsPerBucket * surgeFactor);
          // High out-of-distribution anomaly score for attacked buckets
          anomalyScore = Math.min(0.99, 0.72 + pseudoRand * 0.25);
          reconstructionMse = 0.85 + pseudoRand * 0.85;
        }
      }

      // Determine mitigation action
      let action: 'ALLOW' | 'RATE_LIMIT' | 'DROP_L7' = 'ALLOW';
      let isMitigated = false;

      if (anomalyScore > 0.85 || rps > 1200) {
        action = 'DROP_L7';
        isMitigated = true;
      } else if (anomalyScore > 0.65 || rps > 500) {
        action = 'RATE_LIMIT';
        isMitigated = true;
      }

      cells.push({
        subnetCidr: subnet.cidr,
        subnetName: subnet.name,
        execLabel: subnet.execLabel,
        category: subnet.category,
        hostBucket: b,
        bucketLabel: HOST_BUCKET_LABELS[b],
        sampleIp: buildSampleIp(subnet.cidr, b),
        rps,
        peakRps: Math.round(rps * 1.25),
        anomalyScore: Number(anomalyScore.toFixed(3)),
        reconstructionMse: Number(reconstructionMse.toFixed(4)),
        isMitigated,
        action,
      });
    }
  });

  return cells;
}

/**
 * Computes high-level aggregated metrics across the IP density heatmap
 */
export function computeHeatmapAggregates(cells: HeatmapCellData[]) {
  let totalRps = 0;
  let mitigatedRps = 0;
  let maxRps = 0;
  let hotSubnetsCount = 0;
  let highAnomalyCells = 0;

  const subnetMap = new Map<string, { totalRps: number; maxScore: number }>();

  cells.forEach((cell) => {
    totalRps += cell.rps;
    if (cell.isMitigated) {
      mitigatedRps += cell.rps;
    }
    if (cell.rps > maxRps) {
      maxRps = cell.rps;
    }
    if (cell.anomalyScore > 0.65) {
      highAnomalyCells++;
    }

    const current = subnetMap.get(cell.subnetCidr) || { totalRps: 0, maxScore: 0 };
    current.totalRps += cell.rps;
    current.maxScore = Math.max(current.maxScore, cell.anomalyScore);
    subnetMap.set(cell.subnetCidr, current);
  });

  subnetMap.forEach((val) => {
    if (val.maxScore > 0.65 || val.totalRps > 2000) {
      hotSubnetsCount++;
    }
  });

  return {
    totalRps,
    mitigatedRps,
    passThroughRps: totalRps - mitigatedRps,
    mitigationRatio: totalRps > 0 ? (mitigatedRps / totalRps) : 0,
    maxCellRps: maxRps,
    hotSubnetsCount,
    highAnomalyCells,
    totalCells: cells.length,
  };
}
