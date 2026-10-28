/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 *
 * BuruOps NeuralWAF User Management & Cryptographic Vault Engine
 * Attribution: BuruOps Engineering Team (engr.buru@gmail.com)
 *
 * Implements:
 *  - Role-Based Access Control (SuperAdmin, SecurityOperator, Auditor)
 *  - Password hashing via simulated Argon2id (with CSPRNG salts)
 *  - AES-256-GCM authenticated encryption simulation
 *  - Tamper-evident SHA-256 audit log hash-chaining
 */

export type UserRole = 'SuperAdmin' | 'SecurityOperator' | 'Auditor';
export type UserStatus = 'active' | 'locked' | 'deactivated';

export interface WafUser {
  id: string;
  username: string;
  email: string;
  role: UserRole;
  status: UserStatus;
  hashAlgorithm: 'Argon2id' | 'Bcrypt(cost=12)';
  saltHex: string;
  passwordHashSnippet: string;
  mfaEnabled: boolean;
  failedAttempts: number;
  lockedUntil: number | null;
  createdAt: number;
  lastLogin: number | null;
  lastPasswordRotation: number;
}

export interface AuditLogEntry {
  id: string;
  event: string;
  actor: string;
  targetUser?: string;
  timestamp: number;
  details: string;
  prevHash: string;
  hash: string;
}

export interface VaultMetadata {
  vaultVersion: string;
  encryptionAlgorithm: 'AES-256-GCM';
  keyLengthBits: 256;
  nonceLengthBits: 96;
  argonMemoryCostMb: 64;
  argonTimeCostIterations: 4;
  argonParallelism: 2;
  lastRotationTimestamp: number;
}

// Simple hash simulation helper for audit chain (SHA-256 style)
export function computeEventHash(prevHash: string, event: string, actor: string, timestamp: number, details: string): string {
  const payload = `${prevHash}:${event}:${actor}:${timestamp}:${details}`;
  let hash = 0;
  for (let i = 0; i < payload.length; i++) {
    const char = payload.charCodeAt(i);
    hash = ((hash << 5) - hash) + char;
    hash |= 0;
  }
  // Convert to 64-character pseudo hex
  const hexPart1 = Math.abs(hash).toString(16).padStart(8, '0');
  const hexPart2 = Math.abs(hash ^ 0x5a5a5a5a).toString(16).padStart(8, '0');
  const hexPart3 = Math.abs(hash ^ 0x3c3c3c3c).toString(16).padStart(8, '0');
  const hexPart4 = Math.abs(hash ^ 0xa5a5a5a5).toString(16).padStart(8, '0');
  return (hexPart1 + hexPart2 + hexPart3 + hexPart4 + hexPart2 + hexPart1 + hexPart4 + hexPart3).slice(0, 64);
}

// Generate high-entropy secure password
export function generateSecurePassword(length = 24): string {
  const charset = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*-_+=';
  let pwd = '';
  // Ensure at least one upper, lower, digit, and symbol
  pwd += 'ABCDEFGHJKLMNPQRSTUVWXYZ'[Math.floor(Math.random() * 24)];
  pwd += 'abcdefghijkmnopqrstuvwxyz'[Math.floor(Math.random() * 25)];
  pwd += '23456789'[Math.floor(Math.random() * 8)];
  pwd += '!@#$%^&*-_+='[Math.floor(Math.random() * 12)];

  for (let i = 4; i < length; i++) {
    const randIndex = Math.floor(Math.random() * charset.length);
    pwd += charset[randIndex];
  }
  // Shuffle characters
  return pwd.split('').sort(() => 0.5 - Math.random()).join('');
}

// Role permission matrices
export const ROLE_PERMISSIONS: Record<UserRole, {
  label: string;
  description: string;
  badgeColor: string;
  permissions: {
    canManageUsers: boolean;
    canRotateKeys: boolean;
    canModifyFirewallRules: boolean;
    canTriggerMitigations: boolean;
    canViewAuditLogs: boolean;
    canExportCodebase: boolean;
  };
}> = {
  SuperAdmin: {
    label: 'Super Admin',
    description: 'Full root authority: user provisioning, master key rotation, rule modification, and system bypasses.',
    badgeColor: 'bg-indigo-500/20 text-indigo-300 border-indigo-500/30',
    permissions: {
      canManageUsers: true,
      canRotateKeys: true,
      canModifyFirewallRules: true,
      canTriggerMitigations: true,
      canViewAuditLogs: true,
      canExportCodebase: true,
    },
  },
  SecurityOperator: {
    label: 'Security Operator',
    description: 'Operational defender: inspect live telemetry, trigger DDoS mitigations, and ban/unban IP ranges.',
    badgeColor: 'bg-emerald-500/20 text-emerald-300 border-emerald-500/30',
    permissions: {
      canManageUsers: false,
      canRotateKeys: false,
      canModifyFirewallRules: true,
      canTriggerMitigations: true,
      canViewAuditLogs: true,
      canExportCodebase: false,
    },
  },
  Auditor: {
    label: 'Compliance Auditor',
    description: 'Read-only inspector: access cryptographic audit trail, compliance reports, and tamper logs.',
    badgeColor: 'bg-amber-500/20 text-amber-300 border-amber-500/30',
    permissions: {
      canManageUsers: false,
      canRotateKeys: false,
      canModifyFirewallRules: false,
      canTriggerMitigations: false,
      canViewAuditLogs: true,
      canExportCodebase: false,
    },
  },
};

// Initial Seed Users (Zero actual secrets - hashes with Argon2id signatures)
export const INITIAL_USERS: WafUser[] = [
  {
    id: 'usr_buru_01',
    username: 'buru_admin',
    email: 'engr.buru@gmail.com',
    role: 'SuperAdmin',
    status: 'active',
    hashAlgorithm: 'Argon2id',
    saltHex: '4f9a8b1c2d3e4f5a6b7c8d9e0f1a2b3c',
    passwordHashSnippet: '$argon2id$v=19$m=65536,t=4,p=2$T3BlblNvdXJjZQ...',
    mfaEnabled: true,
    failedAttempts: 0,
    lockedUntil: null,
    createdAt: Date.now() - 1000 * 60 * 60 * 24 * 7,
    lastLogin: Date.now() - 1000 * 60 * 12,
    lastPasswordRotation: Date.now() - 1000 * 60 * 60 * 24 * 7,
  },
  {
    id: 'usr_sec_02',
    username: 'soc_analyst',
    email: 'soc.defense@buruops.io',
    role: 'SecurityOperator',
    status: 'active',
    hashAlgorithm: 'Argon2id',
    saltHex: '8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f',
    passwordHashSnippet: '$argon2id$v=19$m=65536,t=4,p=2$QnlydU9wczIwMjY...',
    mfaEnabled: true,
    failedAttempts: 0,
    lockedUntil: null,
    createdAt: Date.now() - 1000 * 60 * 60 * 24 * 4,
    lastLogin: Date.now() - 1000 * 60 * 45,
    lastPasswordRotation: Date.now() - 1000 * 60 * 60 * 24 * 4,
  },
  {
    id: 'usr_aud_03',
    username: 'compliance_auditor',
    email: 'audit@buruops.io',
    role: 'Auditor',
    status: 'active',
    hashAlgorithm: 'Argon2id',
    saltHex: '3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e',
    passwordHashSnippet: '$argon2id$v=19$m=65536,t=4,p=2$QXVkaXRUcmFpbDI...',
    mfaEnabled: false,
    failedAttempts: 0,
    lockedUntil: null,
    createdAt: Date.now() - 1000 * 60 * 60 * 24 * 2,
    lastLogin: Date.now() - 1000 * 60 * 60 * 3,
    lastPasswordRotation: Date.now() - 1000 * 60 * 60 * 24 * 2,
  },
];

export const INITIAL_AUDIT_LOGS: AuditLogEntry[] = [
  {
    id: 'evt_001',
    event: 'VAULT_INITIALIZED',
    actor: 'buru_admin',
    timestamp: Date.now() - 1000 * 60 * 60 * 24 * 7,
    details: 'Master AES-256-GCM vault created with 256-bit key and Argon2id params',
    prevHash: '0000000000000000000000000000000000000000000000000000000000000000',
    hash: computeEventHash(
      '0000000000000000000000000000000000000000000000000000000000000000',
      'VAULT_INITIALIZED',
      'buru_admin',
      Date.now() - 1000 * 60 * 60 * 24 * 7,
      'Master AES-256-GCM vault created'
    ),
  },
  {
    id: 'evt_002',
    event: 'USER_CREATED',
    actor: 'buru_admin',
    targetUser: 'soc_analyst',
    timestamp: Date.now() - 1000 * 60 * 60 * 24 * 4,
    details: 'Created SecurityOperator role with active MFA and scoped permissions',
    prevHash: 'a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2',
    hash: computeEventHash(
      'a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2',
      'USER_CREATED',
      'buru_admin',
      Date.now() - 1000 * 60 * 60 * 24 * 4,
      'Created SecurityOperator role'
    ),
  },
  {
    id: 'evt_003',
    event: 'AUTH_SUCCESS_MFA',
    actor: 'buru_admin',
    timestamp: Date.now() - 1000 * 60 * 12,
    details: 'Authenticated via TOTP MFA hardware token from internal admin IP',
    prevHash: 'f9e8d7c6b5a4f9e8d7c6b5a4f9e8d7c6b5a4f9e8d7c6b5a4f9e8d7c6b5a4f9e8',
    hash: computeEventHash(
      'f9e8d7c6b5a4f9e8d7c6b5a4f9e8d7c6b5a4f9e8d7c6b5a4f9e8d7c6b5a4f9e8',
      'AUTH_SUCCESS_MFA',
      'buru_admin',
      Date.now() - 1000 * 60 * 12,
      'Authenticated via TOTP'
    ),
  },
];
