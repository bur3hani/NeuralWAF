/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { 
  generateSecurePassword, 
  computeEventHash, 
  ROLE_PERMISSIONS, 
  INITIAL_USERS,
  type UserRole 
} from './user-management.ts';

test('User Management: generateSecurePassword generates strong entropy passwords', () => {
  const pwd1 = generateSecurePassword(24);
  const pwd2 = generateSecurePassword(24);

  assert.equal(pwd1.length, 24);
  assert.equal(pwd2.length, 24);
  assert.notEqual(pwd1, pwd2, 'Subsequent passwords must be distinct CSPRNG outputs');

  // Verify complexity: upper, lower, digit, symbol
  assert.match(pwd1, /[A-Z]/, 'Must contain uppercase');
  assert.match(pwd1, /[a-z]/, 'Must contain lowercase');
  assert.match(pwd1, /[0-9]/, 'Must contain digit');
  assert.match(pwd1, /[!@#$%^&*\-_+=]/, 'Must contain special symbol');
});

test('User Management: computeEventHash produces 64-character deterministic cryptographic hashes', () => {
  const prevHash = '0000000000000000000000000000000000000000000000000000000000000000';
  const h1 = computeEventHash(prevHash, 'LOGIN', 'buru_admin', 1700000000, 'Success');
  const h2 = computeEventHash(prevHash, 'LOGIN', 'buru_admin', 1700000000, 'Success');
  const h3 = computeEventHash(prevHash, 'LOGIN', 'attacker', 1700000000, 'Failure');

  assert.equal(h1.length, 64);
  assert.equal(h1, h2, 'Hash must be strictly deterministic given identical parameters');
  assert.notEqual(h1, h3, 'Tampering actor must completely change the hash signature');
});

test('User Management: Role-Based Access Control matrix enforces principle of least privilege', () => {
  const roles: UserRole[] = ['SuperAdmin', 'SecurityOperator', 'Auditor'];

  // SuperAdmin has full authority
  assert.equal(ROLE_PERMISSIONS.SuperAdmin.permissions.canManageUsers, true);
  assert.equal(ROLE_PERMISSIONS.SuperAdmin.permissions.canRotateKeys, true);
  assert.equal(ROLE_PERMISSIONS.SuperAdmin.permissions.canModifyFirewallRules, true);

  // SecurityOperator cannot manage users or rotate keys
  assert.equal(ROLE_PERMISSIONS.SecurityOperator.permissions.canManageUsers, false);
  assert.equal(ROLE_PERMISSIONS.SecurityOperator.permissions.canRotateKeys, false);
  assert.equal(ROLE_PERMISSIONS.SecurityOperator.permissions.canModifyFirewallRules, true);
  assert.equal(ROLE_PERMISSIONS.SecurityOperator.permissions.canTriggerMitigations, true);

  // Auditor has read-only audit inspection
  assert.equal(ROLE_PERMISSIONS.Auditor.permissions.canManageUsers, false);
  assert.equal(ROLE_PERMISSIONS.Auditor.permissions.canModifyFirewallRules, false);
  assert.equal(ROLE_PERMISSIONS.Auditor.permissions.canTriggerMitigations, false);
  assert.equal(ROLE_PERMISSIONS.Auditor.permissions.canViewAuditLogs, true);
});

test('User Management: INITIAL_USERS contains proper Argon2id metadata without plaintext passwords', () => {
  for (const user of INITIAL_USERS) {
    assert.ok(user.id.startsWith('usr_'));
    assert.equal(user.hashAlgorithm, 'Argon2id');
    assert.ok(user.saltHex.length >= 32, 'Salt must have at least 128-bit/256-bit entropy');
    assert.ok(!user.passwordHashSnippet.includes('password'), 'Plaintext passwords must never appear');
    assert.ok(user.passwordHashSnippet.startsWith('$argon2id$'));
  }
});
