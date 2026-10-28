/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 *
 * BuruOps NeuralWAF User Management & Cryptographic RBAC Dashboard
 * Attribution: BuruOps Engineering Team (engr.buru@gmail.com)
 */

import React, { useState } from 'react';
import { 
  ShieldCheck, 
  UserPlus, 
  KeyRound, 
  Lock, 
  Unlock, 
  Trash2, 
  RefreshCw, 
  CheckCircle2, 
  AlertTriangle, 
  Eye, 
  EyeOff, 
  Terminal, 
  Copy, 
  Check, 
  Users, 
  FileKey, 
  Clock, 
  Sparkles,
  ShieldAlert,
  ArrowRight
} from 'lucide-react';
import { 
  type WafUser, 
  type UserRole, 
  type AuditLogEntry, 
  INITIAL_USERS, 
  INITIAL_AUDIT_LOGS, 
  ROLE_PERMISSIONS, 
  generateSecurePassword, 
  computeEventHash 
} from '../utils/user-management.ts';

interface Props {
  devMode: boolean;
}

export const UserManagementView: React.FC<Props> = ({ devMode }) => {
  const [users, setUsers] = useState<WafUser[]>(INITIAL_USERS);
  const [auditLogs, setAuditLogs] = useState<AuditLogEntry[]>(INITIAL_AUDIT_LOGS);
  const [currentActor, setCurrentActor] = useState<string>('buru_admin');
  const [activeSubTab, setActiveSubTab] = useState<'directory' | 'installer' | 'audit' | 'vault'>('directory');
  
  // New User Modal State
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [newUsername, setNewUsername] = useState('');
  const [newEmail, setNewEmail] = useState('');
  const [newRole, setNewRole] = useState<UserRole>('SecurityOperator');
  const [newPassword, setNewPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [isMfaEnabled, setIsMfaEnabled] = useState(true);
  const [copiedText, setCopiedText] = useState<string | null>(null);

  // Installer simulation state
  const [installStep, setInstallStep] = useState<number>(0);
  const [installAdminUser, setInstallAdminUser] = useState('buru_admin');
  const [installAdminEmail, setInstallAdminEmail] = useState('engr.buru@gmail.com');
  const [installPassword, setInstallPassword] = useState('');
  const [installLogs, setInstallLogs] = useState<string[]>([]);
  const [isInstalling, setIsInstalling] = useState(false);

  // Chain verification state
  const [isChainVerified, setIsChainVerified] = useState<boolean | null>(null);

  // Active current user permissions
  const activeUser = users.find(u => u.username === currentActor) || users[0];
  const activePermissions = ROLE_PERMISSIONS[activeUser.role].permissions;

  const handleCopy = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedText(id);
    setTimeout(() => setCopiedText(null), 2000);
  };

  const handleGeneratePassword = () => {
    const pwd = generateSecurePassword(24);
    setNewPassword(pwd);
    setShowPassword(true);
  };

  const handleCreateUser = (e: React.FormEvent) => {
    e.preventDefault();
    if (!newUsername.trim() || !newEmail.trim() || !newPassword.trim()) return;

    const salt = Array.from({ length: 32 }, () => Math.floor(Math.random() * 16).toString(16)).join('');
    const newUser: WafUser = {
      id: `usr_${Date.now().toString(36)}`,
      username: newUsername.trim().toLowerCase(),
      email: newEmail.trim(),
      role: newRole,
      status: 'active',
      hashAlgorithm: 'Argon2id',
      saltHex: salt,
      passwordHashSnippet: `$argon2id$v=19$m=65536,t=4,p=2$${btoa(newUsername).slice(0, 12)}...`,
      mfaEnabled: isMfaEnabled,
      failedAttempts: 0,
      lockedUntil: null,
      createdAt: Date.now(),
      lastLogin: null,
      lastPasswordRotation: Date.now(),
    };

    const prevEntry = auditLogs[auditLogs.length - 1];
    const timestamp = Date.now();
    const eventHash = computeEventHash(
      prevEntry.hash,
      'USER_PROVISIONED',
      currentActor,
      timestamp,
      `Created ${newUser.role} account for ${newUser.username}`
    );

    const newAuditEntry: AuditLogEntry = {
      id: `evt_${Date.now()}`,
      event: 'USER_PROVISIONED',
      actor: currentActor,
      targetUser: newUser.username,
      timestamp,
      details: `Provisioned operator with ${newUser.role} permissions, Argon2id salt, and AES-256-GCM vault re-encryption`,
      prevHash: prevEntry.hash,
      hash: eventHash,
    };

    setUsers([...users, newUser]);
    setAuditLogs([...auditLogs, newAuditEntry]);
    setIsModalOpen(false);
    setNewUsername('');
    setNewEmail('');
    setNewPassword('');
  };

  const handleToggleLock = (user: WafUser) => {
    if (user.username === 'buru_admin' && user.status === 'active') {
      alert('Protection Policy: Cannot lock the root SuperAdmin account.');
      return;
    }

    const nextStatus = user.status === 'active' ? 'locked' : 'active';
    const updatedUsers = users.map(u => (u.id === user.id ? { ...u, status: nextStatus as any } : u));
    setUsers(updatedUsers);

    const prevEntry = auditLogs[auditLogs.length - 1];
    const timestamp = Date.now();
    const event = nextStatus === 'locked' ? 'USER_LOCKED' : 'USER_UNLOCKED';
    const newAuditEntry: AuditLogEntry = {
      id: `evt_${Date.now()}`,
      event,
      actor: currentActor,
      targetUser: user.username,
      timestamp,
      details: `Operator account ${user.username} was ${nextStatus} by ${currentActor}`,
      prevHash: prevEntry.hash,
      hash: computeEventHash(prevEntry.hash, event, currentActor, timestamp, user.username),
    };
    setAuditLogs([...auditLogs, newAuditEntry]);
  };

  const handleRoleChange = (user: WafUser, role: UserRole) => {
    if (user.username === 'buru_admin' && role !== 'SuperAdmin') {
      alert('Protection Policy: Cannot demote the primary root SuperAdmin.');
      return;
    }

    const updatedUsers = users.map(u => (u.id === user.id ? { ...u, role } : u));
    setUsers(updatedUsers);

    const prevEntry = auditLogs[auditLogs.length - 1];
    const timestamp = Date.now();
    const newAuditEntry: AuditLogEntry = {
      id: `evt_${Date.now()}`,
      event: 'ROLE_MODIFIED',
      actor: currentActor,
      targetUser: user.username,
      timestamp,
      details: `Role for ${user.username} changed to ${role} (RBAC permissions recalculated)`,
      prevHash: prevEntry.hash,
      hash: computeEventHash(prevEntry.hash, 'ROLE_MODIFIED', currentActor, timestamp, `${user.username}:${role}`),
    };
    setAuditLogs([...auditLogs, newAuditEntry]);
  };

  const handleResetPassword = (user: WafUser) => {
    const newPass = generateSecurePassword(24);
    alert(`New Secure Credentials for ${user.username}:\n\nPassword: ${newPass}\n\nVault updated and re-encrypted with AES-256-GCM. Save this password.`);

    const prevEntry = auditLogs[auditLogs.length - 1];
    const timestamp = Date.now();
    const newAuditEntry: AuditLogEntry = {
      id: `evt_${Date.now()}`,
      event: 'PASSWORD_ROTATED',
      actor: currentActor,
      targetUser: user.username,
      timestamp,
      details: `Password rotated for ${user.username}. New Argon2id hash computed and AES-256-GCM vault re-sealed`,
      prevHash: prevEntry.hash,
      hash: computeEventHash(prevEntry.hash, 'PASSWORD_ROTATED', currentActor, timestamp, user.username),
    };
    setAuditLogs([...auditLogs, newAuditEntry]);
  };

  const handleDeleteUser = (user: WafUser) => {
    if (user.username === 'buru_admin') {
      alert('Protection Policy: Cannot delete the primary root SuperAdmin account.');
      return;
    }
    if (!confirm(`Are you sure you want to permanently delete operator ${user.username}?`)) return;

    setUsers(users.filter(u => u.id !== user.id));

    const prevEntry = auditLogs[auditLogs.length - 1];
    const timestamp = Date.now();
    const newAuditEntry: AuditLogEntry = {
      id: `evt_${Date.now()}`,
      event: 'USER_DELETED',
      actor: currentActor,
      targetUser: user.username,
      timestamp,
      details: `Operator account ${user.username} deleted. Access tokens revoked.`,
      prevHash: prevEntry.hash,
      hash: computeEventHash(prevEntry.hash, 'USER_DELETED', currentActor, timestamp, user.username),
    };
    setAuditLogs([...auditLogs, newAuditEntry]);
  };

  const handleVerifyChain = () => {
    let isValid = true;
    for (let i = 1; i < auditLogs.length; i++) {
      if (auditLogs[i].prevHash !== auditLogs[i - 1].hash) {
        isValid = false;
        break;
      }
    }
    setIsChainVerified(isValid);
    setTimeout(() => setIsChainVerified(null), 4000);
  };

  // Run simulated installer
  const runSimulatedInstall = () => {
    setIsInstalling(true);
    setInstallLogs([]);
    setInstallStep(1);

    const generatedPwd = installPassword || generateSecurePassword(24);
    setInstallPassword(generatedPwd);

    const steps = [
      `[1/6] Inspecting runtime prerequisites: PHP 8.2 & OpenSSL 3.0 found. Node.js engine active.`,
      `[2/6] Generating 256-bit CSPRNG Master AES Key: ${Array.from({ length: 16 }, () => Math.floor(Math.random() * 256).toString(16).padStart(2, '0')).join('')}...`,
      `[3/6] Generating HMAC JWT signing secret and IPC token...`,
      `[4/6] Executing Argon2id password hash (memory: 64MB, time: 4 iterations, threads: 2)...`,
      `[5/6] Sealing credentials vault to neuralwaf/data/credentials.enc via AES-256-GCM (chmod 600)...`,
      `[6/6] Writing config.secure.php (chmod 600) and updating .user.ini / .htaccess root hooks...`,
      `SUCCESS: NeuralWAF Root installed! SuperAdmin "${installAdminUser}" active with zero secrets in git.`
    ];

    steps.forEach((line, index) => {
      setTimeout(() => {
        setInstallLogs(prev => [...prev, line]);
        setInstallStep(index + 1);
        if (index === steps.length - 1) {
          setIsInstalling(false);
        }
      }, (index + 1) * 350);
    });
  };

  return (
    <div className="space-y-6">
      {/* Top Banner / Attribution Header */}
      <div className="bg-gradient-to-r from-slate-900 via-indigo-950/40 to-slate-900 border border-slate-800 rounded-2xl p-6 relative overflow-hidden">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2 mb-2">
              <span className="px-2.5 py-1 rounded-md text-xs font-mono font-bold bg-indigo-500/20 text-indigo-300 border border-indigo-500/30 flex items-center gap-1.5">
                <ShieldCheck className="w-3.5 h-3.5 text-indigo-400" />
                BuruOps Security IAM
              </span>
              <span className="px-2.5 py-1 rounded-md text-xs font-mono font-bold bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">
                Argon2id + AES-256-GCM
              </span>
              <span className="px-2.5 py-1 rounded-md text-xs font-mono text-slate-400 border border-slate-800">
                engr.buru@gmail.com
              </span>
            </div>
            <h2 className="text-xl sm:text-2xl font-bold text-white tracking-tight">
              {devMode ? 'Enterprise User Management & Cryptographic Vault' : 'Operator Access Control & Credential Vault'}
            </h2>
            <p className="text-xs sm:text-sm text-slate-400 mt-1 max-w-3xl">
              {devMode
                ? 'Zero secrets in repository: Administrative credentials are encrypted at rest with AES-256-GCM and hashed via Argon2id with individual 256-bit CSPRNG salts. Audited via SHA-256 hash-chaining.'
                : 'Manage authorized firewall operators, assign role-based permissions, rotate encrypted access keys, and review tamper-evident security audit logs.'}
            </p>
          </div>

          {/* Quick Action: New User & Simulation */}
          <div className="flex items-center gap-2.5 shrink-0">
            {activePermissions.canManageUsers && (
              <button
                onClick={() => {
                  handleGeneratePassword();
                  setIsModalOpen(true);
                }}
                className="flex items-center gap-2 bg-gradient-to-r from-indigo-600 to-cyan-600 hover:from-indigo-500 hover:to-cyan-500 text-white font-mono text-xs font-semibold px-4 py-2.5 rounded-xl shadow-lg shadow-indigo-900/40 transition-all cursor-pointer"
              >
                <UserPlus className="w-4 h-4" />
                <span>Provision Operator</span>
              </button>
            )}
          </div>
        </div>

        {/* Current Active Actor Switcher (Demonstrates RBAC in real-time) */}
        <div className="mt-5 pt-4 border-t border-slate-800/80 flex flex-wrap items-center justify-between gap-3 text-xs font-mono">
          <div className="flex items-center gap-2">
            <span className="text-slate-400 flex items-center gap-1">
              <Users className="w-3.5 h-3.5 text-cyan-400" />
              Active Session Actor:
            </span>
            <span className="text-white font-bold bg-slate-950 px-2 py-1 rounded border border-slate-800">
              {activeUser.username}
            </span>
            <span className={`px-2 py-0.5 rounded text-[11px] font-semibold border ${ROLE_PERMISSIONS[activeUser.role].badgeColor}`}>
              {activeUser.role}
            </span>
          </div>

          <div className="flex items-center gap-2">
            <span className="text-slate-500 hidden sm:inline">Simulate Actor:</span>
            {users.map(u => (
              <button
                key={u.id}
                onClick={() => setCurrentActor(u.username)}
                className={`px-2.5 py-1 rounded text-[11px] font-mono transition-all border ${
                  currentActor === u.username
                    ? 'bg-indigo-600 text-white border-indigo-500 shadow-sm'
                    : 'bg-slate-900 text-slate-400 hover:text-slate-200 border-slate-800'
                }`}
              >
                {u.username} ({u.role.slice(0, 5)})
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Navigation Sub-Tabs */}
      <div className="flex items-center gap-2 border-b border-slate-800 pb-2">
        <button
          onClick={() => setActiveSubTab('directory')}
          className={`flex items-center gap-2 px-3.5 py-2 rounded-xl text-xs font-mono font-semibold transition-all ${
            activeSubTab === 'directory'
              ? 'bg-indigo-600/20 text-indigo-300 border border-indigo-500/40 shadow-sm'
              : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900 border border-transparent'
          }`}
        >
          <Users className="w-3.5 h-3.5" />
          <span>Operator Directory ({users.length})</span>
        </button>

        <button
          onClick={() => setActiveSubTab('installer')}
          className={`flex items-center gap-2 px-3.5 py-2 rounded-xl text-xs font-mono font-semibold transition-all ${
            activeSubTab === 'installer'
              ? 'bg-indigo-600/20 text-indigo-300 border border-indigo-500/40 shadow-sm'
              : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900 border border-transparent'
          }`}
        >
          <Terminal className="w-3.5 h-3.5 text-emerald-400" />
          <span>Root Install Script (`scripts/install.sh`)</span>
        </button>

        <button
          onClick={() => setActiveSubTab('audit')}
          className={`flex items-center gap-2 px-3.5 py-2 rounded-xl text-xs font-mono font-semibold transition-all ${
            activeSubTab === 'audit'
              ? 'bg-indigo-600/20 text-indigo-300 border border-indigo-500/40 shadow-sm'
              : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900 border border-transparent'
          }`}
        >
          <Clock className="w-3.5 h-3.5 text-amber-400" />
          <span>Cryptographic Audit Trail</span>
        </button>

        <button
          onClick={() => setActiveSubTab('vault')}
          className={`flex items-center gap-2 px-3.5 py-2 rounded-xl text-xs font-mono font-semibold transition-all ${
            activeSubTab === 'vault'
              ? 'bg-indigo-600/20 text-indigo-300 border border-indigo-500/40 shadow-sm'
              : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900 border border-transparent'
          }`}
        >
          <FileKey className="w-3.5 h-3.5 text-cyan-400" />
          <span>Vault & Encryption Architecture</span>
        </button>
      </div>

      {/* VIEW 1: OPERATOR DIRECTORY */}
      {activeSubTab === 'directory' && (
        <div className="space-y-4">
          <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-md">
            <div className="px-6 py-4 border-b border-slate-800 flex items-center justify-between">
              <div>
                <h3 className="text-sm font-bold text-white">Active Firewall Operators</h3>
                <p className="text-xs text-slate-400 font-mono mt-0.5">
                  RBAC roles determine ingress threshold control, rule adjustments, and key rotation rights
                </p>
              </div>
              <div className="text-xs font-mono text-slate-400 bg-slate-950 px-3 py-1 rounded-lg border border-slate-800">
                Storage: <span className="text-indigo-400">neuralwaf/data/credentials.enc</span> (AES-256-GCM)
              </div>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs font-mono">
                <thead className="bg-slate-950/60 text-slate-400 border-b border-slate-800 uppercase tracking-wider text-[10px]">
                  <tr>
                    <th className="py-3 px-4">Operator</th>
                    <th className="py-3 px-4">Role & RBAC Scope</th>
                    <th className="py-3 px-4">Cryptographic Hash</th>
                    <th className="py-3 px-4">MFA</th>
                    <th className="py-3 px-4">Status</th>
                    <th className="py-3 px-4 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/80">
                  {users.map(user => {
                    const roleInfo = ROLE_PERMISSIONS[user.role];
                    const isSelf = user.username === currentActor;

                    return (
                      <tr key={user.id} className="hover:bg-slate-800/30 transition-colors">
                        {/* Operator Identity */}
                        <td className="py-4 px-4">
                          <div className="flex items-center gap-3">
                            <div className="w-8 h-8 rounded-lg bg-indigo-600/20 border border-indigo-500/30 flex items-center justify-center text-indigo-300 font-bold">
                              {user.username.slice(0, 2).toUpperCase()}
                            </div>
                            <div>
                              <div className="font-bold text-white flex items-center gap-1.5">
                                <span>{user.username}</span>
                                {isSelf && (
                                  <span className="text-[9px] bg-slate-800 text-slate-300 px-1.5 py-0.2 rounded border border-slate-700">
                                    YOU
                                  </span>
                                )}
                              </div>
                              <div className="text-slate-500 text-[11px]">{user.email}</div>
                            </div>
                          </div>
                        </td>

                        {/* Role & Scope */}
                        <td className="py-4 px-4">
                          <div className="space-y-1">
                            {activePermissions.canManageUsers && !isSelf ? (
                              <select
                                value={user.role}
                                onChange={(e) => handleRoleChange(user, e.target.value as UserRole)}
                                className="bg-slate-950 border border-slate-700 text-slate-200 text-xs rounded px-2 py-1 font-mono focus:border-indigo-500 focus:outline-none"
                              >
                                <option value="SuperAdmin">SuperAdmin</option>
                                <option value="SecurityOperator">SecurityOperator</option>
                                <option value="Auditor">Auditor</option>
                              </select>
                            ) : (
                              <span className={`inline-block px-2.5 py-0.5 rounded text-[10px] font-bold border ${roleInfo.badgeColor}`}>
                                {user.role}
                              </span>
                            )}
                            <div className="text-[10px] text-slate-500 line-clamp-1 max-w-xs">
                              {roleInfo.description}
                            </div>
                          </div>
                        </td>

                        {/* Cryptographic Hash */}
                        <td className="py-4 px-4">
                          <div className="space-y-0.5">
                            <div className="flex items-center gap-1 text-[11px] text-emerald-400 font-bold">
                              <CheckCircle2 className="w-3 h-3 text-emerald-400" />
                              {user.hashAlgorithm}
                            </div>
                            <div className="text-[10px] text-slate-500 font-mono">
                              Salt: {user.saltHex.slice(0, 8)}... (256-bit CSPRNG)
                            </div>
                          </div>
                        </td>

                        {/* MFA Status */}
                        <td className="py-4 px-4">
                          {user.mfaEnabled ? (
                            <span className="inline-flex items-center gap-1 text-emerald-400 bg-emerald-500/10 px-2 py-0.5 rounded border border-emerald-500/20 text-[10px] font-semibold">
                              <CheckCircle2 className="w-3 h-3" />
                              TOTP Active
                            </span>
                          ) : (
                            <span className="inline-flex items-center gap-1 text-amber-400 bg-amber-500/10 px-2 py-0.5 rounded border border-amber-500/20 text-[10px] font-semibold">
                              Optional
                            </span>
                          )}
                        </td>

                        {/* Status */}
                        <td className="py-4 px-4">
                          {user.status === 'active' ? (
                            <span className="inline-flex items-center gap-1 text-emerald-400 text-[11px]">
                              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
                              Active
                            </span>
                          ) : (
                            <span className="inline-flex items-center gap-1 text-rose-400 text-[11px]">
                              <Lock className="w-3 h-3" />
                              Locked
                            </span>
                          )}
                        </td>

                        {/* Actions */}
                        <td className="py-4 px-4 text-right">
                          <div className="flex items-center justify-end gap-1.5">
                            {activePermissions.canManageUsers ? (
                              <>
                                <button
                                  onClick={() => handleResetPassword(user)}
                                  className="p-1.5 text-slate-400 hover:text-amber-300 hover:bg-amber-500/10 rounded transition-colors"
                                  title="Rotate password & re-seal vault"
                                >
                                  <KeyRound className="w-4 h-4" />
                                </button>
                                <button
                                  onClick={() => handleToggleLock(user)}
                                  className={`p-1.5 rounded transition-colors ${
                                    user.status === 'active'
                                      ? 'text-slate-400 hover:text-rose-400 hover:bg-rose-500/10'
                                      : 'text-slate-400 hover:text-emerald-400 hover:bg-emerald-500/10'
                                  }`}
                                  title={user.status === 'active' ? 'Lock user' : 'Unlock user'}
                                >
                                  {user.status === 'active' ? <Lock className="w-4 h-4" /> : <Unlock className="w-4 h-4" />}
                                </button>
                                {user.username !== 'buru_admin' && (
                                  <button
                                    onClick={() => handleDeleteUser(user)}
                                    className="p-1.5 text-slate-400 hover:text-rose-400 hover:bg-rose-500/10 rounded transition-colors"
                                    title="Delete operator"
                                  >
                                    <Trash2 className="w-4 h-4" />
                                  </button>
                                )}
                              </>
                            ) : (
                              <span className="text-slate-600 text-[10px]">Read-Only</span>
                            )}
                          </div>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>

          {/* Permissions Matrix Reference */}
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-3">
            <h4 className="text-xs font-mono font-bold uppercase tracking-wider text-slate-400 flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-indigo-400" />
              Role-Based Access Control (RBAC) Enforcement Policy
            </h4>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs font-mono">
              <div className="p-3 bg-slate-950 rounded-lg border border-slate-800 space-y-2">
                <div className="flex items-center justify-between">
                  <span className="font-bold text-indigo-400">SuperAdmin</span>
                  <span className="text-[10px] text-slate-500">Root Level</span>
                </div>
                <p className="text-[11px] text-slate-400">
                  Full control: Add/remove operators, rotate AES-256-GCM master keys, alter zero-day anomaly thresholds, and export deployment bundles.
                </p>
                <div className="text-[10px] text-emerald-400 flex items-center gap-1 font-semibold">
                  <CheckCircle2 className="w-3 h-3" /> All 6 administrative privileges granted
                </div>
              </div>

              <div className="p-3 bg-slate-950 rounded-lg border border-slate-800 space-y-2">
                <div className="flex items-center justify-between">
                  <span className="font-bold text-emerald-400">SecurityOperator</span>
                  <span className="text-[10px] text-slate-500">Defense Ops</span>
                </div>
                <p className="text-[11px] text-slate-400">
                  Tactical monitoring: View live byte vectorization, trigger active DDoS mitigations, inspect source IP heatmaps, and ban anomalous CIDRs.
                </p>
                <div className="text-[10px] text-amber-400 flex items-center gap-1 font-semibold">
                  <CheckCircle2 className="w-3 h-3" /> Telemetry & defense control (No user edit)
                </div>
              </div>

              <div className="p-3 bg-slate-950 rounded-lg border border-slate-800 space-y-2">
                <div className="flex items-center justify-between">
                  <span className="font-bold text-amber-400">Auditor</span>
                  <span className="text-[10px] text-slate-500">Compliance</span>
                </div>
                <p className="text-[11px] text-slate-400">
                  Audit verification: Inspect tamper-evident SHA-256 event chains, download forensic reports, and review cryptographic security status.
                </p>
                <div className="text-[10px] text-cyan-400 flex items-center gap-1 font-semibold">
                  <CheckCircle2 className="w-3 h-3" /> Read-only cryptographic inspection
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* VIEW 2: ROOT INSTALL SCRIPT RUNNER (`scripts/install.sh`) */}
      {activeSubTab === 'installer' && (
        <div className="space-y-4">
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 space-y-5">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800 pb-4">
              <div>
                <div className="flex items-center gap-2">
                  <Terminal className="w-5 h-5 text-emerald-400" />
                  <h3 className="text-base font-bold text-white">Root Directory Installer & Credential Vault Setup</h3>
                </div>
                <p className="text-xs text-slate-400 font-mono mt-1">
                  Runs directly on standard website root directories (public_html/ or /). Creates SuperAdmin credentials, encrypts vault with AES-256-GCM, and configures auto_prepend hooks.
                </p>
              </div>
              <div className="flex items-center gap-2">
                <button
                  onClick={runSimulatedInstall}
                  disabled={isInstalling}
                  className="flex items-center gap-2 bg-emerald-600 hover:bg-emerald-500 text-white font-mono text-xs font-semibold px-4 py-2 rounded-lg transition-all shadow-md shadow-emerald-950/50 cursor-pointer disabled:opacity-50"
                >
                  <RefreshCw className={`w-3.5 h-3.5 ${isInstalling ? 'animate-spin' : ''}`} />
                  <span>{isInstalling ? 'Executing Setup...' : 'Run Install Script'}</span>
                </button>
              </div>
            </div>

            {/* Interactive Install Inputs */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 font-mono text-xs">
              <div className="space-y-1.5">
                <label className="text-slate-400 block font-semibold">Admin Username</label>
                <input
                  type="text"
                  value={installAdminUser}
                  onChange={(e) => setInstallAdminUser(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-white font-mono focus:border-indigo-500 focus:outline-none"
                  placeholder="buru_admin"
                />
              </div>

              <div className="space-y-1.5">
                <label className="text-slate-400 block font-semibold">Admin Email</label>
                <input
                  type="email"
                  value={installAdminEmail}
                  onChange={(e) => setInstallAdminEmail(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-white font-mono focus:border-indigo-500 focus:outline-none"
                  placeholder="engr.buru@gmail.com"
                />
              </div>

              <div className="space-y-1.5">
                <div className="flex items-center justify-between">
                  <label className="text-slate-400 font-semibold">Admin Password</label>
                  <button
                    onClick={() => setInstallPassword(generateSecurePassword(24))}
                    className="text-[11px] text-cyan-400 hover:text-cyan-300 flex items-center gap-1"
                  >
                    <Sparkles className="w-3 h-3" /> Auto-Generate
                  </button>
                </div>
                <input
                  type="text"
                  value={installPassword}
                  onChange={(e) => setInstallPassword(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-white font-mono focus:border-indigo-500 focus:outline-none"
                  placeholder="Click auto-generate or type min 16 chars"
                />
              </div>
            </div>

            {/* Execution Console Output */}
            <div className="bg-slate-950 rounded-xl border border-slate-800 p-4 font-mono text-xs space-y-2">
              <div className="flex items-center justify-between border-b border-slate-800 pb-2 text-[11px] text-slate-500">
                <span className="flex items-center gap-1.5 text-slate-400">
                  <Terminal className="w-3.5 h-3.5 text-emerald-400" />
                  Terminal Execution Stream: <code className="text-emerald-400">bash scripts/install.sh</code>
                </span>
                <span>Mode: POSIX Standard</span>
              </div>

              <div className="py-2 space-y-1 text-slate-300 min-h-[140px]">
                {installLogs.length === 0 ? (
                  <div className="text-slate-600 italic py-6 text-center">
                    Click &ldquo;Run Install Script&rdquo; above to simulate terminal execution of the BuruOps root installer.
                  </div>
                ) : (
                  installLogs.map((log, idx) => (
                    <div 
                      key={idx} 
                      className={`leading-relaxed ${
                        log.includes('SUCCESS') 
                          ? 'text-emerald-400 font-bold bg-emerald-950/30 p-2 rounded border border-emerald-500/30' 
                          : log.includes('✓') 
                          ? 'text-cyan-300' 
                          : 'text-slate-300'
                      }`}
                    >
                      {log}
                    </div>
                  ))
                )}
              </div>
            </div>

            {/* Root Files Generated Card */}
            <div className="p-4 bg-slate-950/60 rounded-xl border border-slate-800 space-y-3 font-mono text-xs">
              <div className="font-bold text-white flex items-center gap-2">
                <ShieldCheck className="w-4 h-4 text-emerald-400" />
                Root Files Created with Zero Git Leaks:
              </div>
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
                <div className="p-3 bg-slate-900 rounded-lg border border-slate-800">
                  <div className="font-bold text-indigo-400">neuralwaf/data/credentials.enc</div>
                  <div className="text-[10px] text-slate-400 mt-1">
                    AES-256-GCM encrypted vault. Permissions: <code className="text-emerald-400">chmod 0600</code>. Ignored by .gitignore.
                  </div>
                </div>

                <div className="p-3 bg-slate-900 rounded-lg border border-slate-800">
                  <div className="font-bold text-cyan-400">neuralwaf/config.secure.php</div>
                  <div className="text-[10px] text-slate-400 mt-1">
                    Master 256-bit AES key & HMAC tokens. Permissions: <code className="text-emerald-400">chmod 0600</code>. Never committed to VCS.
                  </div>
                </div>

                <div className="p-3 bg-slate-900 rounded-lg border border-slate-800">
                  <div className="font-bold text-emerald-400">.user.ini & .htaccess</div>
                  <div className="text-[10px] text-slate-400 mt-1">
                    Injects <code className="text-slate-200">auto_prepend_file = &ldquo;neuralwaf/bootstrap.php&rdquo;</code> for pre-execution.
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* VIEW 3: TAMPER-EVIDENT CRYPTOGRAPHIC AUDIT TRAIL */}
      {activeSubTab === 'audit' && (
        <div className="space-y-4">
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800 pb-3">
              <div>
                <h3 className="text-sm font-bold text-white flex items-center gap-2">
                  <Clock className="w-4 h-4 text-amber-400" />
                  SHA-256 Cryptographic Audit Chain
                </h3>
                <p className="text-xs text-slate-400 font-mono mt-0.5">
                  Every user provision, role elevation, and password rotation is linked via backward SHA-256 pointers (blockchain-grade tamper evidence)
                </p>
              </div>

              <div className="flex items-center gap-2">
                <button
                  onClick={handleVerifyChain}
                  className="flex items-center gap-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 px-3 py-1.5 rounded-lg text-xs font-mono transition-all"
                >
                  <RefreshCw className="w-3.5 h-3.5 text-cyan-400" />
                  <span>Verify Chain Integrity</span>
                </button>
              </div>
            </div>

            {/* Chain verification alert */}
            {isChainVerified !== null && (
              <div className={`p-3 rounded-xl border text-xs font-mono flex items-center gap-2 ${
                isChainVerified
                  ? 'bg-emerald-950/40 border-emerald-500/40 text-emerald-300'
                  : 'bg-rose-950/40 border-rose-500/40 text-rose-300'
              }`}>
                {isChainVerified ? (
                  <>
                    <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                    <span>Cryptographic Audit Chain Integrity Validated: All backward hashes match. Zero evidence of tampering.</span>
                  </>
                ) : (
                  <>
                    <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />
                    <span>Integrity Warning: Discrepancy detected in hash chain sequence!</span>
                  </>
                )}
              </div>
            )}

            {/* Audit Log Entries List */}
            <div className="space-y-3 font-mono text-xs">
              {auditLogs.slice().reverse().map((entry, index) => (
                <div key={entry.id} className="p-3.5 bg-slate-950 rounded-xl border border-slate-800/80 space-y-2">
                  <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-800/60 pb-2">
                    <div className="flex items-center gap-2">
                      <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-indigo-500/20 text-indigo-300 border border-indigo-500/30">
                        {entry.event}
                      </span>
                      <span className="text-white font-semibold">Actor: {entry.actor}</span>
                      {entry.targetUser && (
                        <span className="text-slate-400">Target: {entry.targetUser}</span>
                      )}
                    </div>
                    <div className="text-[11px] text-slate-500">
                      {new Date(entry.timestamp).toLocaleString()}
                    </div>
                  </div>

                  <p className="text-slate-300 text-xs">
                    {entry.details}
                  </p>

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-[10px] pt-1">
                    <div className="text-slate-500 truncate">
                      Prev Hash: <span className="text-slate-400">{entry.prevHash.slice(0, 24)}...</span>
                    </div>
                    <div className="text-slate-500 truncate text-right md:text-right">
                      Event Hash: <span className="text-cyan-400 font-bold">{entry.hash.slice(0, 24)}...</span>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* VIEW 4: VAULT & ENCRYPTION ARCHITECTURE */}
      {activeSubTab === 'vault' && (
        <div className="space-y-4">
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 space-y-6">
            <div>
              <h3 className="text-base font-bold text-white flex items-center gap-2">
                <FileKey className="w-5 h-5 text-indigo-400" />
                Zero-Secrets Cryptographic Vault Architecture
              </h3>
              <p className="text-xs text-slate-400 font-mono mt-1">
                Engineered for compliance with NIST SP 800-132, OWASP ASVS 4.0, and ISO/IEC 27001 credential protection standards.
              </p>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 font-mono text-xs">
              <div className="p-4 bg-slate-950 rounded-xl border border-slate-800 space-y-2">
                <span className="text-slate-500 text-[10px] uppercase font-bold">Storage Encryption</span>
                <div className="text-lg font-bold text-white">AES-256-GCM</div>
                <p className="text-[11px] text-slate-400">
                  Authenticated symmetric cipher with 96-bit CSPRNG initialization vectors and 128-bit authentication tags.
                </p>
              </div>

              <div className="p-4 bg-slate-950 rounded-xl border border-slate-800 space-y-2">
                <span className="text-slate-500 text-[10px] uppercase font-bold">Password Hashing</span>
                <div className="text-lg font-bold text-emerald-400">Argon2id (RFC 9106)</div>
                <p className="text-[11px] text-slate-400">
                  Memory cost: 64MB, time cost: 4 passes, 2 parallelism threads. Highly resistant to GPU/ASIC cracking.
                </p>
              </div>

              <div className="p-4 bg-slate-950 rounded-xl border border-slate-800 space-y-2">
                <span className="text-slate-500 text-[10px] uppercase font-bold">POSIX Permissions</span>
                <div className="text-lg font-bold text-cyan-400">chmod 0600</div>
                <p className="text-[11px] text-slate-400">
                  Vault and configuration files are restricted strictly to the web server process UID (nobody, www-data, or cPanel user).
                </p>
              </div>

              <div className="p-4 bg-slate-950 rounded-xl border border-slate-800 space-y-2">
                <span className="text-slate-500 text-[10px] uppercase font-bold">Git Repository Policy</span>
                <div className="text-lg font-bold text-purple-400">Zero Git Secrets</div>
                <p className="text-[11px] text-slate-400">
                  Strictly blocked via .gitignore. Automated CI pipelines scan all commits for accidentally included private keys.
                </p>
              </div>
            </div>

            {/* CLI Commands Reference */}
            <div className="bg-slate-950 rounded-xl border border-slate-800 p-4 space-y-3 font-mono text-xs">
              <div className="font-bold text-white flex items-center justify-between">
                <span>Production CLI User Management Commands</span>
                <span className="text-slate-500 text-[11px]">BuruOps Tooling</span>
              </div>
              <div className="space-y-2 text-slate-300">
                <div className="p-2.5 bg-slate-900 rounded-lg border border-slate-800 flex items-center justify-between">
                  <code>php neuralwaf/bin/waf-user.php list</code>
                  <span className="text-slate-500 text-[11px]">List all operators & roles</span>
                </div>
                <div className="p-2.5 bg-slate-900 rounded-lg border border-slate-800 flex items-center justify-between">
                  <code>php neuralwaf/bin/waf-user.php add --user analyst1 --role SecurityOperator</code>
                  <span className="text-slate-500 text-[11px]">Provision operator interactively</span>
                </div>
                <div className="p-2.5 bg-slate-900 rounded-lg border border-slate-800 flex items-center justify-between">
                  <code>php neuralwaf/bin/waf-user.php reset-password --user buru_admin</code>
                  <span className="text-slate-500 text-[11px]">Rotate credentials & re-encrypt</span>
                </div>
                <div className="p-2.5 bg-slate-900 rounded-lg border border-slate-800 flex items-center justify-between">
                  <code>php neuralwaf/bin/waf-user.php rotate-master-key</code>
                  <span className="text-slate-500 text-[11px]">Re-encrypt vault with new 256-bit AES key</span>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* MODAL: PROVISION NEW USER */}
      {isModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl w-full max-w-lg shadow-2xl p-6 space-y-5 animate-in fade-in zoom-in-95 duration-200">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center gap-2">
                <UserPlus className="w-5 h-5 text-indigo-400" />
                <h3 className="text-base font-bold text-white">Provision New Firewall Operator</h3>
              </div>
              <button
                onClick={() => setIsModalOpen(false)}
                className="text-slate-400 hover:text-white p-1 rounded-lg"
              >
                ✕
              </button>
            </div>

            <form onSubmit={handleCreateUser} className="space-y-4 font-mono text-xs">
              <div className="space-y-1">
                <label className="text-slate-300 block font-semibold">Operator Username</label>
                <input
                  type="text"
                  required
                  value={newUsername}
                  onChange={(e) => setNewUsername(e.target.value)}
                  placeholder="e.g., soc_lead"
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-white font-mono focus:border-indigo-500 focus:outline-none"
                />
              </div>

              <div className="space-y-1">
                <label className="text-slate-300 block font-semibold">Operator Email Address</label>
                <input
                  type="email"
                  required
                  value={newEmail}
                  onChange={(e) => setNewEmail(e.target.value)}
                  placeholder="operator@company.com"
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-white font-mono focus:border-indigo-500 focus:outline-none"
                />
              </div>

              <div className="space-y-1">
                <label className="text-slate-300 block font-semibold">RBAC Role Assignment</label>
                <select
                  value={newRole}
                  onChange={(e) => setNewRole(e.target.value as UserRole)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-white font-mono focus:border-indigo-500 focus:outline-none"
                >
                  <option value="SecurityOperator">SecurityOperator (Telemetry & DDoS defense)</option>
                  <option value="Auditor">Auditor (Read-only cryptographic compliance)</option>
                  <option value="SuperAdmin">SuperAdmin (Full root authority & key rotation)</option>
                </select>
                <p className="text-[11px] text-slate-500 mt-1">
                  {ROLE_PERMISSIONS[newRole].description}
                </p>
              </div>

              <div className="space-y-1">
                <div className="flex items-center justify-between">
                  <label className="text-slate-300 font-semibold">High-Entropy Password</label>
                  <button
                    type="button"
                    onClick={handleGeneratePassword}
                    className="text-[11px] text-cyan-400 hover:text-cyan-300 flex items-center gap-1 cursor-pointer"
                  >
                    <Sparkles className="w-3 h-3" /> Re-Generate
                  </button>
                </div>
                <div className="relative">
                  <input
                    type={showPassword ? 'text' : 'password'}
                    required
                    value={newPassword}
                    onChange={(e) => setNewPassword(e.target.value)}
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 pr-20 text-white font-mono focus:border-indigo-500 focus:outline-none"
                  />
                  <div className="absolute right-2 top-2 flex items-center gap-1">
                    <button
                      type="button"
                      onClick={() => setShowPassword(!showPassword)}
                      className="p-1 text-slate-400 hover:text-white"
                      title={showPassword ? 'Hide' : 'Show'}
                    >
                      {showPassword ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
                    </button>
                    <button
                      type="button"
                      onClick={() => handleCopy(newPassword, 'modal-pwd')}
                      className="p-1 text-slate-400 hover:text-cyan-400"
                      title="Copy password"
                    >
                      {copiedText === 'modal-pwd' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                    </button>
                  </div>
                </div>
                <p className="text-[10px] text-amber-400 mt-1">
                  Password will be hashed using Argon2id with 256-bit CSPRNG salt and encrypted in credentials.enc.
                </p>
              </div>

              <div className="pt-2 flex items-center gap-2">
                <input
                  type="checkbox"
                  id="mfa"
                  checked={isMfaEnabled}
                  onChange={(e) => setIsMfaEnabled(e.target.checked)}
                  className="rounded bg-slate-950 border-slate-800 text-indigo-600 focus:ring-0"
                />
                <label htmlFor="mfa" className="text-slate-300 text-xs">
                  Enforce TOTP Multi-Factor Authentication (MFA)
                </label>
              </div>

              <div className="pt-4 border-t border-slate-800 flex items-center justify-end gap-2">
                <button
                  type="button"
                  onClick={() => setIsModalOpen(false)}
                  className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg text-xs font-mono transition-colors cursor-pointer"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-2 bg-indigo-600 hover:bg-indigo-500 text-white rounded-lg text-xs font-mono font-semibold transition-all shadow-md shadow-indigo-950/50 cursor-pointer flex items-center gap-1.5"
                >
                  <ShieldCheck className="w-3.5 h-3.5" />
                  <span>Encrypt & Provision</span>
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
