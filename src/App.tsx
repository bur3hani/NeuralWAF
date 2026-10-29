/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState } from 'react';
import { 
  ShieldCheck, 
  Layers, 
  Code2, 
  Zap, 
  Flame, 
  Brain, 
  Download, 
  Terminal, 
  Cpu, 
  Radio, 
  ToggleLeft,
  ToggleRight,
  Code,
  Briefcase,
  Menu,
  X,
  ChevronLeft,
  ChevronRight,
  Activity,
  CheckCircle2,
  Server,
  KeyRound
} from 'lucide-react';

import { ArchitectureView } from './components/ArchitectureView.tsx';
import { CodeExplorer } from './components/CodeExplorer.tsx';
import { DataPlaneSimulator } from './components/DataPlaneSimulator.tsx';
import { DdosBenchmark } from './components/DdosBenchmark.tsx';
import { DeepLearningExplainer } from './components/DeepLearningExplainer.tsx';
import { ProductionRunbook } from './components/ProductionRunbook.tsx';
import { MetricCards } from './components/MetricCards.tsx';
import { UserManagementView } from './components/UserManagementView.tsx';
import { CODE_FILES } from './data/codebase.ts';

type NavigationTab = 'architecture' | 'runbook' | 'code' | 'users' | 'simulator' | 'ddos' | 'deeplearning';

interface NavItemConfig {
  id: NavigationTab;
  title: string;
  execTitle: string;
  subtitle: string;
  execSubtitle: string;
  icon: React.ComponentType<{ className?: string }>;
  accentColor: string;
  badge?: string;
  pulse?: boolean;
}

const NAV_ITEMS: { category: string; items: NavItemConfig[] }[] = [
  {
    category: 'Architecture & Setup',
    items: [
      {
        id: 'architecture',
        title: 'Architecture Blueprint',
        execTitle: 'Enterprise Topology',
        subtitle: 'Dual-tier PHP & Node ingress',
        execSubtitle: 'Autonomous zero-delay shield',
        icon: Layers,
        accentColor: 'text-indigo-400 group-hover:text-indigo-300',
      },
      {
        id: 'runbook',
        title: 'Runbook & Setup',
        execTitle: 'Deployment Playbook',
        subtitle: 'cPanel, Apache & LiteSpeed',
        execSubtitle: 'Zero downtime rollout',
        icon: Terminal,
        accentColor: 'text-emerald-400 group-hover:text-emerald-300',
      },
      {
        id: 'code',
        title: 'Production Code',
        execTitle: 'Firewall Codebase',
        subtitle: 'Root directory scripts',
        execSubtitle: 'Audited source files',
        icon: Code2,
        accentColor: 'text-purple-400 group-hover:text-purple-300',
        badge: `${CODE_FILES.length}`,
      },
      {
        id: 'users',
        title: 'User Management & RBAC',
        execTitle: 'Operator Access & Vault',
        subtitle: 'Argon2id vault & zero secrets',
        execSubtitle: 'Encrypted credentials & roles',
        icon: KeyRound,
        accentColor: 'text-indigo-400 group-hover:text-indigo-300',
        badge: 'AUTH',
      },
    ],
  },
  {
    category: 'Live Labs & Telemetry',
    items: [
      {
        id: 'simulator',
        title: 'Ingestion & D3 Simulator',
        execTitle: 'Live Traffic Monitor',
        subtitle: 'Byte tokenizer & IP heatmap',
        execSubtitle: 'Real-time threat neutralizer',
        icon: Zap,
        accentColor: 'text-amber-400 group-hover:text-amber-300',
        badge: 'LIVE',
        pulse: true,
      },
      {
        id: 'ddos',
        title: 'L7 DDoS Stress Lab',
        execTitle: 'Resilience Benchmark',
        subtitle: 'Zero-leak ring buffers',
        execSubtitle: 'High-volume attack defense',
        icon: Flame,
        accentColor: 'text-rose-400 group-hover:text-rose-300',
      },
      {
        id: 'deeplearning',
        title: 'Deep Learning Math',
        execTitle: 'AI Anomaly Science',
        subtitle: 'LSTM autoencoder vectors',
        execSubtitle: 'Zero-day behavioral detection',
        icon: Brain,
        accentColor: 'text-cyan-400 group-hover:text-cyan-300',
      },
    ],
  },
];

export default function App() {
  const [activeTab, setActiveTab] = useState<NavigationTab>('architecture');
  const [selectedCodePath, setSelectedCodePath] = useState<string>('neuralwaf/bootstrap.php');
  const [devMode, setDevMode] = useState<boolean>(true);
  const [isSidebarCollapsed, setIsSidebarCollapsed] = useState<boolean>(false);
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState<boolean>(false);

  const handleNavigateToCode = (filePath: string) => {
    setSelectedCodePath(filePath);
    setActiveTab('code');
    setIsMobileMenuOpen(false);
  };

  const handleSelectTab = (tab: NavigationTab) => {
    setActiveTab(tab);
    setIsMobileMenuOpen(false);
  };

  const handleDownloadAllCode = () => {
    let bundle = `# NEURALWAF PURE PHP ROOT WEB APPLICATION FIREWALL (PHP 7.4 - 8.3+)\n# 100% pure PHP codebase with LSTM Autoencoder sequence anomaly detection\n# Zero-dependency website root package for Apache, LiteSpeed, Nginx, and cPanel\n\n`;
    for (const f of CODE_FILES) {
      bundle += `================================================================================\n`;
      bundle += `FILE: ${f.path} (${f.plane})\n`;
      bundle += `DESCRIPTION: ${f.description}\n`;
      bundle += `================================================================================\n\n`;
      bundle += f.content;
      bundle += `\n\n`;
    }

    const blob = new Blob([bundle], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = 'neuralwaf-root-package.txt';
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  // Find current active item title for breadcrumb
  const currentItem = NAV_ITEMS.flatMap(g => g.items).find(i => i.id === activeTab);

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex font-sans selection:bg-indigo-500/30">
      {/* Mobile Drawer Overlay */}
      {isMobileMenuOpen && (
        <div 
          className="fixed inset-0 bg-slate-950/80 backdrop-blur-sm z-40 lg:hidden"
          onClick={() => setIsMobileMenuOpen(false)}
          aria-hidden="true"
        />
      )}

      {/* Modern Sidebar Navigation */}
      <aside 
        className={`fixed top-0 bottom-0 left-0 z-50 flex flex-col bg-slate-900 border-r border-slate-800 transition-all duration-300 ease-in-out ${
          isMobileMenuOpen ? 'translate-x-0 w-72' : '-translate-x-full lg:translate-x-0'
        } ${isSidebarCollapsed ? 'lg:w-20' : 'lg:w-72'}`}
      >
        {/* Sidebar Header & Brand */}
        <div className="h-16 px-4 border-b border-slate-800 flex items-center justify-between shrink-0">
          <div className="flex items-center gap-3 overflow-hidden">
            <div className="w-9 h-9 rounded-xl bg-gradient-to-tr from-indigo-600 via-purple-600 to-cyan-500 flex items-center justify-center shadow-lg shadow-indigo-600/30 shrink-0">
              <ShieldCheck className="w-5 h-5 text-white" />
            </div>
            {(!isSidebarCollapsed || isMobileMenuOpen) && (
              <div className="min-w-0">
                <div className="flex items-center gap-2">
                  <span className="font-bold text-white text-base tracking-tight truncate">NeuralWAF</span>
                  <span className="px-1.5 py-0.5 rounded text-[9px] font-mono bg-violet-500/20 text-violet-300 border border-violet-500/30 font-semibold">
                    PHP Core
                  </span>
                </div>
                <div className="text-[10px] text-slate-400 font-mono truncate">
                  {devMode ? 'Pure PHP Deep Learning WAF' : 'Autonomous AI Defense'}
                </div>
              </div>
            )}
          </div>

          {/* Close button for mobile */}
          <button
            onClick={() => setIsMobileMenuOpen(false)}
            className="p-1.5 text-slate-400 hover:text-white rounded-lg hover:bg-slate-800 lg:hidden"
            aria-label="Close menu"
          >
            <X className="w-5 h-5" />
          </button>

          {/* Collapse/Expand button for desktop */}
          <button
            onClick={() => setIsSidebarCollapsed(!isSidebarCollapsed)}
            className="hidden lg:flex p-1.5 text-slate-400 hover:text-white rounded-lg hover:bg-slate-800 transition-colors"
            title={isSidebarCollapsed ? 'Expand sidebar' : 'Collapse sidebar'}
            aria-label={isSidebarCollapsed ? 'Expand sidebar' : 'Collapse sidebar'}
          >
            {isSidebarCollapsed ? (
              <ChevronRight className="w-4 h-4" />
            ) : (
              <ChevronLeft className="w-4 h-4" />
            )}
          </button>
        </div>

        {/* Sidebar Nav Items */}
        <div className="flex-1 overflow-y-auto px-3 py-4 space-y-6">
          {NAV_ITEMS.map((group, groupIdx) => (
            <div key={groupIdx} className="space-y-1">
              {(!isSidebarCollapsed || isMobileMenuOpen) && (
                <div className="px-3 pb-1 text-[10px] font-mono uppercase tracking-wider text-slate-500 font-semibold">
                  {group.category}
                </div>
              )}
              {group.items.map((item) => {
                const IconComponent = item.icon;
                const isActive = activeTab === item.id;
                const title = devMode ? item.title : item.execTitle;
                const subtitle = devMode ? item.subtitle : item.execSubtitle;

                return (
                  <button
                    key={item.id}
                    onClick={() => handleSelectTab(item.id)}
                    title={isSidebarCollapsed && !isMobileMenuOpen ? title : undefined}
                    className={`w-full group relative flex items-center rounded-xl transition-all ${
                      isSidebarCollapsed && !isMobileMenuOpen
                        ? 'p-3 justify-center'
                        : 'px-3.5 py-2.5 gap-3 justify-start'
                    } ${
                      isActive
                        ? 'bg-indigo-600/15 text-white border border-indigo-500/40 shadow-sm shadow-indigo-950/50'
                        : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60 border border-transparent'
                    }`}
                  >
                    {/* Active Indicator Bar on Left */}
                    {isActive && (
                      <span className="absolute left-0 top-2 bottom-2 w-1 bg-gradient-to-b from-indigo-500 to-cyan-500 rounded-r-full" />
                    )}

                    <div className="shrink-0 flex items-center justify-center">
                      <IconComponent
                        className={`w-5 h-5 transition-transform duration-200 group-hover:scale-110 ${
                          isActive ? 'text-indigo-400' : item.accentColor
                        }`}
                      />
                    </div>

                    {(!isSidebarCollapsed || isMobileMenuOpen) && (
                      <div className="flex-1 min-w-0 text-left">
                        <div className="flex items-center justify-between gap-1">
                          <span
                            className={`text-xs font-semibold truncate ${
                              isActive ? 'text-white' : 'text-slate-300'
                            }`}
                          >
                            {title}
                          </span>
                          {item.badge && (
                            <span
                              className={`shrink-0 px-1.5 py-0.2 rounded text-[9px] font-mono font-bold flex items-center gap-1 ${
                                item.badge === 'LIVE'
                                  ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                                  : 'bg-slate-800 text-slate-300 border border-slate-700'
                              }`}
                            >
                              {item.pulse && (
                                <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-ping" />
                              )}
                              {item.badge}
                            </span>
                          )}
                        </div>
                        <p className="text-[10px] text-slate-500 truncate font-mono">
                          {subtitle}
                        </p>
                      </div>
                    )}
                  </button>
                );
              })}
            </div>
          ))}
        </div>

        {/* Sidebar Health Status & Quick Action Footer */}
        {(!isSidebarCollapsed || isMobileMenuOpen) ? (
          <div className="p-3 border-t border-slate-800 bg-slate-950/60 space-y-3 shrink-0">
            {/* Live System Health Box */}
            <div className="p-2.5 rounded-lg bg-slate-900 border border-slate-800/80 space-y-1.5 font-mono text-[10px]">
              <div className="flex items-center justify-between text-slate-400 font-semibold border-b border-slate-800/60 pb-1">
                <span className="flex items-center gap-1 text-slate-300">
                  <Activity className="w-3 h-3 text-cyan-400" />
                  {devMode ? 'Root Daemon Health' : 'Protection Status'}
                </span>
                <span className="text-emerald-400 flex items-center gap-1">
                  <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
                  {devMode ? 'ONLINE' : 'ACTIVE'}
                </span>
              </div>
              <div className="flex items-center justify-between text-slate-400">
                <span>PHP Hook:</span>
                <span className="text-slate-200">auto_prepend</span>
              </div>
              <div className="flex items-center justify-between text-slate-400">
                <span>AI Engine:</span>
                <span className="text-slate-200">Pure PHP LSTM</span>
              </div>
              <div className="flex items-center justify-between text-slate-400">
                <span>Latent SLA:</span>
                <span className="text-cyan-400 font-bold">&lt; 0.35 ms</span>
              </div>
            </div>

            {/* Quick Export Code Button */}
            <button
              onClick={handleDownloadAllCode}
              className="w-full flex items-center justify-center gap-2 bg-slate-800 hover:bg-slate-700 text-slate-200 hover:text-white border border-slate-700/80 px-3 py-2 rounded-lg text-xs font-mono transition-all shadow-sm"
              title="Download consolidated codebase package"
            >
              <Download className="w-3.5 h-3.5 text-indigo-400" />
              <span>Export Codebase ({CODE_FILES.length})</span>
            </button>
          </div>
        ) : (
          <div className="p-2 border-t border-slate-800 flex flex-col items-center gap-2 shrink-0">
            <button
              onClick={handleDownloadAllCode}
              className="p-2.5 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg border border-slate-700 transition-colors"
              title="Export Codebase"
              aria-label="Export Codebase"
            >
              <Download className="w-4 h-4 text-indigo-400" />
            </button>
          </div>
        )}
      </aside>

      {/* Main Content Viewport */}
      <div 
        className={`flex-1 flex flex-col min-w-0 transition-all duration-300 ease-in-out ${
          isSidebarCollapsed ? 'lg:pl-20' : 'lg:pl-72'
        }`}
      >
        {/* Enterprise Top Header */}
        <header className="bg-slate-900/90 backdrop-blur-md border-b border-slate-800 sticky top-0 z-30">
          <div className="px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between gap-4">
            {/* Left: Mobile hamburger & Active View Breadcrumb */}
            <div className="flex items-center gap-3 min-w-0">
              <button
                onClick={() => setIsMobileMenuOpen(true)}
                className="p-2 text-slate-400 hover:text-white rounded-lg hover:bg-slate-800 lg:hidden shrink-0"
                aria-label="Open navigation sidebar"
              >
                <Menu className="w-5 h-5" />
              </button>

              <div className="min-w-0">
                <div className="flex items-center gap-2">
                  <span className="text-xs font-mono text-slate-400 hidden sm:inline">NeuralWAF Root</span>
                  <span className="text-slate-600 hidden sm:inline">/</span>
                  <span className="text-sm font-bold text-white tracking-tight truncate">
                    {devMode ? currentItem?.title : currentItem?.execTitle}
                  </span>
                </div>
                <p className="text-[11px] text-slate-400 font-mono truncate hidden md:block">
                  {devMode ? currentItem?.subtitle : currentItem?.execSubtitle}
                </p>
              </div>
            </div>

            {/* Right: Mode Switcher & Sockets indicators */}
            <div className="flex items-center gap-3 shrink-0">
              {/* Prominent Developer vs Executive Mode Switcher */}
              <button
                onClick={() => setDevMode(!devMode)}
                aria-label="Toggle between Developer Mode and Executive Mode"
                className={`flex items-center gap-2 px-3 py-1.5 rounded-xl border text-xs font-mono font-semibold transition-all shadow-md ${
                  devMode
                    ? 'bg-indigo-950/80 border-indigo-500 text-indigo-300 ring-1 ring-indigo-500/40 shadow-indigo-950/50'
                    : 'bg-emerald-950/80 border-emerald-500 text-emerald-300 ring-1 ring-emerald-500/40 shadow-emerald-950/50'
                }`}
              >
                {devMode ? (
                  <>
                    <Code className="w-3.5 h-3.5 text-indigo-400" />
                    <span className="hidden sm:inline">Mode:</span>
                    <span className="text-white font-bold">Developer</span>
                    <ToggleRight className="w-4 h-4 text-indigo-400" />
                  </>
                ) : (
                  <>
                    <Briefcase className="w-3.5 h-3.5 text-emerald-400" />
                    <span className="hidden sm:inline">Mode:</span>
                    <span className="text-white font-bold">Executive</span>
                    <ToggleLeft className="w-4 h-4 text-emerald-400" />
                  </>
                )}
              </button>

              {/* Sockets / Planes Indicators */}
              <div className="hidden xl:flex items-center gap-2 text-xs font-mono bg-slate-950 px-3 py-1.5 rounded-lg border border-slate-800">
                <span className="flex items-center gap-1.5 text-violet-400">
                  <span className="w-2 h-2 rounded-full bg-violet-500 animate-pulse" />
                  {devMode ? 'PHP Ingress' : 'PHP Shield'}
                </span>
                <span className="text-slate-600">|</span>
                <span className="flex items-center gap-1.5 text-emerald-400">
                  <Cpu className="w-3.5 h-3.5" />
                  {devMode ? 'PHP LSTM Engine' : 'Neural Defense'}
                </span>
                <span className="text-slate-600">|</span>
                <span className="flex items-center gap-1.5 text-cyan-400">
                  <Radio className="w-3.5 h-3.5" />
                  {devMode ? 'Argon2id Vault' : 'Encrypted RBAC'}
                </span>
              </div>

              {/* Header Export Button */}
              <button
                onClick={handleDownloadAllCode}
                className="hidden sm:flex items-center gap-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 px-3 py-1.5 rounded-lg text-xs font-mono transition-all"
                title="Download consolidated codebase package"
              >
                <Download className="w-3.5 h-3.5 text-indigo-400" />
                <span className="hidden md:inline">Export Codebase</span>
              </button>
            </div>
          </div>
        </header>

        {/* Workspace Main Body */}
        <main className="flex-1 p-4 sm:p-6 lg:p-8 space-y-6 max-w-7xl w-full mx-auto">
          {/* Dual-Delivery KPI Metric Cards */}
          <MetricCards devMode={devMode} />

          {/* Active Navigation View */}
          {activeTab === 'architecture' && (
            <ArchitectureView devMode={devMode} onNavigateToCode={handleNavigateToCode} />
          )}
          {activeTab === 'runbook' && (
            <ProductionRunbook devMode={devMode} />
          )}
          {activeTab === 'code' && (
            <CodeExplorer initialFilePath={selectedCodePath} />
          )}
          {activeTab === 'users' && (
            <UserManagementView devMode={devMode} />
          )}
          {activeTab === 'simulator' && (
            <DataPlaneSimulator devMode={devMode} />
          )}
          {activeTab === 'ddos' && (
            <DdosBenchmark devMode={devMode} />
          )}
          {activeTab === 'deeplearning' && (
            <DeepLearningExplainer />
          )}
        </main>

        {/* Enterprise Bottom Status Footer */}
        <footer className="bg-slate-900 border-t border-slate-800 py-4 px-4 sm:px-6 lg:px-8 text-xs text-slate-400 mt-auto">
          <div className="max-w-7xl mx-auto flex flex-col sm:flex-row items-center justify-between gap-3">
            <div className="flex items-center gap-2">
              <span className="font-semibold text-white">NeuralWAF by BuruOps</span>
              <span>·</span>
              <span className="text-indigo-400 font-mono">Open Source</span>
              <span>·</span>
              <span className="text-emerald-400 font-mono flex items-center gap-1">
                <CheckCircle2 className="w-3.5 h-3.5" />
                {devMode ? 'Argon2id + AES-256-GCM Vault' : 'Zero Secrets in Git'}
              </span>
            </div>
            <div className="font-mono text-[11px] text-slate-500 flex items-center gap-2">
              <span>Maintained by BuruOps (engr.buru@gmail.com)</span>
              <span>·</span>
              <span>MIT License 2026</span>
            </div>
          </div>
        </footer>
      </div>
    </div>
  );
}
