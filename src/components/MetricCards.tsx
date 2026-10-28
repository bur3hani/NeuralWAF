/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React from 'react';
import { 
  Clock, 
  ShieldCheck, 
  HardDrive, 
  CheckCircle2, 
  Activity,
  ArrowUpRight
} from 'lucide-react';
import { 
  formatLatencyMetric, 
  formatMemoryMetric, 
  formatThreatMetric 
} from '../utils/metrics-transformer.ts';

interface Props {
  devMode: boolean;
  totalRequests?: number;
  blockedCount?: number;
  p99LatencyUs?: number;
  heapAllocMb?: number;
  pooledBuffers?: number;
}

export const MetricCards: React.FC<Props> = ({
  devMode,
  totalRequests = 142850,
  blockedCount = 8940,
  p99LatencyUs = 1200,
  heapAllocMb = 44,
  pooledBuffers = 184000,
}) => {
  const latencySummary = formatLatencyMetric(p99LatencyUs);
  const memorySummary = formatMemoryMetric(heapAllocMb, pooledBuffers);
  const threatSummary = formatThreatMetric(blockedCount, totalRequests);

  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
      {/* KPI 1: Speed & Latency */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 shadow-md relative overflow-hidden flex flex-col justify-between">
        <div className="flex items-center justify-between mb-2">
          <span className="text-xs font-mono text-slate-400">
            {devMode ? latencySummary.developer.technicalLabel : latencySummary.executive.businessLabel}
          </span>
          <div className="w-7 h-7 rounded-lg bg-cyan-500/10 border border-cyan-500/20 flex items-center justify-center text-cyan-400">
            <Clock className="w-4 h-4" />
          </div>
        </div>

        <div>
          <div className="text-2xl font-bold font-mono text-white">
            {devMode ? latencySummary.developer.primaryValue : latencySummary.executive.primaryValue}
          </div>
          <div className="text-xs font-mono text-cyan-400 mt-0.5 flex items-center gap-1 font-semibold">
            {devMode ? latencySummary.developer.secondaryValue : latencySummary.executive.secondaryValue}
            <ArrowUpRight className="w-3 h-3" />
          </div>
        </div>

        <div className="text-[11px] text-slate-400 mt-3 pt-2.5 border-t border-slate-800/80">
          {devMode ? latencySummary.developer.subtext : latencySummary.executive.subtext}
        </div>
      </div>

      {/* KPI 2: Attack Neutralization & Saved Costs */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 shadow-md relative overflow-hidden flex flex-col justify-between">
        <div className="flex items-center justify-between mb-2">
          <span className="text-xs font-mono text-slate-400">
            {devMode ? threatSummary.developer.technicalLabel : threatSummary.executive.businessLabel}
          </span>
          <div className="w-7 h-7 rounded-lg bg-rose-500/10 border border-rose-500/20 flex items-center justify-center text-rose-400">
            <ShieldCheck className="w-4 h-4" />
          </div>
        </div>

        <div>
          <div className="text-2xl font-bold font-mono text-white">
            {devMode ? threatSummary.developer.primaryValue : threatSummary.executive.primaryValue}
          </div>
          <div className="text-xs font-mono text-emerald-400 mt-0.5 flex items-center gap-1 font-semibold">
            {devMode ? threatSummary.developer.secondaryValue : threatSummary.executive.secondaryValue}
            <ArrowUpRight className="w-3 h-3" />
          </div>
        </div>

        <div className="text-[11px] text-slate-400 mt-3 pt-2.5 border-t border-slate-800/80">
          {devMode ? threatSummary.developer.subtext : threatSummary.executive.subtext}
        </div>
      </div>

      {/* KPI 3: Memory Footprint & Infrastructure Stability */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 shadow-md relative overflow-hidden flex flex-col justify-between">
        <div className="flex items-center justify-between mb-2">
          <span className="text-xs font-mono text-slate-400">
            {devMode ? memorySummary.developer.technicalLabel : memorySummary.executive.businessLabel}
          </span>
          <div className="w-7 h-7 rounded-lg bg-purple-500/10 border border-purple-500/20 flex items-center justify-center text-purple-400">
            <HardDrive className="w-4 h-4" />
          </div>
        </div>

        <div>
          <div className="text-2xl font-bold font-mono text-white">
            {devMode ? memorySummary.developer.primaryValue : memorySummary.executive.primaryValue}
          </div>
          <div className="text-xs font-mono text-purple-400 mt-0.5 flex items-center gap-1 font-semibold">
            {devMode ? memorySummary.developer.secondaryValue : memorySummary.executive.secondaryValue}
            <ArrowUpRight className="w-3 h-3" />
          </div>
        </div>

        <div className="text-[11px] text-slate-400 mt-3 pt-2.5 border-t border-slate-800/80">
          {devMode ? memorySummary.developer.subtext : memorySummary.executive.subtext}
        </div>
      </div>

      {/* KPI 4: Multi-Plane Health & Service Availability */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 shadow-md relative overflow-hidden flex flex-col justify-between">
        <div className="flex items-center justify-between mb-2">
          <span className="text-xs font-mono text-slate-400">
            {devMode ? 'Enterprise Plane Synchronization' : 'Business Service Availability'}
          </span>
          <div className="w-7 h-7 rounded-lg bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center text-emerald-400">
            <Activity className="w-4 h-4" />
          </div>
        </div>

        <div>
          <div className="text-2xl font-bold font-mono text-emerald-400">
            {devMode ? 'Root Ingress Active' : '99.999% Uptime'}
          </div>
          <div className="text-xs font-mono text-emerald-300 mt-0.5 flex items-center gap-1 font-semibold">
            {devMode ? 'PHP Hook · Node.js · gRPC' : '0 Downtime Incidents'}
            <CheckCircle2 className="w-3 h-3 text-emerald-400" />
          </div>
        </div>

        <div className="text-[11px] text-slate-400 mt-3 pt-2.5 border-t border-slate-800/80">
          {devMode
            ? 'Pre-Execution Ingress · 0.2ms overhead · Ingested: 142k'
            : 'Uninterrupted enterprise shopping & API access'}
        </div>
      </div>
    </div>
  );
};
