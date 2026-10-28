/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState } from 'react';
import { 
  ShieldCheck, 
  Cpu, 
  Activity, 
  Layers, 
  Zap, 
  CheckCircle2, 
  ArrowRight,
  Radio,
  Clock,
  Briefcase,
  TrendingUp,
  FileCheck
} from 'lucide-react';
import { PlaneTopologyGraph } from './d3/PlaneTopologyGraph.tsx';
import { ThroughputStreamChart } from './d3/ThroughputStreamChart.tsx';

interface Props {
  devMode: boolean;
  onNavigateToCode: (filePath: string) => void;
}

export const ArchitectureView: React.FC<Props> = ({ devMode, onNavigateToCode }) => {
  const [selectedPlane, setSelectedPlane] = useState<'data' | 'inference' | 'telemetry' | 'control'>('data');

  return (
    <div className="space-y-8">
      {/* Top Banner / Core Thesis */}
      <div className="bg-gradient-to-r from-slate-900 via-indigo-950 to-slate-900 border border-indigo-900/60 rounded-xl p-6 shadow-xl relative overflow-hidden">
        <div className="absolute right-0 top-0 w-96 h-96 bg-indigo-500/10 rounded-full blur-3xl pointer-events-none" />
        <div className="relative z-10 flex flex-col md:flex-row md:items-center justify-between gap-6">
          <div>
            <div className="flex items-center gap-2 mb-2">
              <span className="px-2.5 py-0.5 rounded-full text-xs font-mono font-medium bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">
                {devMode ? 'PHP & NODE.JS ROOT DIRECTORY INGRESS' : 'ROOT WEBSITE IMMUNITY'}
              </span>
              <span className="px-2.5 py-0.5 rounded-full text-xs font-mono font-medium bg-indigo-500/20 text-indigo-300 border border-indigo-500/30">
                {devMode ? 'DATA SCIENCE INGESTION PARADIGM' : 'ZERO CUSTOMER FRICTION'}
              </span>
            </div>
            <h2 className="text-2xl font-bold text-white tracking-tight">
              {devMode
                ? 'Root Directory Web Application Firewall Architecture'
                : 'Executive Security & Threat Immunity Architecture'}
            </h2>
            <p className="text-slate-300 text-sm mt-1 max-w-3xl leading-relaxed">
              {devMode
                ? 'Engineered to install directly in the website root directory (public_html/ or /). Intercepts HTTP traffic before CMS or application frameworks execute, tokenizing raw byte streams and evaluating deep learning anomaly reconstruction loss in microsecond execution windows with zero regex vulnerabilities.'
                : 'Autonomous AI protection safeguarding your customer transactions, database assets, and digital operations. Unlike legacy firewalls that break legitimate users and slow down checkout, NeuralWAF sits at the root ingress of your website, delivering instant threat neutralization with zero false alarms.'}
            </p>
          </div>

          <div className="grid grid-cols-2 gap-3 min-w-[280px]">
            <div className="bg-slate-800/80 border border-slate-700/60 rounded-lg p-3">
              <div className="text-xs text-slate-400 flex items-center gap-1.5 font-mono">
                <Clock className="w-3.5 h-3.5 text-cyan-400" />
                {devMode ? 'Latency SLA' : 'User Speed Impact'}
              </div>
              <div className="text-xl font-bold text-white mt-1 font-mono">
                {devMode ? '≤ 3.5 ms' : '0.00 ms Delay'}
              </div>
              <div className="text-[11px] text-cyan-400">
                {devMode ? 'Microsecond timeout' : 'Imperceptible to customers'}
              </div>
            </div>
            <div className="bg-slate-800/80 border border-slate-700/60 rounded-lg p-3">
              <div className="text-xs text-slate-400 flex items-center gap-1.5 font-mono">
                <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
                {devMode ? 'Memory Policy' : 'System Availability'}
              </div>
              <div className="text-xl font-bold text-white mt-1 font-mono">
                {devMode ? 'Zero-Alloc' : '99.999%'}
              </div>
              <div className="text-[11px] text-emerald-400">
                {devMode ? 'sync.Pool amortized' : 'Always online guarantee'}
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* D3 Multi-Plane Topology Diagram */}
      <PlaneTopologyGraph devMode={devMode} />

      {/* D3 Live Throughput Stream Chart */}
      <ThroughputStreamChart devMode={devMode} />

      {/* Sovereign Execution Planes Cards */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-lg">
        <div className="flex items-center justify-between mb-6">
          <div>
            <h3 className="text-lg font-bold text-white flex items-center gap-2">
              <Layers className="w-5 h-5 text-indigo-400" />
              {devMode ? 'Sovereign Execution Planes Detail' : 'Core Protective Layers'}
            </h3>
            <p className="text-xs text-slate-400 mt-0.5">
              {devMode
                ? 'Select any plane below to inspect its production Go implementation details, concurrency guarantees, and memory boundaries.'
                : 'Click any protective layer below to understand how it guards your customers and business infrastructure.'}
            </p>
          </div>
          <div className="flex gap-2">
            {(['data', 'inference', 'telemetry', 'control'] as const).map((plane) => (
              <button
                key={plane}
                onClick={() => setSelectedPlane(plane)}
                className={`px-3 py-1.5 rounded-lg text-xs font-mono transition-all capitalize ${
                  selectedPlane === plane
                    ? 'bg-indigo-600 text-white shadow-md shadow-indigo-600/30'
                    : 'bg-slate-800 text-slate-300 hover:bg-slate-700'
                }`}
              >
                {plane} Plane
              </button>
            ))}
          </div>
        </div>

        {/* Visual Workflow Cards */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4 relative">
          {/* Data Plane Card */}
          <div
            onClick={() => setSelectedPlane('data')}
            className={`cursor-pointer rounded-xl p-5 border transition-all relative ${
              selectedPlane === 'data'
                ? 'bg-indigo-950/40 border-indigo-500 shadow-lg shadow-indigo-950/50 ring-1 ring-indigo-500'
                : 'bg-slate-900/80 border-slate-800 hover:border-slate-700'
            }`}
          >
            <div className="flex items-center justify-between mb-3">
              <span className="px-2 py-0.5 rounded text-[11px] font-mono bg-indigo-500/20 text-indigo-300 font-semibold">
                {devMode ? 'Port :8080' : 'Front Gateway'}
              </span>
              <Zap className="w-4 h-4 text-indigo-400" />
            </div>
            <h4 className="text-base font-bold text-white">
              {devMode ? '1. Data Plane' : '1. Fast Ingress Shield'}
            </h4>
            <div className="text-xs font-mono text-slate-400 mt-1">
              {devMode ? 'cmd/edge-proxy/main.go' : 'Traffic Verification'}
            </div>
            <ul className="mt-3 space-y-1.5 text-xs text-slate-300">
              <li className="flex items-center gap-1.5">
                <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                <span>{devMode ? 'net/http/httputil.ReverseProxy' : 'Sub-millisecond customer pass-through'}</span>
              </li>
              <li className="flex items-center gap-1.5">
                <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                <span>{devMode ? 'http.MaxBytesReader (2MB bound)' : 'Protection against massive payload floods'}</span>
              </li>
              <li className="flex items-center gap-1.5">
                <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                <span>{devMode ? 'sync.Pool Tokenizer vectorization' : 'Memory auto-recycling prevents crashes'}</span>
              </li>
            </ul>
            {devMode && (
              <button
                onClick={(e) => {
                  e.stopPropagation();
                  onNavigateToCode('cmd/edge-proxy/main.go');
                }}
                className="mt-4 text-xs font-mono text-indigo-400 hover:text-indigo-300 flex items-center gap-1"
              >
                Inspect Source <ArrowRight className="w-3 h-3" />
              </button>
            )}
          </div>

          {/* Inference Plane Card */}
          <div
            onClick={() => setSelectedPlane('inference')}
            className={`cursor-pointer rounded-xl p-5 border transition-all relative ${
              selectedPlane === 'inference'
                ? 'bg-purple-950/40 border-purple-500 shadow-lg shadow-purple-950/50 ring-1 ring-purple-500'
                : 'bg-slate-900/80 border-slate-800 hover:border-slate-700'
            }`}
          >
            <div className="flex items-center justify-between mb-3">
              <span className="px-2 py-0.5 rounded text-[11px] font-mono bg-purple-500/20 text-purple-300 font-semibold">
                {devMode ? 'Port :50051 (gRPC)' : 'Deep Learning Brain'}
              </span>
              <Cpu className="w-4 h-4 text-purple-400" />
            </div>
            <h4 className="text-base font-bold text-white">
              {devMode ? '2. Inference Plane' : '2. Autonomous AI Defense'}
            </h4>
            <div className="text-xs font-mono text-slate-400 mt-1">
              {devMode ? 'internal/inference/client.go' : 'Zero-Day Detection'}
            </div>
            <ul className="mt-3 space-y-1.5 text-xs text-slate-300">
              <li className="flex items-center gap-1.5">
                <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                <span>{devMode ? 'gRPC ClientPool (16 pre-warmed conns)' : 'Pre-connected neural analysis cluster'}</span>
              </li>
              <li className="flex items-center gap-1.5">
                <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                <span>{devMode ? 'context.WithTimeout (3.5ms SLA)' : 'Strict 3.5ms maximum analysis deadline'}</span>
              </li>
              <li className="flex items-center gap-1.5">
                <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                <span>{devMode ? 'LSTM Autoencoder MSE evaluation' : 'Flags abnormal hacker syntax without rules'}</span>
              </li>
            </ul>
            {devMode && (
              <button
                onClick={(e) => {
                  e.stopPropagation();
                  onNavigateToCode('internal/inference/client.go');
                }}
                className="mt-4 text-xs font-mono text-purple-400 hover:text-purple-300 flex items-center gap-1"
              >
                Inspect Source <ArrowRight className="w-3 h-3" />
              </button>
            )}
          </div>

          {/* Telemetry Plane Card */}
          <div
            onClick={() => setSelectedPlane('telemetry')}
            className={`cursor-pointer rounded-xl p-5 border transition-all relative ${
              selectedPlane === 'telemetry'
                ? 'bg-cyan-950/40 border-cyan-500 shadow-lg shadow-cyan-950/50 ring-1 ring-cyan-500'
                : 'bg-slate-900/80 border-slate-800 hover:border-slate-700'
            }`}
          >
            <div className="flex items-center justify-between mb-3">
              <span className="px-2 py-0.5 rounded text-[11px] font-mono bg-cyan-500/20 text-cyan-300 font-semibold">
                {devMode ? 'Port :9092 (Kafka)' : 'Incident Stream'}
              </span>
              <Radio className="w-4 h-4 text-cyan-400" />
            </div>
            <h4 className="text-base font-bold text-white">
              {devMode ? '3. Telemetry Plane' : '3. Zima MDR Audit Trail'}
            </h4>
            <div className="text-xs font-mono text-slate-400 mt-1">
              {devMode ? 'internal/telemetry/kafka.go' : 'Real-Time Threat Intel'}
            </div>
            <ul className="mt-3 space-y-1.5 text-xs text-slate-300">
              <li className="flex items-center gap-1.5">
                <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                <span>{devMode ? 'Non-blocking select ring buffer' : 'Zero-delay incident dispatching'}</span>
              </li>
              <li className="flex items-center gap-1.5">
                <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                <span>{devMode ? 'Zero-wait atomic drop on saturation' : 'Web store never freezes on audit delays'}</span>
              </li>
              <li className="flex items-center gap-1.5">
                <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                <span>{devMode ? 'Streams to Zima MDR (snappy batch)' : 'Compliant forensic records & SOC alerts'}</span>
              </li>
            </ul>
            {devMode && (
              <button
                onClick={(e) => {
                  e.stopPropagation();
                  onNavigateToCode('internal/telemetry/kafka.go');
                }}
                className="mt-4 text-xs font-mono text-cyan-400 hover:text-cyan-300 flex items-center gap-1"
              >
                Inspect Source <ArrowRight className="w-3 h-3" />
              </button>
            )}
          </div>

          {/* Control Plane Card */}
          <div
            onClick={() => setSelectedPlane('control')}
            className={`cursor-pointer rounded-xl p-5 border transition-all relative ${
              selectedPlane === 'control'
                ? 'bg-amber-950/40 border-amber-500 shadow-lg shadow-amber-950/50 ring-1 ring-amber-500'
                : 'bg-slate-900/80 border-slate-800 hover:border-slate-700'
            }`}
          >
            <div className="flex items-center justify-between mb-3">
              <span className="px-2 py-0.5 rounded text-[11px] font-mono bg-amber-500/20 text-amber-300 font-semibold">
                {devMode ? 'Port :9090 (Admin)' : 'Health & Control'}
              </span>
              <Activity className="w-4 h-4 text-amber-400" />
            </div>
            <h4 className="text-base font-bold text-white">
              {devMode ? '4. Control Plane' : '4. Operational Health'}
            </h4>
            <div className="text-xs font-mono text-slate-400 mt-1">
              {devMode ? 'cmd/edge-proxy/main.go' : 'Governance & Tuning'}
            </div>
            <ul className="mt-3 space-y-1.5 text-xs text-slate-300">
              <li className="flex items-center gap-1.5">
                <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                <span>{devMode ? 'Prometheus /metrics endpoint' : 'Automated 24/7 reliability monitoring'}</span>
              </li>
              <li className="flex items-center gap-1.5">
                <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                <span>{devMode ? '/healthz & /readyz probes' : 'Kubernetes zero-downtime health probes'}</span>
              </li>
              <li className="flex items-center gap-1.5">
                <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                <span>{devMode ? 'Dynamic threshold reloader' : 'Live sensitivity adjustment without restart'}</span>
              </li>
            </ul>
            {devMode && (
              <button
                onClick={(e) => {
                  e.stopPropagation();
                  onNavigateToCode('configs/waf.yaml');
                }}
                className="mt-4 text-xs font-mono text-amber-400 hover:text-amber-300 flex items-center gap-1"
              >
                Inspect Config <ArrowRight className="w-3 h-3" />
              </button>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
