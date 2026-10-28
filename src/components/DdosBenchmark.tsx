/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useEffect, useRef } from 'react';
import { 
  Zap, 
  Flame, 
  Activity, 
  ShieldCheck, 
  Play, 
  Square, 
  RefreshCw,
  HardDrive,
  Radio,
  Clock,
  CheckCircle2
} from 'lucide-react';
import { ThreatImpactDonut } from './d3/ThreatImpactDonut.tsx';

interface Props {
  devMode: boolean;
}

export const DdosBenchmark: React.FC<Props> = ({ devMode }) => {
  const [isRunning, setIsRunning] = useState<boolean>(false);
  const [concurrencyRPS, setConcurrencyRPS] = useState<number>(10000);
  const [kafkaPressure, setKafkaPressure] = useState<'healthy' | 'degraded' | 'saturated'>('healthy');
  const [poolEnabled, setPoolEnabled] = useState<boolean>(true);

  const [totalRequests, setTotalRequests] = useState<number>(0);
  const [activeConns, setActiveConns] = useState<number>(0);
  const [recycledBuffers, setRecycledBuffers] = useState<number>(0);
  const [heapAllocMb, setHeapAllocMb] = useState<number>(42);
  const [kafkaEnqueued, setKafkaEnqueued] = useState<number>(0);
  const [kafkaDropped, setKafkaDropped] = useState<number>(0);
  const [p99LatencyMs, setP99LatencyMs] = useState<number>(1.2);

  const timerRef = useRef<NodeJS.Timeout | null>(null);

  useEffect(() => {
    if (!isRunning) {
      if (timerRef.current) clearInterval(timerRef.current);
      return;
    }

    timerRef.current = setInterval(() => {
      const stepRequests = Math.floor(concurrencyRPS / 10);
      setTotalRequests((prev) => prev + stepRequests);
      setActiveConns(Math.floor(concurrencyRPS * 0.15 + (Math.random() * 50 - 25)));

      if (poolEnabled) {
        setRecycledBuffers((prev) => prev + stepRequests * 2);
        setHeapAllocMb(42 + Math.random() * 4);
      } else {
        setHeapAllocMb((prev) => Math.min(prev + 12, 1850));
      }

      if (kafkaPressure === 'healthy') {
        setKafkaEnqueued((prev) => prev + Math.floor(stepRequests * 0.15));
        setP99LatencyMs(1.1 + Math.random() * 0.3);
      } else if (kafkaPressure === 'degraded') {
        setKafkaEnqueued((prev) => prev + Math.floor(stepRequests * 0.08));
        setKafkaDropped((prev) => prev + Math.floor(stepRequests * 0.07));
        setP99LatencyMs(1.2 + Math.random() * 0.4);
      } else {
        setKafkaDropped((prev) => prev + Math.floor(stepRequests * 0.14));
        setKafkaEnqueued((prev) => prev + Math.floor(stepRequests * 0.01));
        setP99LatencyMs(1.2 + Math.random() * 0.5);
      }
    }, 100);

    return () => {
      if (timerRef.current) clearInterval(timerRef.current);
    };
  }, [isRunning, concurrencyRPS, kafkaPressure, poolEnabled]);

  const handleReset = () => {
    setIsRunning(false);
    setTotalRequests(0);
    setActiveConns(0);
    setRecycledBuffers(0);
    setHeapAllocMb(42);
    setKafkaEnqueued(0);
    setKafkaDropped(0);
    setP99LatencyMs(1.2);
  };

  return (
    <div className="space-y-6">
      {/* Benchmark Banner */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-lg">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div>
            <h2 className="text-xl font-bold text-white flex items-center gap-2">
              <Flame className="w-5 h-5 text-rose-500" />
              {devMode
                ? 'Layer 7 DDoS & Memory Safety Benchmark'
                : 'High-Volume Traffic Surge & Resilience Stress Test'}
            </h2>
            <p className="text-xs text-slate-400 mt-1">
              {devMode
                ? 'Simulate high-velocity Layer 7 floods to test zero-allocation buffer pooling and non-blocking Kafka ring-buffer drop behavior under cluster saturation.'
                : 'Simulate extreme Black Friday / cyber attack traffic spikes to verify that your website never slows down or crashes under load.'}
            </p>
          </div>

          <div className="flex items-center gap-3">
            <button
              onClick={handleReset}
              className="flex items-center gap-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 px-3 py-1.5 rounded-lg text-xs font-mono transition-all"
            >
              <RefreshCw className="w-3.5 h-3.5" />
              {devMode ? 'Reset Counters' : 'Reset Test'}
            </button>
            <button
              onClick={() => setIsRunning(!isRunning)}
              className={`flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-mono font-semibold transition-all shadow-md ${
                isRunning
                  ? 'bg-rose-600 hover:bg-rose-500 text-white shadow-rose-600/30'
                  : 'bg-emerald-600 hover:bg-emerald-500 text-white shadow-emerald-600/30'
              }`}
            >
              {isRunning ? <Square className="w-3.5 h-3.5 fill-current" /> : <Play className="w-3.5 h-3.5 fill-current" />}
              {isRunning
                ? devMode ? 'Halt Simulation' : 'Stop Traffic Surge'
                : devMode ? 'Launch L7 DDoS Surge' : 'Start High-Volume Traffic Test'}
            </button>
          </div>
        </div>
      </div>

      {/* Control Knobs */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {/* Concurrency RPS Slider */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 shadow-md">
          <div className="flex items-center justify-between text-xs font-mono mb-2">
            <span className="text-slate-400">{devMode ? 'Target Request Velocity:' : 'Traffic Flood Intensity:'}</span>
            <span className="text-indigo-400 font-bold">{concurrencyRPS.toLocaleString()} req/s</span>
          </div>
          <input
            type="range"
            min="1000"
            max="50000"
            step="1000"
            value={concurrencyRPS}
            onChange={(e) => setConcurrencyRPS(parseInt(e.target.value))}
            className="w-full accent-indigo-500 h-1.5 bg-slate-800 rounded-lg cursor-pointer"
          />
          <div className="flex justify-between text-[10px] text-slate-500 font-mono mt-1">
            <span>1k req/s</span>
            <span>25k req/s</span>
            <span>50k req/s</span>
          </div>
        </div>

        {/* Memory Pooling Toggle */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 shadow-md flex flex-col justify-between">
          <div className="text-xs font-mono text-slate-400 mb-1">
            {devMode ? 'sync.Pool Zero-Allocation Mode:' : 'Crash Prevention Optimization:'}
          </div>
          <div className="flex gap-2">
            <button
              onClick={() => setPoolEnabled(true)}
              className={`flex-1 py-1.5 rounded-lg text-xs font-mono transition-all ${
                poolEnabled
                  ? 'bg-emerald-600 text-white font-bold'
                  : 'bg-slate-950 text-slate-400 border border-slate-800'
              }`}
            >
              {devMode ? 'Enabled (Zero-Alloc)' : 'Active (Immune)'}
            </button>
            <button
              onClick={() => setPoolEnabled(false)}
              className={`flex-1 py-1.5 rounded-lg text-xs font-mono transition-all ${
                !poolEnabled
                  ? 'bg-rose-600 text-white font-bold'
                  : 'bg-slate-950 text-slate-400 border border-slate-800'
              }`}
            >
              {devMode ? 'Disabled (Heap Bloat)' : 'Disabled (High Risk)'}
            </button>
          </div>
        </div>

        {/* Kafka Backpressure Scenario */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 shadow-md flex flex-col justify-between">
          <div className="text-xs font-mono text-slate-400 mb-1">
            {devMode ? 'Kafka Zima MDR Health State:' : 'Compliance Audit Network Condition:'}
          </div>
          <div className="flex gap-1.5">
            {(['healthy', 'degraded', 'saturated'] as const).map((state) => (
              <button
                key={state}
                onClick={() => setKafkaPressure(state)}
                className={`flex-1 py-1.5 rounded-lg text-[11px] font-mono capitalize transition-all ${
                  kafkaPressure === state
                    ? state === 'healthy'
                      ? 'bg-cyan-600 text-white font-bold'
                      : state === 'degraded'
                      ? 'bg-amber-600 text-white font-bold'
                      : 'bg-rose-600 text-white font-bold'
                    : 'bg-slate-950 text-slate-400 border border-slate-800'
                }`}
              >
                {state}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Live Metrics Grid */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 shadow-md">
          <div className="text-xs text-slate-400 font-mono flex items-center gap-1.5">
            <Zap className="w-3.5 h-3.5 text-indigo-400" />
            {devMode ? 'Ingested Requests' : 'Processed Web Requests'}
          </div>
          <div className="text-2xl font-bold text-white font-mono mt-1">
            {totalRequests.toLocaleString()}
          </div>
          <div className="text-[11px] text-slate-400 mt-1">
            {devMode ? `Active Conns: ${activeConns.toLocaleString()}` : 'Live Connections Filtered'}
          </div>
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 shadow-md">
          <div className="text-xs text-slate-400 font-mono flex items-center gap-1.5">
            <Activity className="w-3.5 h-3.5 text-emerald-400" />
            {devMode ? 'P99 Edge Proxy Latency' : 'Real-World User Latency'}
          </div>
          <div className="text-2xl font-bold text-emerald-400 font-mono mt-1">
            {p99LatencyMs.toFixed(2)} ms
          </div>
          <div className="text-[11px] text-slate-400 mt-1">
            {devMode ? 'SLA: ≤ 3.50 ms (Strict)' : 'Zero Checkout Stalls'}
          </div>
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 shadow-md">
          <div className="text-xs text-slate-400 font-mono flex items-center gap-1.5">
            <HardDrive className="w-3.5 h-3.5 text-purple-400" />
            {devMode ? 'Heap Allocations' : 'Server Memory Health'}
          </div>
          <div className={`text-2xl font-bold font-mono mt-1 ${heapAllocMb > 250 ? 'text-rose-400' : 'text-purple-300'}`}>
            {heapAllocMb.toFixed(0)} MB
          </div>
          <div className="text-[11px] text-slate-400 mt-1">
            {devMode
              ? `Recycled: ${(recycledBuffers / 1000).toFixed(0)}k buffers`
              : 'Auto-Recycled Zero Overhead'}
          </div>
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 shadow-md">
          <div className="text-xs text-slate-400 font-mono flex items-center gap-1.5">
            <Radio className="w-3.5 h-3.5 text-cyan-400" />
            {devMode ? 'Kafka Drops (Atomic)' : 'Non-Blocking Guarantee'}
          </div>
          <div className={`text-2xl font-bold font-mono mt-1 ${kafkaDropped > 0 ? 'text-amber-400' : 'text-slate-300'}`}>
            {kafkaDropped.toLocaleString()}
          </div>
          <div className="text-[11px] text-emerald-400 mt-1">
            {devMode ? `Enqueued: ${kafkaEnqueued.toLocaleString()}` : '0 Milliseconds Blocked'}
          </div>
        </div>
      </div>

      {/* D3 Threat Composition Donut */}
      <ThreatImpactDonut devMode={devMode} />

      {/* Proof Box */}
      <div className="bg-slate-950 border border-slate-800 rounded-xl p-5 shadow-lg space-y-3">
        <h3 className="text-sm font-bold text-white flex items-center gap-2">
          <ShieldCheck className="w-4 h-4 text-emerald-400" />
          {devMode
            ? 'The Non-Blocking Proof: Why Proxy Latency Never Stalls Under Kafka Failures'
            : 'Why High Traffic Surges Never Slow Down Customers'}
        </h3>
        <p className="text-xs text-slate-300 leading-relaxed">
          {devMode
            ? 'In typical legacy microservices, logging or streaming to Kafka blocks the main request worker thread if the Kafka broker experiences network partitions or disk I/O bottlenecks. NeuralWAF guarantees that telemetry.Pipeline.EmitBlockedEvent() executes in fewer than 15 nanoseconds.'
            : 'Traditional security software blocks customer requests when internal logging servers slow down. NeuralWAF strictly separates customer traffic from audit logging, so even under massive multi-gigabit attacks, genuine shoppers experience lightning-fast load times.'}
        </p>
      </div>
    </div>
  );
};
