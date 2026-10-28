/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React from 'react';
import { 
  Brain, 
  Cpu, 
  Layers, 
  AlertTriangle, 
  CheckCircle2, 
  Binary, 
  Network,
  Sigma,
  Activity,
  ArrowRight
} from 'lucide-react';

export const DeepLearningExplainer: React.FC = () => {
  return (
    <div className="space-y-8">
      {/* Overview Banner */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-xl">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2 mb-2">
              <span className="px-2.5 py-0.5 rounded-full text-xs font-mono font-medium bg-purple-500/20 text-purple-300 border border-purple-500/30">
                DATA SCIENCE CONSTITUTION
              </span>
              <span className="px-2.5 py-0.5 rounded-full text-xs font-mono font-medium bg-rose-500/20 text-rose-300 border border-rose-500/30">
                ZERO STATIC REGEX POLICY
              </span>
            </div>
            <h2 className="text-2xl font-bold text-white tracking-tight">
              LSTM Autoencoder Anomaly Detection Engine
            </h2>
            <p className="text-slate-300 text-sm mt-1 max-w-3xl leading-relaxed">
              Why NeuralWAF rejects static signature rules: traditional WAFs rely on brittle regular expressions that suffer from catastrophic backtracking (ReDoS) and trivial evasion.
              NeuralWAF treats the edge proxy strictly as a feature ingestion pipeline for a sequence-to-sequence deep learning Autoencoder.
            </p>
          </div>
        </div>
      </div>

      {/* Comparison: Why Regex Rules Fail vs Why Deep Learning Wins */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* The Flaws of Static Regex */}
        <div className="bg-slate-900/90 border border-rose-900/40 rounded-xl p-6 shadow-lg">
          <div className="flex items-center gap-2 text-rose-400 font-bold text-base mb-3">
            <AlertTriangle className="w-5 h-5 text-rose-500" />
            Flaws of Traditional Regex-Based WAFs
          </div>
          <ul className="space-y-3 text-xs text-slate-300">
            <li className="flex items-start gap-2">
              <span className="text-rose-400 font-mono font-bold">[X]</span>
              <div>
                <strong className="text-white">ReDoS Vulnerabilities:</strong>
                <p className="text-slate-400 mt-0.5">
                  Complex nested regexes (e.g., ModSecurity CRS) suffer from polynomial or exponential backtracking when evaluated on crafted inputs, pinning CPU cores at 100%.
                </p>
              </div>
            </li>
            <li className="flex items-start gap-2">
              <span className="text-rose-400 font-mono font-bold">[X]</span>
              <div>
                <strong className="text-white">Trivial Evasion & Obfuscation:</strong>
                <p className="text-slate-400 mt-0.5">
                  Attackers bypass string matches using SQL comment interleaving (<code className="text-rose-300 font-mono">UN/**/ION</code>), Unicode normalization quirks, or base64 wrappers.
                </p>
              </div>
            </li>
            <li className="flex items-start gap-2">
              <span className="text-rose-400 font-mono font-bold">[X]</span>
              <div>
                <strong className="text-white">Blind to Zero-Days:</strong>
                <p className="text-slate-400 mt-0.5">
                  Static rules only match previously identified exploit signatures. Novel protocol deviations or zero-days bypass regex filters entirely.
                </p>
              </div>
            </li>
          </ul>
        </div>

        {/* The Power of LSTM Autoencoders */}
        <div className="bg-slate-900/90 border border-emerald-900/40 rounded-xl p-6 shadow-lg">
          <div className="flex items-center gap-2 text-emerald-400 font-bold text-base mb-3">
            <CheckCircle2 className="w-5 h-5 text-emerald-500" />
            Advantages of NeuralWAF LSTM Autoencoder
          </div>
          <ul className="space-y-3 text-xs text-slate-300">
            <li className="flex items-start gap-2">
              <span className="text-emerald-400 font-mono font-bold">[OK]</span>
              <div>
                <strong className="text-white">Deterministic O(N) Ingestion Time:</strong>
                <p className="text-slate-400 mt-0.5">
                  Tokenization in Go runs in strictly bounded linear time with zero memory allocations (<code className="text-emerald-300 font-mono">sync.Pool</code>), completely immune to ReDoS.
                </p>
              </div>
            </li>
            <li className="flex items-start gap-2">
              <span className="text-emerald-400 font-mono font-bold">[OK]</span>
              <div>
                <strong className="text-white">Grammar Reconstruction Loss:</strong>
                <p className="text-slate-400 mt-0.5">
                  The model learns the statistical latent grammar of benign application traffic. Payloads exhibiting high Mean Squared Error (MSE) are blocked regardless of evasion syntax.
                </p>
              </div>
            </li>
            <li className="flex items-start gap-2">
              <span className="text-emerald-400 font-mono font-bold">[OK]</span>
              <div>
                <strong className="text-white">Sub-Millisecond TensorRT Execution:</strong>
                <p className="text-slate-400 mt-0.5">
                  The Python/C++ inference server compiles the model to TensorRT INT8/FP16, evaluating batches in &lt;1.5 milliseconds over high-speed gRPC streams.
                </p>
              </div>
            </li>
          </ul>
        </div>
      </div>

      {/* Model Mathematics & Tensor Architecture */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-lg space-y-6">
        <h3 className="text-lg font-bold text-white flex items-center gap-2">
          <Sigma className="w-5 h-5 text-indigo-400" />
          Mathematical Formulation & Tensor Shapes
        </h3>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Stage 1: Embedding */}
          <div className="bg-slate-950 p-4 rounded-xl border border-slate-800 space-y-2">
            <div className="text-xs font-mono text-indigo-400 uppercase tracking-wider font-semibold">
              1. Input Embedding Matrix
            </div>
            <div className="text-base font-bold text-white font-mono">
              X in Tensor(1, L, D)
            </div>
            <p className="text-xs text-slate-400 leading-relaxed">
              HTTP streams are tokenized into sequences of length <code className="text-indigo-300 font-mono">L = 1024</code>.
              Each token index is mapped to a continuous dense vector of dimension <code className="text-indigo-300 font-mono">D = 64</code>.
            </p>
          </div>

          {/* Stage 2: Latent Compression */}
          <div className="bg-slate-950 p-4 rounded-xl border border-slate-800 space-y-2">
            <div className="text-xs font-mono text-purple-400 uppercase tracking-wider font-semibold">
              2. Latent Bottleneck
            </div>
            <div className="text-base font-bold text-white font-mono">
              z = LSTM_enc(X) in Tensor(1, 128)
            </div>
            <p className="text-xs text-slate-400 leading-relaxed">
              The encoder compresses sequential dependencies into a low-dimensional bottleneck vector <code className="text-purple-300 font-mono">z</code>, capturing the semantic structure of normal HTTP queries.
            </p>
          </div>

          {/* Stage 3: Reconstruction MSE */}
          <div className="bg-slate-950 p-4 rounded-xl border border-slate-800 space-y-2">
            <div className="text-xs font-mono text-cyan-400 uppercase tracking-wider font-semibold">
              3. Reconstruction Loss MSE
            </div>
            <div className="text-base font-bold text-white font-mono">
              MSE = (1/N) * sum((x_i - x_hat_i)^2)
            </div>
            <p className="text-xs text-slate-400 leading-relaxed">
              The decoder attempts to reconstruct <code className="text-cyan-300 font-mono">X_hat</code> from <code className="text-cyan-300 font-mono">z</code>.
              Benign traffic yields <code className="text-emerald-400 font-mono">MSE &lt; 0.05</code>; malicious payloads yield <code className="text-rose-400 font-mono">MSE &ge; 0.65</code>.
            </p>
          </div>
        </div>

        {/* Visual Tensor Pipeline */}
        <div className="bg-slate-950 p-5 rounded-xl border border-slate-800/80">
          <div className="text-xs font-mono text-slate-400 uppercase tracking-wider mb-4">
            Tensor Pipeline Flow: Ingestion to Anomaly Score
          </div>

          <div className="flex flex-col md:flex-row items-center justify-between gap-3 text-xs font-mono">
            <div className="bg-slate-900 border border-slate-800 p-3 rounded-lg text-center flex-1 w-full">
              <div className="text-slate-400">Raw HTTP Stream</div>
              <div className="text-white font-bold mt-1">URI, Headers, Body</div>
              <div className="text-[10px] text-indigo-400 mt-1">cmd/edge-proxy</div>
            </div>

            <ArrowRight className="w-4 h-4 text-slate-600 hidden md:block shrink-0" />

            <div className="bg-slate-900 border border-slate-800 p-3 rounded-lg text-center flex-1 w-full">
              <div className="text-slate-400">Token Sequence</div>
              <div className="text-white font-bold mt-1">[1024] uint32</div>
              <div className="text-[10px] text-emerald-400 mt-1">internal/tokenizer</div>
            </div>

            <ArrowRight className="w-4 h-4 text-slate-600 hidden md:block shrink-0" />

            <div className="bg-slate-900 border border-slate-800 p-3 rounded-lg text-center flex-1 w-full">
              <div className="text-slate-400">gRPC Payload</div>
              <div className="text-white font-bold mt-1">InferenceRequest</div>
              <div className="text-[10px] text-purple-400 mt-1">api/inference.proto</div>
            </div>

            <ArrowRight className="w-4 h-4 text-slate-600 hidden md:block shrink-0" />

            <div className="bg-slate-900 border border-slate-800 p-3 rounded-lg text-center flex-1 w-full">
              <div className="text-slate-400">LSTM Autoencoder</div>
              <div className="text-white font-bold mt-1">Reconstruction Loss</div>
              <div className="text-[10px] text-cyan-400 mt-1">TensorRT Engine</div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
