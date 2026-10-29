/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useMemo } from 'react';
import { 
  FileCode, 
  Copy, 
  Check, 
  Download, 
  Search, 
  Folder, 
  Layers, 
  Zap, 
  Cpu, 
  Radio, 
  FileText,
  ChevronRight,
  ExternalLink,
  Code2
} from 'lucide-react';
import { CODE_FILES, CodeFile } from '../data/codebase.ts';

export const CodeExplorer: React.FC<{ initialFilePath?: string }> = ({ initialFilePath }) => {
  const [selectedPath, setSelectedPath] = useState<string>(initialFilePath || 'neuralwaf/bootstrap.php');
  const [activeStackFilter, setActiveStackFilter] = useState<'all' | 'php' | 'node' | 'enterprise'>('all');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [copied, setCopied] = useState<boolean>(false);

  const activeFile = useMemo(() => {
    return CODE_FILES.find((f) => f.path === selectedPath) || CODE_FILES[0];
  }, [selectedPath]);

  const filteredFiles = useMemo(() => {
    let files = CODE_FILES;
    if (activeStackFilter === 'php') {
      files = files.filter(f => f.plane === 'PHP Root Interceptor' || f.language === 'php' || f.path.startsWith('neuralwaf/') || f.path === 'composer.json' || f.path === '.htaccess' || f.path === '.user.ini');
    } else if (activeStackFilter === 'node') {
      files = files.filter(f => f.plane === 'Node.js Root Engine' || f.language === 'javascript');
    } else if (activeStackFilter === 'enterprise') {
      files = files.filter(f => f.language === 'go' || f.language === 'protobuf' || f.plane === 'DevOps & Orchestration');
    }

    if (!searchQuery.trim()) return files;
    const q = searchQuery.toLowerCase();
    return files.filter(
      (f) =>
        f.path.toLowerCase().includes(q) ||
        f.description.toLowerCase().includes(q) ||
        f.content.toLowerCase().includes(q)
    );
  }, [searchQuery, activeStackFilter]);

  const handleCopy = () => {
    navigator.clipboard.writeText(activeFile.content);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleDownloadFile = () => {
    const blob = new Blob([activeFile.content], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = activeFile.name;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  const lines = useMemo(() => {
    return activeFile.content.split('\n');
  }, [activeFile]);

  // Syntax highlighting helper for PHP, JS, Go, Proto, Yaml, Ini, Htaccess
  const renderHighlightedLine = (line: string) => {
    const trimmed = line.trim();
    if (trimmed.startsWith('//') || trimmed.startsWith('#') || trimmed.startsWith(';') || trimmed.startsWith('/*') || trimmed.startsWith('*')) {
      return <span className="text-slate-500 italic">{line}</span>;
    }
    if (trimmed.startsWith('<?php') || trimmed.startsWith('namespace ') || trimmed.startsWith('package ') || trimmed.startsWith('import ') || trimmed.startsWith('syntax =') || trimmed.startsWith("'use strict'")) {
      return <span className="text-purple-400 font-semibold">{line}</span>;
    }
    if (line.includes('class ') || line.includes('function ') || line.includes('func ') || line.includes('type ') || line.includes('service ') || line.includes('message ')) {
      return <span className="text-amber-300 font-semibold">{line}</span>;
    }
    if (line.includes('return ') || line.includes('if ') || line.includes('else ') || line.includes('select ') || line.includes('case ') || line.includes('const ') || line.includes('let ')) {
      return <span className="text-indigo-400 font-medium">{line}</span>;
    }
    if (line.includes('auto_prepend_file') || line.includes('RewriteRule') || line.includes('auto_prepend_file') || line.includes('neuralWafMiddleware') || line.includes('RootBootstrap') || line.includes('sync.Pool') || line.includes('ReverseProxy') || line.includes('MaxBytesReader')) {
      return <span className="text-emerald-300 font-bold bg-emerald-950/40 px-1 rounded">{line}</span>;
    }
    if (line.includes('$_SERVER') || line.includes('header(') || line.includes('http_response_code') || line.includes('req.headers') || line.includes('res.writeHead')) {
      return <span className="text-cyan-300 font-mono">{line}</span>;
    }
    return <span className="text-slate-200">{line}</span>;
  };

  const getPlaneBadgeColor = (plane: CodeFile['plane']) => {
    switch (plane) {
      case 'PHP Root Interceptor':
        return 'bg-violet-500/20 text-violet-300 border-violet-500/30';
      case 'Node.js Root Engine':
        return 'bg-emerald-500/20 text-emerald-300 border-emerald-500/30';
      case 'Data Plane':
        return 'bg-indigo-500/20 text-indigo-300 border-indigo-500/30';
      case 'Inference Plane':
        return 'bg-purple-500/20 text-purple-300 border-purple-500/30';
      case 'Telemetry Plane':
        return 'bg-cyan-500/20 text-cyan-300 border-cyan-500/30';
      case 'Configuration':
        return 'bg-amber-500/20 text-amber-300 border-amber-500/30';
      case 'DevOps & Orchestration':
        return 'bg-teal-500/20 text-teal-300 border-teal-500/30';
      default:
        return 'bg-slate-500/20 text-slate-300 border-slate-500/30';
    }
  };

  return (
    <div className="space-y-6">
      {/* Code Explorer Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-lg">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-violet-500/20 text-violet-300 border border-violet-500/30 font-semibold">
              PHP 7.4 - 8.3+
            </span>
            <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 font-semibold">
              Node.js 18 - 22+
            </span>
            <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-indigo-500/20 text-indigo-300 border border-indigo-500/30 font-semibold">
              Root Directory Drop-In
            </span>
          </div>
          <h2 className="text-xl font-bold text-white flex items-center gap-2">
            <Code2 className="w-5 h-5 text-indigo-400" />
            Production Codebase & Root Package Explorer
          </h2>
          <p className="text-xs text-slate-400 mt-1">
            Browse and inspect complete, production-ready code designed to sit directly in your website root directory (<code className="text-indigo-300">public_html/</code> or <code className="text-indigo-300">/</code>).
          </p>
        </div>

        <div className="flex items-center gap-2">
          <div className="relative">
            <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              placeholder="Search code or files..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="bg-slate-950 border border-slate-700/80 rounded-lg pl-9 pr-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-indigo-500 w-52"
            />
          </div>
          <button
            onClick={handleDownloadFile}
            className="flex items-center gap-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 px-3 py-1.5 rounded-lg text-xs font-mono transition-all"
            title="Download active file"
          >
            <Download className="w-3.5 h-3.5" />
            Download
          </button>
          <button
            onClick={handleCopy}
            className="flex items-center gap-1.5 bg-indigo-600 hover:bg-indigo-500 text-white px-3 py-1.5 rounded-lg text-xs font-mono transition-all shadow-md shadow-indigo-600/30"
          >
            {copied ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
            {copied ? 'Copied!' : 'Copy Code'}
          </button>
        </div>
      </div>

      {/* Main Split Layout: Left File Tree, Right Code Viewer */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Column: File Tree */}
        <div className="lg:col-span-4 space-y-3">
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 shadow-md">
            {/* Stack Filter Buttons */}
            <div className="flex items-center gap-1.5 mb-3.5 overflow-x-auto pb-1">
              <button
                onClick={() => setActiveStackFilter('all')}
                className={`px-2.5 py-1 rounded-md text-xs font-mono transition-all ${
                  activeStackFilter === 'all'
                    ? 'bg-indigo-600 text-white font-bold shadow'
                    : 'bg-slate-800 text-slate-300 hover:bg-slate-700'
                }`}
              >
                All ({CODE_FILES.length})
              </button>
              <button
                onClick={() => setActiveStackFilter('php')}
                className={`px-2.5 py-1 rounded-md text-xs font-mono transition-all ${
                  activeStackFilter === 'php'
                    ? 'bg-violet-600 text-white font-bold shadow'
                    : 'bg-slate-800 text-slate-300 hover:bg-slate-700'
                }`}
              >
                PHP Core WAF
              </button>
              <button
                onClick={() => setActiveStackFilter('node')}
                className={`px-2.5 py-1 rounded-md text-xs font-mono transition-all ${
                  activeStackFilter === 'node'
                    ? 'bg-emerald-600 text-white font-bold shadow'
                    : 'bg-slate-800 text-slate-300 hover:bg-slate-700'
                }`}
              >
                Node.js Root
              </button>
              <button
                onClick={() => setActiveStackFilter('enterprise')}
                className={`px-2.5 py-1 rounded-md text-xs font-mono transition-all ${
                  activeStackFilter === 'enterprise'
                    ? 'bg-cyan-600 text-white font-bold shadow'
                    : 'bg-slate-800 text-slate-300 hover:bg-slate-700'
                }`}
              >
                Go / Edge
              </button>
            </div>

            <div className="text-xs font-mono text-slate-400 uppercase tracking-wider mb-3 flex items-center justify-between">
              <span className="flex items-center gap-1.5">
                <Folder className="w-4 h-4 text-slate-400" />
                Root Files ({filteredFiles.length})
              </span>
              <span className="text-[10px] text-slate-500 lowercase">public_html/</span>
            </div>

            <div className="space-y-1.5">
              {filteredFiles.map((file) => {
                const isSelected = file.path === selectedPath;
                return (
                  <button
                    key={file.path}
                    onClick={() => setSelectedPath(file.path)}
                    className={`w-full text-left p-2.5 rounded-lg border transition-all flex flex-col gap-1 ${
                      isSelected
                        ? 'bg-indigo-950/50 border-indigo-500/80 shadow-md ring-1 ring-indigo-500/30'
                        : 'bg-slate-950/60 border-slate-800/80 hover:bg-slate-800/50 hover:border-slate-700'
                    }`}
                  >
                    <div className="flex items-center justify-between">
                      <span className="font-mono text-xs font-semibold text-white flex items-center gap-2 truncate">
                        <FileCode className={`w-3.5 h-3.5 ${isSelected ? 'text-indigo-400' : 'text-slate-400'}`} />
                        {file.path}
                      </span>
                      <span className={`text-[10px] font-mono px-2 py-0.5 rounded border ${getPlaneBadgeColor(file.plane)}`}>
                        {file.plane}
                      </span>
                    </div>
                    <p className="text-[11px] text-slate-400 line-clamp-1 pl-5">
                      {file.description}
                    </p>
                  </button>
                );
              })}
            </div>
          </div>

          {/* Active File Architecture Highlights */}
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 shadow-md">
            <h4 className="text-xs font-mono text-slate-400 uppercase tracking-wider mb-2 flex items-center gap-1.5">
              <Zap className="w-3.5 h-3.5 text-amber-400" />
              Engineering Patterns in {activeFile.name}
            </h4>
            <ul className="space-y-2 mt-3">
              {activeFile.keyFeatures.map((feat, idx) => (
                <li key={idx} className="flex items-start gap-2 text-xs text-slate-300">
                  <div className="w-1.5 h-1.5 rounded-full bg-emerald-400 mt-1.5 shrink-0" />
                  <span>{feat}</span>
                </li>
              ))}
            </ul>
          </div>
        </div>

        {/* Right Column: Code Viewer */}
        <div className="lg:col-span-8">
          <div className="bg-slate-950 border border-slate-800 rounded-xl shadow-xl overflow-hidden flex flex-col">
            {/* Code Header Bar */}
            <div className="bg-slate-900/90 border-b border-slate-800 px-4 py-3 flex items-center justify-between">
              <div className="flex items-center gap-2 font-mono text-xs">
                <span className="text-slate-400">path:</span>
                <span className="text-emerald-400 font-semibold">{activeFile.path}</span>
                <span className="text-slate-600">|</span>
                <span className="text-slate-400">{lines.length} lines</span>
              </div>
              <div className="flex items-center gap-2">
                <span className={`text-[10px] font-mono px-2 py-0.5 rounded border ${getPlaneBadgeColor(activeFile.plane)}`}>
                  {activeFile.plane}
                </span>
              </div>
            </div>

            {/* Code Body with Line Numbers */}
            <div className="overflow-x-auto p-4 max-h-[750px] overflow-y-auto font-mono text-xs leading-relaxed selection:bg-indigo-500/30">
              <table className="w-full border-collapse">
                <tbody>
                  {lines.map((line, idx) => (
                    <tr key={idx} className="hover:bg-slate-900/40">
                      <td className="pr-4 py-0.5 text-right text-slate-600 select-none text-[11px] font-mono w-10">
                        {idx + 1}
                      </td>
                      <td className="py-0.5 whitespace-pre font-mono">
                        {renderHighlightedLine(line)}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
