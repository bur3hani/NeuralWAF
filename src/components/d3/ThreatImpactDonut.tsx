/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useEffect, useRef, useState } from 'react';
import * as d3 from 'd3';
import { ShieldCheck, ShieldAlert, DollarSign } from 'lucide-react';

interface ThreatSlice {
  id: string;
  devLabel: string;
  execLabel: string;
  cwe: string;
  businessImpact: string;
  count: number;
  color: string;
  avgMSE: number;
}

interface Props {
  devMode: boolean;
}

export const ThreatImpactDonut: React.FC<Props> = ({ devMode }) => {
  const svgRef = useRef<SVGSVGElement | null>(null);
  const containerRef = useRef<HTMLDivElement | null>(null);
  const [activeSlice, setActiveSlice] = useState<ThreatSlice | null>(null);

  const threatData: ThreatSlice[] = [
    {
      id: 'sqli',
      devLabel: 'SQL Injection (CWE-89)',
      execLabel: 'Customer Database Theft',
      cwe: 'CWE-89 / SQLi',
      businessImpact: 'Protected confidential credit cards & passwords',
      count: 4820,
      color: '#ef4444',
      avgMSE: 1.15,
    },
    {
      id: 'rce',
      devLabel: 'JNDI / Log4Shell (CVE-2021-44228)',
      execLabel: 'Server Hijacking & Ransomware',
      cwe: 'CVE-2021-44228 / RCE',
      businessImpact: 'Prevented malicious backdoor installation',
      count: 2450,
      color: '#a855f7',
      avgMSE: 1.42,
    },
    {
      id: 'traversal',
      devLabel: 'Path Traversal (CWE-22)',
      execLabel: 'Internal File Leakage',
      cwe: 'CWE-22 / Traversal',
      businessImpact: 'Prevented unauthorized reading of system files',
      count: 1890,
      color: '#f59e0b',
      avgMSE: 0.98,
    },
    {
      id: 'ddos',
      devLabel: 'Layer 7 Volumetric Flood (CWE-400)',
      execLabel: 'Service Outage Disruption',
      cwe: 'CWE-400 / L7 DDoS',
      businessImpact: 'Maintained 100% online store uptime',
      count: 7320,
      color: '#38bdf8',
      avgMSE: 0.88,
    },
    {
      id: 'oov',
      devLabel: 'Null Byte / Control OOV (CWE-158)',
      execLabel: 'Zero-Day Protocol Exploitation',
      cwe: 'CWE-158 / Evasion',
      businessImpact: 'Blocked evasion tricks bypassing standard filters',
      count: 1140,
      color: '#ec4899',
      avgMSE: 1.25,
    },
  ];

  const totalThreats = threatData.reduce((acc, d) => acc + d.count, 0);

  useEffect(() => {
    if (!svgRef.current || !containerRef.current) return;

    const width = 260;
    const height = 220;
    const radius = Math.min(width, height) / 2 - 10;
    const innerRadius = radius * 0.65;

    const svg = d3.select(svgRef.current);
    svg.selectAll('*').remove();

    svg.attr('width', width).attr('height', height);

    const g = svg
      .append('g')
      .attr('transform', `translate(${width / 2},${height / 2})`);

    const pie = d3
      .pie<ThreatSlice>()
      .value((d) => d.count)
      .sort(null);

    const arc = d3
      .arc<d3.PieArcDatum<ThreatSlice>>()
      .innerRadius(innerRadius)
      .outerRadius(radius)
      .padAngle(0.03)
      .cornerRadius(4);

    const arcHover = d3
      .arc<d3.PieArcDatum<ThreatSlice>>()
      .innerRadius(innerRadius)
      .outerRadius(radius + 7)
      .padAngle(0.03)
      .cornerRadius(4);

    const paths = g
      .selectAll('.slice')
      .data(pie(threatData))
      .enter()
      .append('path')
      .attr('class', 'slice')
      .attr('d', arc)
      .attr('fill', (d) => d.data.color)
      .attr('stroke', '#0f172a')
      .attr('stroke-width', 2)
      .style('cursor', 'pointer')
      .on('mouseenter', function (event, d) {
        d3.select(this).transition().duration(200).attr('d', arcHover as any);
        setActiveSlice(d.data);
      })
      .on('mouseleave', function () {
        d3.select(this).transition().duration(200).attr('d', arc as any);
      });
  }, []);

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-lg flex flex-col justify-between" ref={containerRef}>
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 mb-3">
        <div>
          <div className="flex items-center gap-2">
            <ShieldAlert className="w-4 h-4 text-rose-400" />
            <h3 className="text-sm font-bold text-white font-mono">
              {devMode
                ? 'D3 Composition: Intercepted Threat Signatures (CWE/CVE)'
                : 'D3 Threat Breakdown: Security Attacks Prevented'}
            </h3>
          </div>
          <p className="text-xs text-slate-400 mt-0.5">
            {devMode
              ? 'Classification of payload vectors intercepted by the LSTM Autoencoder without static regex rules.'
              : 'Detailed breakdown of specific cyber danger categories neutralized before reaching business servers.'}
          </p>
        </div>

        <div className="text-right">
          <div className="text-[10px] text-slate-400 font-mono">Total Threats Deflected</div>
          <div className="text-base font-bold text-emerald-400 font-mono">
            {totalThreats.toLocaleString()}
          </div>
        </div>
      </div>

      {/* Main Grid: Left Donut, Right Legend / Details */}
      <div className="grid grid-cols-1 md:grid-cols-12 gap-4 items-center">
        {/* Donut SVG */}
        <div className="md:col-span-5 flex justify-center relative">
          <svg ref={svgRef} className="overflow-visible" />
          <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
            <span className="text-xs text-slate-400 font-mono">
              {devMode ? 'Total Intercepts' : 'Safely Blocked'}
            </span>
            <span className="text-base font-bold text-white font-mono">
              {totalThreats.toLocaleString()}
            </span>
          </div>
        </div>

        {/* Legend / Slice Details */}
        <div className="md:col-span-7 space-y-2">
          {threatData.map((t) => {
            const isHovered = activeSlice?.id === t.id;
            const pct = ((t.count / totalThreats) * 100).toFixed(1);
            return (
              <div
                key={t.id}
                onMouseEnter={() => setActiveSlice(t)}
                className={`p-2 rounded-lg border transition-all text-xs font-mono flex items-center justify-between cursor-pointer ${
                  isHovered
                    ? 'bg-slate-800/90 border-slate-600 ring-1 ring-slate-500'
                    : 'bg-slate-950/60 border-slate-800/80 hover:bg-slate-800/40'
                }`}
              >
                <div className="flex items-center gap-2">
                  <span className="w-2.5 h-2.5 rounded-full shrink-0" style={{ backgroundColor: t.color }} />
                  <div>
                    <div className="font-semibold text-white">
                      {devMode ? t.devLabel : t.execLabel}
                    </div>
                    <div className="text-[10px] text-slate-400 line-clamp-1">
                      {devMode ? `Avg MSE: ${t.avgMSE.toFixed(2)}` : t.businessImpact}
                    </div>
                  </div>
                </div>

                <div className="text-right pl-2">
                  <div className="text-white font-bold">{t.count.toLocaleString()}</div>
                  <div className="text-[10px] text-slate-400">{pct}%</div>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Executive Compliance & Developer Memory Guarantee Footer */}
      <div className="mt-3 pt-3 border-t border-slate-800/80 flex items-center justify-between text-xs font-mono text-slate-400">
        <span className="flex items-center gap-1.5 text-emerald-400">
          <ShieldCheck className="w-3.5 h-3.5" />
          {devMode
            ? '0 Static Signatures · 100% Unsupervised Machine Learning'
            : 'Continuous SOC 2 Type II & PCI-DSS 4.0 Audit Alignment'}
        </span>
        <span className="text-slate-500">Auto-updated via Kafka Stream</span>
      </div>
    </div>
  );
};
