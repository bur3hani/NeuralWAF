/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useEffect, useRef, useState, useMemo } from 'react';
import * as d3 from 'd3';
import { 
  ShieldAlert, 
  ShieldCheck, 
  Activity, 
  Zap, 
  Flame, 
  Layers, 
  Crosshair, 
  Info,
  Radio
} from 'lucide-react';
import { 
  HeatmapCellData, 
  MONITORED_SUBNETS, 
  HOST_BUCKET_COUNT, 
  HOST_BUCKET_LABELS,
  computeHeatmapAggregates,
  DdosAttackProfile,
  ATTACK_PROFILES
} from '../../utils/ip-density.ts';

interface IpDensityHeatmapProps {
  cells: HeatmapCellData[];
  devMode: boolean;
  activeAttack: DdosAttackProfile;
  isStreaming: boolean;
}

export const IpDensityHeatmap: React.FC<IpDensityHeatmapProps> = ({
  cells,
  devMode,
  activeAttack,
  isStreaming,
}) => {
  const svgRef = useRef<SVGSVGElement | null>(null);
  const containerRef = useRef<HTMLDivElement | null>(null);
  const [hoveredCell, setHoveredCell] = useState<HeatmapCellData | null>(null);
  const [selectedCell, setSelectedCell] = useState<HeatmapCellData | null>(null);
  const [dimensions, setDimensions] = useState({ width: 720, height: 380 });

  const aggregates = useMemo(() => computeHeatmapAggregates(cells), [cells]);

  // Handle container resize
  useEffect(() => {
    if (!containerRef.current) return;
    const observer = new ResizeObserver((entries) => {
      for (const entry of entries) {
        if (entry.contentRect.width > 0) {
          setDimensions({
            width: Math.max(500, Math.floor(entry.contentRect.width)),
            height: Math.max(340, Math.min(420, Math.floor(entry.contentRect.width * 0.45))),
          });
        }
      }
    });
    observer.observe(containerRef.current);
    return () => observer.disconnect();
  }, []);

  // D3 Rendering
  useEffect(() => {
    if (!svgRef.current || cells.length === 0) return;

    const { width, height } = dimensions;
    const margin = {
      top: 36,
      right: 28,
      bottom: 55,
      left: devMode ? 140 : 160,
    };

    const innerWidth = width - margin.left - margin.right;
    const innerHeight = height - margin.top - margin.bottom;

    const svg = d3.select(svgRef.current);
    svg.selectAll('*').remove();
    svg.attr('width', width).attr('height', height).attr('viewBox', `0 0 ${width} ${height}`);

    const g = svg
      .append('g')
      .attr('transform', `translate(${margin.left},${margin.top})`);

    // Y Dimension: Subnet rows
    const ySubnets = MONITORED_SUBNETS.map((s) => s.cidr);
    const yScale = d3
      .scaleBand<string>()
      .domain(ySubnets)
      .range([0, innerHeight])
      .padding(0.08);

    // X Dimension: Host octet buckets
    const xBuckets = Array.from({ length: HOST_BUCKET_COUNT }, (_, i) => i);
    const xScale = d3
      .scaleBand<number>()
      .domain(xBuckets)
      .range([0, innerWidth])
      .padding(0.08);

    // Color Scale: Sequential Heatmap interpolator
    // 0 = Dark slate -> 100-300 RPS = emerald/cyan -> 800+ RPS = amber -> 1800+ = fiery crimson/red-orange
    const maxDensityRps = Math.max(1200, aggregates.maxCellRps);
    const colorScale = d3
      .scaleSequential((t: number) => {
        if (t <= 0.05) return '#0f172a'; // Deep slate
        if (t <= 0.20) return d3.interpolateLab('#0f172a', '#0284c7')(t / 0.20); // Cyan low baseline
        if (t <= 0.45) return d3.interpolateLab('#0284c7', '#10b981')((t - 0.20) / 0.25); // Emerald benign
        if (t <= 0.70) return d3.interpolateLab('#10b981', '#f59e0b')((t - 0.45) / 0.25); // Amber elevated
        if (t <= 0.90) return d3.interpolateLab('#f59e0b', '#ef4444')((t - 0.70) / 0.20); // Crimson attack surge
        return d3.interpolateLab('#ef4444', '#fecdd3')((t - 0.90) / 0.10); // Saturated hot peak
      })
      .domain([0, maxDensityRps]);

    // Defs: Gradients and filters
    const defs = svg.append('defs');
    const glowFilter = defs.append('filter').attr('id', 'hot-surge-glow').attr('x', '-20%').attr('y', '-20%').attr('width', '140%').attr('height', '140%');
    glowFilter.append('feGaussianBlur').attr('stdDeviation', '2.5').attr('result', 'blur');
    glowFilter.append('feComposite').attr('in', 'SourceGraphic').attr('in2', 'blur').attr('operator', 'over');

    // Draw Heatmap Cells
    const cellGroups = g
      .selectAll<SVGGElement, HeatmapCellData>('.heat-cell')
      .data(cells, (d) => `${d.subnetCidr}-${d.hostBucket}`)
      .enter()
      .append('g')
      .attr('class', 'heat-cell')
      .attr('transform', (d) => `translate(${xScale(d.hostBucket) ?? 0},${yScale(d.subnetCidr) ?? 0})`)
      .style('cursor', 'pointer');

    // Background rect
    cellGroups
      .append('rect')
      .attr('width', xScale.bandwidth())
      .attr('height', yScale.bandwidth())
      .attr('rx', 4)
      .attr('ry', 4)
      .attr('fill', (d) => colorScale(d.rps))
      .attr('stroke', (d) => {
        if (hoveredCell && hoveredCell.subnetCidr === d.subnetCidr && hoveredCell.hostBucket === d.hostBucket) {
          return '#38bdf8';
        }
        if (d.action === 'DROP_L7') return '#fda4af';
        if (d.action === 'RATE_LIMIT') return '#fde047';
        return '#1e293b';
      })
      .attr('stroke-width', (d) => {
        if (hoveredCell && hoveredCell.subnetCidr === d.subnetCidr && hoveredCell.hostBucket === d.hostBucket) {
          return 2;
        }
        return d.isMitigated ? 1.5 : 1;
      })
      .attr('filter', (d) => (d.action === 'DROP_L7' ? 'url(#hot-surge-glow)' : 'none'))
      .on('mouseenter', (_, d) => setHoveredCell(d))
      .on('mouseleave', () => setHoveredCell(null))
      .on('click', (_, d) => setSelectedCell(d));

    // Cell numerical RPS label (shown when band is wide enough and RPS is significant)
    if (xScale.bandwidth() >= 42) {
      cellGroups
        .append('text')
        .attr('x', xScale.bandwidth() / 2)
        .attr('y', yScale.bandwidth() / 2 + 3.5)
        .attr('text-anchor', 'middle')
        .attr('font-size', '9px')
        .attr('font-family', 'ui-monospace, monospace')
        .attr('font-weight', '600')
        .attr('pointer-events', 'none')
        .attr('fill', (d) => {
          if (d.rps / maxDensityRps > 0.6) return '#ffffff';
          if (d.rps / maxDensityRps > 0.25) return '#0f172a';
          return '#64748b';
        })
        .text((d) => (d.rps >= 1000 ? `${(d.rps / 1000).toFixed(1)}k` : d.rps > 0 ? `${d.rps}` : ''));
    }

    // Y Axis (Subnets)
    const yAxisG = g.append('g').attr('class', 'y-axis');
    ySubnets.forEach((cidr) => {
      const sub = MONITORED_SUBNETS.find((s) => s.cidr === cidr);
      const y = (yScale(cidr) ?? 0) + yScale.bandwidth() / 2;

      const labelText = devMode ? cidr : (sub?.execLabel || cidr);

      yAxisG
        .append('text')
        .attr('x', -10)
        .attr('y', y + 3.5)
        .attr('text-anchor', 'end')
        .attr('font-size', '10px')
        .attr('font-family', devMode ? 'ui-monospace, monospace' : 'system-ui, sans-serif')
        .attr('font-weight', devMode ? '500' : '600')
        .attr('fill', (d) => {
          const isAttacked = sub?.cidr && ATTACK_PROFILES[activeAttack].targetSubnets.includes(sub.cidr);
          return isAttacked ? '#f87171' : '#94a3b8';
        })
        .text(labelText);
    });

    // X Axis (Host IP Buckets)
    const xAxisG = g.append('g').attr('transform', `translate(0,${innerHeight + 6})`);
    xBuckets.forEach((bucketIdx) => {
      const x = (xScale(bucketIdx) ?? 0) + xScale.bandwidth() / 2;
      xAxisG
        .append('text')
        .attr('x', x)
        .attr('y', 12)
        .attr('text-anchor', 'middle')
        .attr('font-size', '9.5px')
        .attr('font-family', 'ui-monospace, monospace')
        .attr('font-weight', '500')
        .attr('fill', '#94a3b8')
        .text(HOST_BUCKET_LABELS[bucketIdx]);
    });

    // Axis Header Labels
    svg
      .append('text')
      .attr('x', margin.left)
      .attr('y', margin.top - 12)
      .attr('font-size', '10px')
      .attr('font-family', 'ui-monospace, monospace')
      .attr('font-weight', '600')
      .attr('fill', '#64748b')
      .text(devMode ? 'SOURCE ORIGIN CIDR' : 'TRAFFIC ORIGIN SECTOR');

    svg
      .append('text')
      .attr('x', width - margin.right)
      .attr('y', margin.top - 12)
      .attr('text-anchor', 'end')
      .attr('font-size', '10px')
      .attr('font-family', 'ui-monospace, monospace')
      .attr('font-weight', '600')
      .attr('fill', '#64748b')
      .text(devMode ? 'HOST OCTET BIN (.X)' : 'CLIENT IP DISTRIBUTION');

    // Horizontal Legend Scale at Bottom
    const legendWidth = Math.min(220, innerWidth * 0.45);
    const legendHeight = 8;
    const legendX = margin.left;
    const legendY = height - 18;

    const legendGradient = defs
      .append('linearGradient')
      .attr('id', 'heat-legend-grad')
      .attr('x1', '0%')
      .attr('y1', '0%')
      .attr('x2', '100%')
      .attr('y2', '0%');

    legendGradient.append('stop').attr('offset', '0%').attr('stop-color', '#0f172a');
    legendGradient.append('stop').attr('offset', '20%').attr('stop-color', '#0284c7');
    legendGradient.append('stop').attr('offset', '45%').attr('stop-color', '#10b981');
    legendGradient.append('stop').attr('offset', '70%').attr('stop-color', '#f59e0b');
    legendGradient.append('stop').attr('offset', '90%').attr('stop-color', '#ef4444');
    legendGradient.append('stop').attr('offset', '100%').attr('stop-color', '#ffe4e6');

    svg
      .append('rect')
      .attr('x', legendX)
      .attr('y', legendY)
      .attr('width', legendWidth)
      .attr('height', legendHeight)
      .attr('rx', 2)
      .attr('fill', 'url(#heat-legend-grad)')
      .attr('stroke', '#334155')
      .attr('stroke-width', 0.8);

    svg
      .append('text')
      .attr('x', legendX)
      .attr('y', legendY - 4)
      .attr('font-size', '9px')
      .attr('font-family', 'ui-monospace, monospace')
      .attr('fill', '#64748b')
      .text('0 RPS (Nominal)');

    svg
      .append('text')
      .attr('x', legendX + legendWidth)
      .attr('y', legendY - 4)
      .attr('text-anchor', 'end')
      .attr('font-size', '9px')
      .attr('font-family', 'ui-monospace, monospace')
      .attr('fill', '#f87171')
      .text(`≥ ${maxDensityRps.toLocaleString()} RPS (Surge Flood)`);
  }, [cells, dimensions, devMode, activeAttack, hoveredCell]);

  const activeInspect = hoveredCell || selectedCell;

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-lg space-y-4">
      {/* Header and Live Status */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800/80 pb-3">
        <div>
          <div className="flex items-center gap-2">
            <h3 className="text-sm font-bold text-white flex items-center gap-2 font-mono">
              <Flame className="w-4 h-4 text-rose-400" />
              {devMode
                ? 'Source IP Origin Density Heatmap (CIDR / Host Matrix)'
                : 'Real-Time Cyber Attack Origin & Defense Heatmap'}
            </h3>
            {isStreaming && (
              <span className="flex items-center gap-1 text-[10px] font-mono px-2 py-0.5 rounded-full bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
                LIVE STREAM (1s)
              </span>
            )}
            {activeAttack !== 'none' && (
              <span className="flex items-center gap-1 text-[10px] font-mono px-2 py-0.5 rounded-full bg-rose-500/20 text-rose-300 border border-rose-500/30 animate-pulse font-semibold">
                <ShieldAlert className="w-3 h-3 text-rose-400" />
                L7 FLOOD SURGE ACTIVE
              </span>
            )}
          </div>
          <p className="text-xs text-slate-400 mt-1">
            {devMode
              ? 'Real-time D3 matrix tracking ingestion request density across 8 monitored CIDR blocks & 8 host octet partitions to pinpoint volumetric L7 DDoS attacks.'
              : 'Live visual grid showing where website visitors and cyber attack traffic are coming from, and how the AI shields your application in real time.'}
          </p>
        </div>

        {/* Aggregate KPI Badges */}
        <div className="flex items-center gap-2 font-mono text-xs">
          <div className="bg-slate-950 px-2.5 py-1.5 rounded-lg border border-slate-800 text-right">
            <div className="text-[10px] text-slate-500">INGRESS RATE</div>
            <div className="text-white font-bold">{aggregates.totalRps.toLocaleString()} RPS</div>
          </div>
          <div className="bg-slate-950 px-2.5 py-1.5 rounded-lg border border-slate-800 text-right">
            <div className="text-[10px] text-rose-400">SURGE MITIGATED</div>
            <div className="text-rose-300 font-bold">{aggregates.mitigatedRps.toLocaleString()} RPS</div>
          </div>
          <div className="bg-slate-950 px-2.5 py-1.5 rounded-lg border border-slate-800 text-right">
            <div className="text-[10px] text-emerald-400">CLEAN PASS</div>
            <div className="text-emerald-300 font-bold">{aggregates.passThroughRps.toLocaleString()} RPS</div>
          </div>
        </div>
      </div>

      {/* D3 SVG Container */}
      <div ref={containerRef} className="w-full relative overflow-x-auto">
        <svg ref={svgRef} className="w-full select-none" />
      </div>

      {/* Inspection Card: Active Cell Details */}
      {activeInspect ? (
        <div className="bg-slate-950 border border-slate-800 rounded-lg p-3.5 text-xs font-mono transition-all">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-800 pb-2">
            <div className="flex items-center gap-2">
              <Crosshair className="w-4 h-4 text-indigo-400" />
              <span className="font-bold text-white">
                {devMode ? activeInspect.sampleIp : activeInspect.execLabel}
              </span>
              <span className="text-slate-500">
                ({activeInspect.subnetCidr} • Host Range: {activeInspect.bucketLabel})
              </span>
              <span className="text-[10px] px-1.5 py-0.5 rounded bg-slate-800 text-slate-300">
                {activeInspect.category}
              </span>
            </div>

            <div className="flex items-center gap-2">
              <span className="text-slate-400">Mitigation Action:</span>
              <span
                className={`px-2 py-0.5 rounded font-bold text-[11px] ${
                  activeInspect.action === 'DROP_L7'
                    ? 'bg-rose-500/20 text-rose-300 border border-rose-500/30'
                    : activeInspect.action === 'RATE_LIMIT'
                    ? 'bg-amber-500/20 text-amber-300 border border-amber-500/30'
                    : 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30'
                }`}
              >
                {devMode
                  ? activeInspect.action === 'DROP_L7'
                    ? 'TCP_RESET / DROP_SILENT'
                    : activeInspect.action === 'RATE_LIMIT'
                    ? 'HTTP_429_RATE_LIMIT'
                    : 'PASS_PROXY_UPSTREAM'
                  : activeInspect.action === 'DROP_L7'
                  ? 'Attack Traffic Dropped'
                  : activeInspect.action === 'RATE_LIMIT'
                  ? 'Traffic Throttled'
                  : 'Clean Customer Allowed'}
              </span>
            </div>
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 pt-2 text-[11px]">
            <div>
              <span className="text-slate-400 block">Instant Volume:</span>
              <span className="text-white font-bold">{activeInspect.rps.toLocaleString()} RPS</span>
            </div>
            <div>
              <span className="text-slate-400 block">
                {devMode ? 'LSTM Reconstruction MSE:' : 'Anomaly Severity:'}
              </span>
              <span
                className={`font-bold ${
                  activeInspect.anomalyScore > 0.65 ? 'text-rose-400' : 'text-emerald-400'
                }`}
              >
                {devMode
                  ? activeInspect.reconstructionMse.toFixed(4)
                  : `${(activeInspect.anomalyScore * 100).toFixed(1)}% Out-of-Distribution`}
              </span>
            </div>
            <div>
              <span className="text-slate-400 block">
                {devMode ? 'Buffer Pressure:' : 'Server Protection:'}
              </span>
              <span className="text-indigo-300 font-semibold">
                {devMode
                  ? activeInspect.action === 'DROP_L7'
                    ? '100% Bound (0 B Heap Alloc)'
                    : 'Nominal Pool Queue'
                  : '0% Server Load Impact'}
              </span>
            </div>
            <div>
              <span className="text-slate-400 block">
                {devMode ? 'Zima MDR Telemetry:' : 'Security Alert:'}
              </span>
              <span className="text-cyan-300">
                {activeInspect.action !== 'ALLOW'
                  ? 'Asynchronously Enqueued'
                  : 'Bypassed (Clean)'}
              </span>
            </div>
          </div>
        </div>
      ) : (
        <div className="bg-slate-950/60 border border-slate-800/80 rounded-lg p-2.5 text-center text-xs text-slate-500 flex items-center justify-center gap-2 font-mono">
          <Info className="w-3.5 h-3.5 text-slate-400" />
          <span>Hover or tap any cell in the heatmap matrix above to inspect specific IP subnets, traffic volume, and deep learning anomaly scores.</span>
        </div>
      )}
    </div>
  );
};
