/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useEffect, useRef, useState } from 'react';
import * as d3 from 'd3';
import { Clock, CheckCircle2 } from 'lucide-react';

interface Props {
  devMode: boolean;
}

export const LatencyDistributionChart: React.FC<Props> = ({ devMode }) => {
  const svgRef = useRef<SVGSVGElement | null>(null);
  const containerRef = useRef<HTMLDivElement | null>(null);
  const [hoveredBucket, setHoveredBucket] = useState<{ range: string; count: number; pct: string } | null>(null);

  useEffect(() => {
    if (!svgRef.current || !containerRef.current) return;

    const width = containerRef.current.clientWidth || 500;
    const height = 220;
    const margin = { top: 20, right: 30, bottom: 35, left: 45 };
    const innerWidth = width - margin.left - margin.right;
    const innerHeight = height - margin.top - margin.bottom;

    const svg = d3.select(svgRef.current);
    svg.selectAll('*').remove();

    svg.attr('width', width).attr('height', height);

    const g = svg
      .append('g')
      .attr('transform', `translate(${margin.left},${margin.top})`);

    const buckets = [
      { min: 400, max: 700, count: 420 },
      { min: 700, max: 1000, count: 2840 },
      { min: 1000, max: 1300, count: 6890 },
      { min: 1300, max: 1600, count: 4120 },
      { min: 1600, max: 2000, count: 1850 },
      { min: 2000, max: 2500, count: 740 },
      { min: 2500, max: 3000, count: 260 },
      { min: 3000, max: 3500, count: 85 },
      { min: 3500, max: 4000, count: 12 },
    ];

    const totalSamples = buckets.reduce((acc, b) => acc + b.count, 0);

    const xScale = d3.scaleLinear().domain([400, 4000]).range([0, innerWidth]);
    const maxCount = d3.max(buckets, (d) => d.count) || 7000;
    const yScale = d3.scaleLinear().domain([0, maxCount * 1.1]).range([innerHeight, 0]);

    const defs = svg.append('defs');
    const barGradient = defs
      .append('linearGradient')
      .attr('id', 'lat-bar-grad')
      .attr('x1', '0%')
      .attr('y1', '0%')
      .attr('x2', '0%')
      .attr('y2', '100%');
    barGradient.append('stop').attr('offset', '0%').attr('stop-color', '#6366f1').attr('stop-opacity', 0.8);
    barGradient.append('stop').attr('offset', '100%').attr('stop-color', '#4338ca').attr('stop-opacity', 0.3);

    g.selectAll('.bar')
      .data(buckets)
      .enter()
      .append('rect')
      .attr('class', 'bar')
      .attr('x', (d) => xScale(d.min))
      .attr('width', (d) => Math.max(0, xScale(d.max) - xScale(d.min) - 2))
      .attr('y', (d) => yScale(d.count))
      .attr('height', (d) => innerHeight - yScale(d.count))
      .attr('rx', 3)
      .attr('fill', (d) => (d.min >= 3500 ? '#f43f5e' : 'url(#lat-bar-grad)'))
      .attr('stroke', (d) => (d.min >= 3500 ? '#fb7185' : '#818cf8'))
      .attr('stroke-width', 1)
      .style('cursor', 'pointer')
      .on('mouseenter', (event, d) => {
        d3.select(event.currentTarget as SVGRectElement).attr('stroke', '#38bdf8').attr('stroke-width', 2);
        const pct = ((d.count / totalSamples) * 100).toFixed(1);
        setHoveredBucket({ range: `${d.min} - ${d.max} μs`, count: d.count, pct: `${pct}%` });
      })
      .on('mouseleave', (event, d) => {
        d3.select(event.currentTarget as SVGRectElement)
          .attr('stroke', d.min >= 3500 ? '#fb7185' : '#818cf8')
          .attr('stroke-width', 1);
        setHoveredBucket(null);
      });

    const percentiles = [
      { name: 'P50', val: 1100, color: '#38bdf8' },
      { name: 'P90', val: 1550, color: '#a855f7' },
      { name: 'P99', val: 2450, color: '#f59e0b' },
      { name: 'SLA (3.5ms)', val: 3500, color: '#ef4444' },
    ];

    percentiles.forEach((p) => {
      const x = xScale(p.val);
      g.append('line')
        .attr('x1', x)
        .attr('x2', x)
        .attr('y1', 0)
        .attr('y2', innerHeight)
        .attr('stroke', p.color)
        .attr('stroke-dasharray', '3,3')
        .attr('stroke-width', 1.5);

      g.append('text')
        .attr('x', x)
        .attr('y', -6)
        .attr('text-anchor', 'middle')
        .attr('fill', p.color)
        .attr('font-size', '9px')
        .attr('font-family', 'monospace')
        .attr('font-weight', 'bold')
        .text(p.name);
    });

    const xAxis = d3
      .axisBottom(xScale)
      .ticks(6)
      .tickFormat((d) => (devMode ? `${d} μs` : `${(Number(d) / 1000).toFixed(1)} ms`));
    g.append('g')
      .attr('transform', `translate(0,${innerHeight})`)
      .call(xAxis)
      .attr('color', '#64748b')
      .selectAll('text')
      .attr('font-size', '10px')
      .attr('font-family', 'monospace');

    const yAxis = d3.axisLeft(yScale).ticks(4).tickFormat((d) => `${(Number(d) / 1000).toFixed(1)}k`);
    g.append('g')
      .call(yAxis)
      .attr('color', '#64748b')
      .selectAll('text')
      .attr('font-size', '10px')
      .attr('font-family', 'monospace');
  }, [devMode]);

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-lg flex flex-col justify-between" ref={containerRef}>
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 mb-3">
        <div>
          <div className="flex items-center gap-2">
            <Clock className="w-4 h-4 text-cyan-400" />
            <h3 className="text-sm font-bold text-white font-mono">
              {devMode ? 'D3 Distribution: Edge Proxy Latency (Microseconds)' : 'D3 Speed Inspection: Customer Response Latency'}
            </h3>
          </div>
          <p className="text-xs text-slate-400 mt-0.5">
            {devMode
              ? 'Tokenization + gRPC inference round-trip distribution measured across 17,217 HTTP transactions.'
              : 'End-to-end inspection speed ensuring safe transactions complete with virtually zero perceptible delay.'}
          </p>
        </div>

        <div className="flex items-center gap-2 bg-emerald-500/10 border border-emerald-500/30 px-2.5 py-1 rounded-lg">
          <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
          <span className="text-xs font-mono text-emerald-300 font-semibold">
            {devMode ? '99.93% within ≤ 3.5ms SLA' : 'Lightning Fast (1.2ms Avg)'}
          </span>
        </div>
      </div>

      <div className="w-full overflow-hidden relative">
        <svg ref={svgRef} className="w-full overflow-visible" />

        {hoveredBucket && (
          <div className="absolute top-2 right-4 bg-slate-950/95 border border-indigo-500/50 rounded-lg p-2.5 shadow-xl text-xs font-mono pointer-events-none">
            <div className="text-slate-400 text-[10px]">Latency Range:</div>
            <div className="text-cyan-400 font-bold">{hoveredBucket.range}</div>
            <div className="text-white mt-1">
              Samples: {hoveredBucket.count.toLocaleString()} ({hoveredBucket.pct})
            </div>
          </div>
        )}
      </div>

      <div className="mt-3 pt-3 border-t border-slate-800/80 grid grid-cols-4 gap-2 text-center text-xs font-mono">
        <div className="bg-slate-950 p-1.5 rounded border border-slate-800">
          <div className="text-[10px] text-slate-400">{devMode ? 'P50 (Median)' : 'Typical Speed'}</div>
          <div className="text-cyan-400 font-bold">1,100 μs (1.1ms)</div>
        </div>
        <div className="bg-slate-950 p-1.5 rounded border border-slate-800">
          <div className="text-[10px] text-slate-400">{devMode ? 'P90' : '90% of Users'}</div>
          <div className="text-purple-400 font-bold">1,550 μs (1.5ms)</div>
        </div>
        <div className="bg-slate-950 p-1.5 rounded border border-slate-800">
          <div className="text-[10px] text-slate-400">{devMode ? 'P99' : 'Slowest 1%'}</div>
          <div className="text-amber-400 font-bold">2,450 μs (2.4ms)</div>
        </div>
        <div className="bg-slate-950 p-1.5 rounded border border-slate-800">
          <div className="text-[10px] text-slate-400">{devMode ? 'Strict SLA' : 'Industry Average'}</div>
          <div className="text-rose-400 font-bold">{devMode ? '3,500 μs' : '25.0 ms (10x slower)'}</div>
        </div>
      </div>
    </div>
  );
};
