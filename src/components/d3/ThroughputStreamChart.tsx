/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useEffect, useRef, useState } from 'react';
import * as d3 from 'd3';

interface DataPoint {
  timestamp: Date;
  allowed: number;
  blocked: number;
  total: number;
}

interface Props {
  devMode: boolean;
  rateRPS?: number;
}

export const ThroughputStreamChart: React.FC<Props> = ({ devMode, rateRPS = 12500 }) => {
  const svgRef = useRef<SVGSVGElement | null>(null);
  const containerRef = useRef<HTMLDivElement | null>(null);
  const [hoveredData, setHoveredData] = useState<DataPoint | null>(null);

  // Generate initial rolling history
  const [data, setData] = useState<DataPoint[]>(() => {
    const points: DataPoint[] = [];
    const now = Date.now();
    for (let i = 40; i >= 0; i--) {
      const time = new Date(now - i * 1000);
      const base = rateRPS * (0.85 + Math.sin(i / 4) * 0.15);
      const blocked = Math.floor(base * (0.05 + Math.random() * 0.08));
      const allowed = Math.floor(base - blocked);
      points.push({
        timestamp: time,
        allowed,
        blocked,
        total: allowed + blocked,
      });
    }
    return points;
  });

  // Streaming real-time updates
  useEffect(() => {
    const interval = setInterval(() => {
      setData((prev) => {
        const now = new Date();
        const base = rateRPS * (0.85 + Math.sin(Date.now() / 4000) * 0.15 + (Math.random() * 0.1 - 0.05));
        const blocked = Math.floor(base * (0.06 + Math.random() * 0.09));
        const allowed = Math.floor(base - blocked);
        const next = [...prev.slice(1), { timestamp: now, allowed, blocked, total: allowed + blocked }];
        return next;
      });
    }, 1000);

    return () => clearInterval(interval);
  }, [rateRPS]);

  // D3 Rendering
  useEffect(() => {
    if (!svgRef.current || !containerRef.current || data.length === 0) return;

    const width = containerRef.current.clientWidth || 650;
    const height = 240;
    const margin = { top: 20, right: 24, bottom: 30, left: 54 };
    const innerWidth = width - margin.left - margin.right;
    const innerHeight = height - margin.top - margin.bottom;

    const svg = d3.select(svgRef.current);
    svg.selectAll('*').remove();

    svg.attr('width', width).attr('height', height);

    const g = svg
      .append('g')
      .attr('transform', `translate(${margin.left},${margin.top})`);

    // Defs: Gradients
    const defs = svg.append('defs');

    // Allowed (Emerald / Cyan)
    const allowedGradient = defs
      .append('linearGradient')
      .attr('id', 'allowed-grad')
      .attr('x1', '0%')
      .attr('y1', '0%')
      .attr('x2', '0%')
      .attr('y2', '100%');
    allowedGradient.append('stop').attr('offset', '0%').attr('stop-color', '#10b981').attr('stop-opacity', 0.45);
    allowedGradient.append('stop').attr('offset', '100%').attr('stop-color', '#10b981').attr('stop-opacity', 0.02);

    // Blocked (Rose / Crimson)
    const blockedGradient = defs
      .append('linearGradient')
      .attr('id', 'blocked-grad')
      .attr('x1', '0%')
      .attr('y1', '0%')
      .attr('x2', '0%')
      .attr('y2', '100%');
    blockedGradient.append('stop').attr('offset', '0%').attr('stop-color', '#f43f5e').attr('stop-opacity', 0.55);
    blockedGradient.append('stop').attr('offset', '100%').attr('stop-color', '#f43f5e').attr('stop-opacity', 0.05);

    // Scales
    const xScale = d3
      .scaleTime()
      .domain(d3.extent(data, (d) => d.timestamp) as [Date, Date])
      .range([0, innerWidth]);

    const maxTotal = d3.max(data, (d) => d.total) || 15000;
    const yScale = d3
      .scaleLinear()
      .domain([0, maxTotal * 1.15])
      .range([innerHeight, 0]);

    // Gridlines
    const yAxisGrid = d3.axisLeft(yScale).tickSize(-innerWidth).tickFormat(() => '').ticks(4);
    g.append('g')
      .attr('class', 'grid')
      .call(yAxisGrid)
      .selectAll('line')
      .attr('stroke', '#334155')
      .attr('stroke-dasharray', '2,3')
      .attr('stroke-opacity', 0.4);

    // Area Generators
    const allowedArea = d3
      .area<DataPoint>()
      .x((d) => xScale(d.timestamp))
      .y0(innerHeight)
      .y1((d) => yScale(d.allowed))
      .curve(d3.curveMonotoneX);

    const blockedArea = d3
      .area<DataPoint>()
      .x((d) => xScale(d.timestamp))
      .y0((d) => yScale(d.allowed))
      .y1((d) => yScale(d.total))
      .curve(d3.curveMonotoneX);

    const totalLine = d3
      .line<DataPoint>()
      .x((d) => xScale(d.timestamp))
      .y((d) => yScale(d.total))
      .curve(d3.curveMonotoneX);

    // Render Areas
    g.append('path')
      .datum(data)
      .attr('fill', 'url(#allowed-grad)')
      .attr('d', allowedArea);

    g.append('path')
      .datum(data)
      .attr('fill', 'url(#blocked-grad)')
      .attr('d', blockedArea);

    g.append('path')
      .datum(data)
      .attr('fill', 'none')
      .attr('stroke', '#38bdf8')
      .attr('stroke-width', 2)
      .attr('d', totalLine);

    // Axes
    const xAxis = d3.axisBottom(xScale).ticks(5).tickFormat((d) => d3.timeFormat('%H:%M:%S')(d as Date));
    g.append('g')
      .attr('transform', `translate(0,${innerHeight})`)
      .call(xAxis)
      .attr('color', '#64748b')
      .selectAll('text')
      .attr('font-size', '10px')
      .attr('font-family', 'monospace');

    const yAxis = d3.axisLeft(yScale).ticks(4).tickFormat((d) => `${(Number(d) / 1000).toFixed(0)}k`);
    g.append('g')
      .call(yAxis)
      .attr('color', '#64748b')
      .selectAll('text')
      .attr('font-size', '10px')
      .attr('font-family', 'monospace');

    // Interactive Hover Overlay
    const bisect = d3.bisector<DataPoint, Date>((d) => d.timestamp).left;
    const focusLine = g
      .append('line')
      .attr('stroke', '#818cf8')
      .attr('stroke-width', 1.5)
      .attr('stroke-dasharray', '3,3')
      .attr('y1', 0)
      .attr('y2', innerHeight)
      .style('opacity', 0);

    svg
      .append('rect')
      .attr('transform', `translate(${margin.left},${margin.top})`)
      .attr('width', innerWidth)
      .attr('height', innerHeight)
      .attr('fill', 'transparent')
      .on('mousemove', (event) => {
        const [xPos] = d3.pointer(event);
        const xDate = xScale.invert(xPos);
        const index = bisect(data, xDate, 1);
        const d0 = data[index - 1];
        const d1 = data[index];
        let d = d0;
        if (d1 && xDate.getTime() - d0.timestamp.getTime() > d1.timestamp.getTime() - xDate.getTime()) {
          d = d1;
        }
        if (d) {
          focusLine.attr('x1', xScale(d.timestamp)).attr('x2', xScale(d.timestamp)).style('opacity', 1);
          setHoveredData(d);
        }
      })
      .on('mouseleave', () => {
        focusLine.style('opacity', 0);
        setHoveredData(null);
      });
  }, [data]);

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-lg flex flex-col justify-between" ref={containerRef}>
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 mb-3">
        <div>
          <div className="flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-emerald-400 animate-ping" />
            <h3 className="text-sm font-bold text-white font-mono">
              {devMode
                ? 'D3 Stream: net/http Ingestion vs Anomaly Blocks (RPS)'
                : 'D3 Live Defense Stream: Normal Traffic vs Neutralized Threats'}
            </h3>
          </div>
          <p className="text-xs text-slate-400 mt-0.5">
            {devMode
              ? 'Real-time telemetry showing proxy ingress, LSTM Autoencoder gate decisions, and Kafka streaming velocity.'
              : 'Continuous protection stream displaying live safe customer requests and automatically blocked attacks.'}
          </p>
        </div>

        {/* Legend */}
        <div className="flex items-center gap-4 text-xs font-mono">
          <div className="flex items-center gap-1.5">
            <span className="w-3 h-3 rounded-sm bg-emerald-500/60 border border-emerald-400" />
            <span className="text-slate-300">{devMode ? 'Allowed (Proxied)' : 'Safe Customer Traffic'}</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="w-3 h-3 rounded-sm bg-rose-500/60 border border-rose-400" />
            <span className="text-slate-300">{devMode ? 'Blocked (MSE >= τ)' : 'Blocked Threats'}</span>
          </div>
        </div>
      </div>

      {/* D3 Canvas */}
      <div className="w-full overflow-hidden relative">
        <svg ref={svgRef} className="w-full overflow-visible" />

        {/* Dynamic Tooltip */}
        {hoveredData && (
          <div className="absolute top-2 right-4 bg-slate-950/95 border border-indigo-500/50 rounded-lg p-2.5 shadow-xl text-xs font-mono z-10 pointer-events-none">
            <div className="text-slate-400 text-[10px]">
              {hoveredData.timestamp.toLocaleTimeString()}
            </div>
            <div className="text-white font-bold mt-1">
              {devMode ? 'Total Ingress:' : 'Total Volume:'} {hoveredData.total.toLocaleString()} req/s
            </div>
            <div className="text-emerald-400">
              {devMode ? 'Allowed:' : 'Safe Traffic:'} {hoveredData.allowed.toLocaleString()} req/s
            </div>
            <div className="text-rose-400">
              {devMode ? 'Blocked (MSE):' : 'Threats Blocked:'} {hoveredData.blocked.toLocaleString()} req/s
            </div>
          </div>
        )}
      </div>

      {/* Footer Info */}
      <div className="mt-3 pt-3 border-t border-slate-800/80 flex items-center justify-between text-[11px] font-mono text-slate-400">
        <span>Window: Rolling 40 seconds</span>
        <span>
          {devMode
            ? `Zero-alloc amortized pipeline (sync.Pool)`
            : `100% Automated · 0 Admin Intervention Required`}
        </span>
      </div>
    </div>
  );
};
