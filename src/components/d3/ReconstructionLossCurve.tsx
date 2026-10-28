/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useEffect, useRef, useState } from 'react';
import * as d3 from 'd3';
import { Sigma, ShieldAlert, CheckCircle2, Sliders } from 'lucide-react';

interface Props {
  devMode: boolean;
  initialThreshold?: number;
  onThresholdChange?: (val: number) => void;
}

export const ReconstructionLossCurve: React.FC<Props> = ({
  devMode,
  initialThreshold = 0.65,
  onThresholdChange,
}) => {
  const svgRef = useRef<SVGSVGElement | null>(null);
  const containerRef = useRef<HTMLDivElement | null>(null);
  const [threshold, setThreshold] = useState<number>(initialThreshold);

  const handleSliderChange = (newVal: number) => {
    setThreshold(newVal);
    if (onThresholdChange) onThresholdChange(newVal);
  };

  useEffect(() => {
    if (!svgRef.current || !containerRef.current) return;

    const width = containerRef.current.clientWidth || 500;
    const height = 220;
    const margin = { top: 25, right: 30, bottom: 35, left: 45 };
    const innerWidth = width - margin.left - margin.right;
    const innerHeight = height - margin.top - margin.bottom;

    const svg = d3.select(svgRef.current);
    svg.selectAll('*').remove();

    svg.attr('width', width).attr('height', height);

    const g = svg
      .append('g')
      .attr('transform', `translate(${margin.left},${margin.top})`);

    // Generate Points for Benign Traffic Gaussian Distribution (mean=0.08, std=0.06)
    // and Malicious Traffic Anomaly Distribution (mean=1.10, std=0.35)
    const steps = 120;
    const maxMSE = 1.8;
    const dataPoints: { mse: number; benignDensity: number; attackDensity: number }[] = [];

    const gaussian = (x: number, mean: number, std: number) => {
      return (1 / (std * Math.sqrt(2 * Math.PI))) * Math.exp(-0.5 * Math.pow((x - mean) / std, 2));
    };

    for (let i = 0; i <= steps; i++) {
      const mse = (i / steps) * maxMSE;
      const benignDensity = gaussian(mse, 0.12, 0.08) * 0.9;
      const attackDensity = gaussian(mse, 1.15, 0.32) * 0.45;
      dataPoints.push({ mse, benignDensity, attackDensity });
    }

    // Scales
    const xScale = d3.scaleLinear().domain([0, maxMSE]).range([0, innerWidth]);
    const maxDensity = d3.max(dataPoints, (d) => Math.max(d.benignDensity, d.attackDensity)) || 5;
    const yScale = d3.scaleLinear().domain([0, maxDensity * 1.1]).range([innerHeight, 0]);

    // Defs: Gradients
    const defs = svg.append('defs');

    // Benign Area (Green)
    const benignArea = d3
      .area<{ mse: number; benignDensity: number }>()
      .x((d) => xScale(d.mse))
      .y0(innerHeight)
      .y1((d) => yScale(d.benignDensity))
      .curve(d3.curveBasis);

    // Attack Area (Red)
    const attackArea = d3
      .area<{ mse: number; attackDensity: number }>()
      .x((d) => xScale(d.mse))
      .y0(innerHeight)
      .y1((d) => yScale(d.attackDensity))
      .curve(d3.curveBasis);

    // Shaded Allowed Zone (0 to Threshold)
    g.append('rect')
      .attr('x', 0)
      .attr('width', Math.max(0, xScale(threshold)))
      .attr('y', 0)
      .attr('height', innerHeight)
      .attr('fill', '#10b981')
      .attr('fill-opacity', 0.07);

    // Shaded Blocked Zone (Threshold to maxMSE)
    g.append('rect')
      .attr('x', xScale(threshold))
      .attr('width', Math.max(0, innerWidth - xScale(threshold)))
      .attr('y', 0)
      .attr('height', innerHeight)
      .attr('fill', '#f43f5e')
      .attr('fill-opacity', 0.09);

    // Draw Benign Density Curve
    g.append('path')
      .datum(dataPoints)
      .attr('fill', '#10b981')
      .attr('fill-opacity', 0.25)
      .attr('stroke', '#10b981')
      .attr('stroke-width', 2)
      .attr('d', benignArea);

    // Draw Attack Density Curve
    g.append('path')
      .datum(dataPoints)
      .attr('fill', '#f43f5e')
      .attr('fill-opacity', 0.3)
      .attr('stroke', '#f43f5e')
      .attr('stroke-width', 2)
      .attr('d', attackArea);

    // Threshold Marker Line
    const threshX = xScale(threshold);
    g.append('line')
      .attr('x1', threshX)
      .attr('x2', threshX)
      .attr('y1', 0)
      .attr('y2', innerHeight)
      .attr('stroke', '#f59e0b')
      .attr('stroke-width', 2.5)
      .attr('stroke-dasharray', '4,2');

    g.append('circle')
      .attr('cx', threshX)
      .attr('cy', 12)
      .attr('r', 5)
      .attr('fill', '#f59e0b')
      .attr('stroke', '#ffffff')
      .attr('stroke-width', 1.5);

    g.append('text')
      .attr('x', threshX)
      .attr('y', -6)
      .attr('text-anchor', 'middle')
      .attr('fill', '#f59e0b')
      .attr('font-size', '10px')
      .attr('font-family', 'monospace')
      .attr('font-weight', 'bold')
      .text(devMode ? `τ = ${threshold.toFixed(2)}` : `Cutoff = ${threshold.toFixed(2)}`);

    // Axes
    const xAxis = d3
      .axisBottom(xScale)
      .ticks(6)
      .tickFormat((d) => (devMode ? `${d} MSE` : `Anomaly ${d}`));
    g.append('g')
      .attr('transform', `translate(0,${innerHeight})`)
      .call(xAxis)
      .attr('color', '#64748b')
      .selectAll('text')
      .attr('font-size', '10px')
      .attr('font-family', 'monospace');

    const yAxis = d3.axisLeft(yScale).ticks(3).tickFormat(() => '');
    g.append('g').call(yAxis).attr('color', '#64748b');
  }, [threshold, devMode]);

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-lg flex flex-col justify-between" ref={containerRef}>
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 mb-3">
        <div>
          <div className="flex items-center gap-2">
            <Sigma className="w-4 h-4 text-purple-400" />
            <h3 className="text-sm font-bold text-white font-mono">
              {devMode
                ? 'D3 Model: LSTM Autoencoder Reconstruction Loss Distribution'
                : 'D3 AI Brain: Normal Behavior vs Cyber Attack Separation'}
            </h3>
          </div>
          <p className="text-xs text-slate-400 mt-0.5">
            {devMode
              ? 'MSE loss separation between benign training corpus and out-of-distribution injection vectors.'
              : 'Visualizing how our neural network easily distinguishes between safe customer actions and malicious hackers.'}
          </p>
        </div>

        {/* Legend */}
        <div className="flex items-center gap-3 text-xs font-mono">
          <div className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-full bg-emerald-400" />
            <span className="text-slate-300">{devMode ? 'Benign HTTP' : 'Normal Users'}</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-full bg-rose-400" />
            <span className="text-slate-300">{devMode ? 'Malicious Payloads' : 'Attacks'}</span>
          </div>
        </div>
      </div>

      {/* SVG Canvas */}
      <div className="w-full overflow-hidden relative">
        <svg ref={svgRef} className="w-full overflow-visible" />
      </div>

      {/* Interactive Threshold Slider Knob */}
      <div className="mt-4 pt-3 border-t border-slate-800/80 space-y-2">
        <div className="flex items-center justify-between text-xs font-mono">
          <span className="text-slate-400 flex items-center gap-1.5">
            <Sliders className="w-3.5 h-3.5 text-amber-400" />
            {devMode ? 'LSTM Decision Threshold (τ):' : 'AI Protection Sensitivity:'}
          </span>
          <span className="text-amber-400 font-bold bg-amber-500/10 px-2 py-0.5 rounded border border-amber-500/30">
            {threshold.toFixed(2)} MSE
          </span>
        </div>

        <input
          type="range"
          min="0.30"
          max="1.20"
          step="0.05"
          value={threshold}
          onChange={(e) => handleSliderChange(parseFloat(e.target.value))}
          className="w-full accent-amber-500 h-1.5 bg-slate-800 rounded-lg cursor-pointer"
        />

        <div className="flex justify-between text-[11px] font-mono text-slate-400 pt-1">
          <span className="text-emerald-400">
            {devMode ? '← Lower False Positives' : '← Permissive (Fewer blocks)'}
          </span>
          <span className="text-amber-400 font-semibold">Recommended: 0.65</span>
          <span className="text-rose-400">
            {devMode ? 'Higher True Positive Rate →' : 'Stricter Defense →'}
          </span>
        </div>
      </div>
    </div>
  );
};
