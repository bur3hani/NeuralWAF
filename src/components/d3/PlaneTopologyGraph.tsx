/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useEffect, useRef, useState } from 'react';
import * as d3 from 'd3';
import { Layers, ArrowRight, Zap, Cpu, Radio, ShieldCheck } from 'lucide-react';

interface Props {
  devMode: boolean;
  onSelectNode?: (nodeId: string) => void;
}

interface NodeData {
  id: string;
  devName: string;
  execName: string;
  devSub: string;
  execSub: string;
  x: number;
  y: number;
  color: string;
  iconType: 'data' | 'token' | 'grpc' | 'kafka' | 'upstream' | 'client';
}

export const PlaneTopologyGraph: React.FC<Props> = ({ devMode, onSelectNode }) => {
  const svgRef = useRef<SVGSVGElement | null>(null);
  const containerRef = useRef<HTMLDivElement | null>(null);
  const [activeNode, setActiveNode] = useState<NodeData | null>(null);

  const nodes: NodeData[] = [
    {
      id: 'client',
      devName: 'Client Ingress',
      execName: 'Incoming Web Visitors',
      devSub: 'HTTPS / TLS 1.3',
      execSub: 'Customers & API Clients',
      x: 70,
      y: 110,
      color: '#38bdf8',
      iconType: 'client',
    },
    {
      id: 'data-plane',
      devName: '1. Data Plane (:8080)',
      execName: 'Edge Security Gateway',
      devSub: 'net/http/httputil + MaxBytes',
      execSub: 'Zero-Lag Connection Intercept',
      x: 230,
      y: 110,
      color: '#6366f1',
      iconType: 'data',
    },
    {
      id: 'tokenizer',
      devName: 'Zero-Alloc Tokenizer',
      execName: 'Traffic DNA Vectorizer',
      devSub: 'sync.Pool [1024]uint32',
      execSub: 'Prepares Requests for AI',
      x: 390,
      y: 110,
      color: '#818cf8',
      iconType: 'token',
    },
    {
      id: 'inference',
      devName: '2. Inference Plane (:50051)',
      execName: 'LSTM Deep Learning Brain',
      devSub: 'gRPC Pool (16) · ≤ 3.5ms SLA',
      execSub: 'Autonomous Anomaly Detection',
      x: 550,
      y: 110,
      color: '#a855f7',
      iconType: 'grpc',
    },
    {
      id: 'upstream',
      devName: 'Protected Upstream (:8000)',
      execName: 'Your Business Application',
      devSub: 'Safe Reverse Proxy Target',
      execSub: '100% Verified Safe Requests',
      x: 720,
      y: 55,
      color: '#10b981',
      iconType: 'upstream',
    },
    {
      id: 'telemetry',
      devName: '3. Telemetry Plane (:9092)',
      execName: 'Zima MDR Incident Cloud',
      devSub: 'Non-Blocking Kafka Ring Buffer',
      execSub: 'Real-Time Threat Intelligence',
      x: 720,
      y: 165,
      color: '#06b6d4',
      iconType: 'kafka',
    },
  ];

  const links = [
    { source: 'client', target: 'data-plane', label: 'HTTP Req' },
    { source: 'data-plane', target: 'tokenizer', label: 'Bounded Stream' },
    { source: 'tokenizer', target: 'inference', label: 'gRPC Ingest' },
    { source: 'inference', target: 'upstream', label: 'Benign (MSE < τ)' },
    { source: 'inference', target: 'telemetry', label: 'Threat (MSE ≥ τ)' },
  ];

  useEffect(() => {
    if (!svgRef.current || !containerRef.current) return;

    const width = 800;
    const height = 230;

    const svg = d3.select(svgRef.current);
    svg.selectAll('*').remove();

    svg.attr('viewBox', `0 0 ${width} ${height}`).attr('width', '100%').attr('height', height);

    const g = svg.append('g');

    // Defs: Marker Arrows
    const defs = svg.append('defs');
    defs
      .append('marker')
      .attr('id', 'arrow')
      .attr('viewBox', '0 0 10 10')
      .attr('refX', 22)
      .attr('refY', 5)
      .attr('markerWidth', 6)
      .attr('markerHeight', 6)
      .attr('orient', 'auto-start-reverse')
      .append('path')
      .attr('d', 'M 0 0 L 10 5 L 0 10 z')
      .attr('fill', '#64748b');

    // Draw Links
    links.forEach((l) => {
      const src = nodes.find((n) => n.id === l.source)!;
      const tgt = nodes.find((n) => n.id === l.target)!;

      // Curved or straight path
      const pathData = d3.path();
      pathData.moveTo(src.x, src.y);
      if (src.y === tgt.y) {
        pathData.lineTo(tgt.x, tgt.y);
      } else {
        pathData.bezierCurveTo(src.x + 60, src.y, tgt.x - 60, tgt.y, tgt.x, tgt.y);
      }

      g.append('path')
        .attr('d', pathData.toString())
        .attr('fill', 'none')
        .attr('stroke', l.target === 'upstream' ? '#10b981' : l.target === 'telemetry' ? '#06b6d4' : '#475569')
        .attr('stroke-width', 2)
        .attr('stroke-dasharray', l.target === 'telemetry' ? '4,3' : 'none')
        .attr('marker-end', 'url(#arrow)');
    });

    // Draw Nodes
    const nodeGroups = g
      .selectAll('.node')
      .data(nodes)
      .enter()
      .append('g')
      .attr('class', 'node')
      .attr('transform', (d) => `translate(${d.x},${d.y})`)
      .style('cursor', 'pointer')
      .on('mouseenter', (event, d) => {
        setActiveNode(d);
        if (onSelectNode) onSelectNode(d.id);
      });

    // Outer Circle Glow
    nodeGroups
      .append('circle')
      .attr('r', 22)
      .attr('fill', (d) => d.color)
      .attr('fill-opacity', 0.15)
      .attr('stroke', (d) => d.color)
      .attr('stroke-width', 2);

    // Inner Circle Core
    nodeGroups
      .append('circle')
      .attr('r', 12)
      .attr('fill', (d) => d.color)
      .attr('fill-opacity', 0.85);

    // Node Labels
    nodeGroups
      .append('text')
      .attr('y', 36)
      .attr('text-anchor', 'middle')
      .attr('fill', '#f1f5f9')
      .attr('font-size', '10px')
      .attr('font-family', 'monospace')
      .attr('font-weight', 'bold')
      .text((d) => (devMode ? d.devName : d.execName));

    nodeGroups
      .append('text')
      .attr('y', 48)
      .attr('text-anchor', 'middle')
      .attr('fill', '#94a3b8')
      .attr('font-size', '8.5px')
      .attr('font-family', 'monospace')
      .text((d) => (devMode ? d.devSub : d.execSub));
  }, [devMode]);

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-lg" ref={containerRef}>
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 mb-3">
        <div>
          <h3 className="text-sm font-bold text-white font-mono flex items-center gap-2">
            <Layers className="w-4 h-4 text-indigo-400" />
            {devMode
              ? 'D3 Network Topology: 3 Sovereign Planes Ingestion Pipeline'
              : 'D3 Live Architecture: How Traffic Flows Through Neural Defense'}
          </h3>
          <p className="text-xs text-slate-400 mt-0.5">
            {devMode
              ? 'Strict non-blocking boundary isolating net/http reverse proxy from gRPC inference & Kafka telemetry.'
              : 'Visual map showing how customer traffic is vetted by the AI brain before reaching your applications.'}
          </p>
        </div>

        {activeNode && (
          <div className="text-xs font-mono bg-slate-950 px-3 py-1 rounded-lg border border-slate-800 text-indigo-300">
            Selected: <span className="font-bold text-white">{devMode ? activeNode.devName : activeNode.execName}</span>
          </div>
        )}
      </div>

      {/* SVG Canvas */}
      <div className="w-full overflow-x-auto">
        <svg ref={svgRef} className="w-full min-w-[700px]" />
      </div>

      <div className="mt-2 pt-2 border-t border-slate-800/80 flex items-center justify-between text-[11px] font-mono text-slate-400">
        <span className="flex items-center gap-1.5 text-emerald-400">
          <ShieldCheck className="w-3.5 h-3.5" />
          {devMode
            ? 'Independent Scaling: Data Plane can scale horizontally without touching Kafka/DL clusters'
            : 'Enterprise Resilience: Web traffic never slows down even during security updates'}
        </span>
        <span className="text-slate-500">Interactive D3 Node Graph</span>
      </div>
    </div>
  );
};
