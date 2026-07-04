import React, { useMemo, useState, useEffect, useRef } from 'react';
import { useAlertStore } from '@stores/alertStore';
import { GrafanaStatPanel } from './widgets/GrafanaStatPanel';
import { GrafanaLineChart } from './widgets/GrafanaLineChart';
import { GrafanaTable } from './widgets/GrafanaTable';
import { ThreatTriageList } from './widgets/ThreatTriageList';
import { AgentHealth } from './widgets/AgentHealth';
import { TopJA3 } from './widgets/TopJA3';
import { AlertVolumeChart } from './widgets/AlertVolumeChart';
import { Shield, Activity } from 'lucide-react';
import { apiClient } from '@lib/axios';

const DashboardPage: React.FC = () => {
  const alerts = useAlertStore((state) => state.alerts);
  const [totalRawEvents, setTotalRawEvents] = useState(0);
  const rawEventsRef = useRef(0);

  // Stats
  const flaggedThreats = alerts.filter(a => a.severity === 'CRITICAL' || a.severity === 'HIGH').length;

  // Real-time raw suricata WebSocket
  useEffect(() => {
    let wsUrl = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000';
    if (wsUrl.startsWith('http')) {
      wsUrl = wsUrl.replace(/^http/, 'ws');
    } else {
      const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
      wsUrl = import.meta.env.MODE === 'development'
        ? `${protocol}//${window.location.hostname}:8000`
        : `${protocol}//${window.location.host}`;
    }

    const ws = new WebSocket(`${wsUrl}/ws/suricata_raw`);

    ws.onmessage = async (event) => {
      try {
        const msg = JSON.parse(event.data);
        if (msg.type === 'suricata_raw') {
          rawEventsRef.current += 1;
          setTotalRawEvents(rawEventsRef.current);

          const rawData = msg.data;
          try {
            await apiClient.post('/pipeline/suricata', rawData);
          } catch (e) {
            console.error("Failed to send raw data to ML pipeline:", e);
          }
        }
      } catch (err) {
        console.error("WS Parse error", err);
      }
    };

    return () => { ws.close(); };
  }, []);

  // ── Build real time-series from actual alert timestamps ──
  const severityCriticalData = useMemo(() => buildTimeSeries(alerts, 'CRITICAL'), [alerts]);
  const severityHighData = useMemo(() => buildTimeSeries(alerts, 'HIGH'), [alerts]);
  const severityMediumData = useMemo(() => buildTimeSeries(alerts, 'MEDIUM'), [alerts]);

  // Format real alerts for the table
  const tableData = alerts.slice(0, 50).map((alert) => ({
    id: alert.id,
    timestamp: new Date(alert.timestamp).toISOString().replace('T', ' ').substring(0, 19),
    signatureId: alert.id.substring(0, 8),
    alertSignature: alert.mitre || "Unknown Event",
    sourceIp: alert.sourceIp,
    protocol: alert.raw_payload?.protocol || 'TCP',
    destinationIp: alert.destinationIp || '0.0.0.0',
    destinationPort: alert.raw_payload?.dst_port || 0,
  }));

  // Format real alerts for Triage
  const triageData = [...alerts]
    .sort((a, b) => (b.crs || 0) - (a.crs || 0))
    .slice(0, 15)
    .map(alert => ({
      id: alert.id,
      sourceIp: alert.sourceIp,
      severity: alert.severity as 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW',
      category: alert.mitre || 'Threat Activity',
      score: alert.crs || 0
    }));

  return (
    <div className="flex flex-col h-full bg-bg-primary text-text-primary overflow-y-auto p-4 space-y-4 font-sans animate-fade-up">

      {/* Header */}
      <div className="flex items-center justify-between mb-2">
        <h1 className="text-xl font-bold text-text-primary tracking-wide flex items-center gap-2">
          SOC Overview
        </h1>
        <div className="flex items-center gap-2">
           <span className="live-badge live-badge-active">
              <span className="status-dot-online" style={{ width: 6, height: 6 }} />
              LIVE FEED
           </span>
        </div>
      </div>

      {/* Row 1: Stat Panels */}
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 h-[120px]">
        <GrafanaStatPanel
          title="Total Raw Network Events (Suricata)"
          value={totalRawEvents}
          colorClass="text-accent-teal"
        />
        <GrafanaStatPanel
          title="Flagged Threats (High/Critical)"
          value={flaggedThreats}
          colorClass="text-severity-critical"
        />
      </div>

      {/* Row 2: Severity Timelines */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 h-[200px]">
        <GrafanaLineChart title="Critical Severity Volume" data={severityCriticalData} color="#EF4444" />
        <GrafanaLineChart title="High Severity Volume" data={severityHighData} color="#F97316" />
        <GrafanaLineChart title="Medium/Low Volume" data={severityMediumData} color="#EAB308" />
      </div>

      {/* Row 3: Live Triage & Table */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4 h-[400px]">

        {/* Threat Triage System */}
        <div className="lg:col-span-4 h-[400px]">
          <ThreatTriageList title="Active Threat Triage (Ranked)" data={triageData} />
        </div>

        {/* Events Table */}
        <div className="lg:col-span-8 h-[400px]">
          <GrafanaTable title="Analyzed ML Detection Feed" data={tableData} />
        </div>
      </div>

      {/* Row 4: System Telemetry */}
      <div className="grid grid-cols-1 md:grid-cols-12 gap-4 h-[400px]">
        <div className="md:col-span-8">
          <AlertVolumeChart />
        </div>
        <div className="md:col-span-4 flex flex-col gap-4 h-[400px]">
          <div className="flex-1">
            <AgentHealth />
          </div>
          <div className="flex-1">
            <TopJA3 />
          </div>
        </div>
      </div>
    </div>
  );
};

/**
 * Build a time-bucketed series from real alert timestamps,
 * bucketed into 30-second intervals over the last 15 minutes.
 */
function buildTimeSeries(
  alerts: { timestamp: string; severity: string }[],
  severity: string
): { time: string; value: number }[] {
  const filtered = alerts.filter(a => a.severity === severity);
  const now = Date.now();
  const BUCKET_MS = 30_000;     // 30-second buckets
  const TOTAL_BUCKETS = 30;     // last 15 minutes

  const buckets: number[] = new Array(TOTAL_BUCKETS).fill(0);
  const bucketStart = now - TOTAL_BUCKETS * BUCKET_MS;

  for (const a of filtered) {
    const t = new Date(a.timestamp).getTime();
    const idx = Math.floor((t - bucketStart) / BUCKET_MS);
    if (idx >= 0 && idx < TOTAL_BUCKETS) {
      buckets[idx]++;
    }
  }

  return buckets.map((count, i) => {
    const ts = new Date(bucketStart + i * BUCKET_MS);
    const hh = ts.getHours().toString().padStart(2, '0');
    const mm = ts.getMinutes().toString().padStart(2, '0');
    const ss = ts.getSeconds().toString().padStart(2, '0');
    return { time: `${hh}:${mm}:${ss}`, value: count };
  });
}

export default DashboardPage;
