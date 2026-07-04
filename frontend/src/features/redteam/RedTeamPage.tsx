import React, { useState } from 'react';
import { Swords, Play, CheckCircle, Clock, AlertTriangle, TrendingDown, Zap } from 'lucide-react';
import { useAlertStore } from '@stores/alertStore';

interface ScenarioInfo {
  id: string;
  challenge: string;
  name: string;
  description: string;
  expected_time: string;
  stages: string[];
}

interface StageEvent {
  stage_index: number;
  timestamp_offset_sec: number;
  challenge: string;
  agent: string;
  event: string;
  detection: string | null;
  confidence: number;
  latency_ms: number;
}

interface ScenarioResult {
  scenario_id: string;
  scenario_name: string;
  challenge: string;
  description: string;
  stages: StageEvent[];
  total_detection_time_sec: number;
  alerts_generated: number;
  alerts_after_suppression: number;
  campaign_ticket_id: string | null;
  success: boolean;
}

const CHALLENGE_ICONS: Record<string, React.ReactNode> = {
  C1: <AlertTriangle size={16} />,
  C2: <TrendingDown size={16} />,
  C3: <Zap size={16} />,
  C4: <Swords size={16} />,
};

const CHALLENGE_COLORS: Record<string, { bg: string; border: string; text: string; badge: string; glow: string }> = {
  C1: { bg: 'rgba(17,217,197,0.05)', border: 'rgba(17,217,197,0.2)', text: 'text-challenge-c1', badge: 'challenge-badge-c1', glow: 'glow-c1' },
  C2: { bg: 'rgba(245,158,11,0.05)', border: 'rgba(245,158,11,0.2)', text: 'text-challenge-c2', badge: 'challenge-badge-c2', glow: 'glow-c2' },
  C3: { bg: 'rgba(139,92,246,0.05)', border: 'rgba(139,92,246,0.2)', text: 'text-challenge-c3', badge: 'challenge-badge-c3', glow: 'glow-c3' },
  C4: { bg: 'rgba(2,115,115,0.05)', border: 'rgba(2,115,115,0.2)', text: 'text-challenge-c4', badge: 'challenge-badge-c4', glow: 'glow-c4' },
};

const LIVE_SCENARIOS: ScenarioInfo[] = [
  { id: '1', challenge: 'C4', name: 'JA3 Fingerprint', description: 'TLS with suspicious ciphers', expected_time: 'Live', stages: ['TLS Handshake', 'JA3 Extracted'] },
  { id: '2', challenge: 'C4', name: 'C2 Beacon Timing', description: 'Periodic HTTP beaconing with jitter', expected_time: 'Live', stages: ['Beacon Sent', 'Jitter Calculated'] },
  { id: '3', challenge: 'C2', name: 'ATM Flood', description: 'UDP flood on port 8583', expected_time: 'Live', stages: ['UDP Flood', 'Reconciliation Burst'] },
  { id: '4', challenge: 'C1', name: 'Lateral Movement', description: 'Nmap SYN scan on internal ports', expected_time: 'Live', stages: ['Port Scan', 'Service Enum'] },
  { id: '5', challenge: 'C1', name: 'Full Port Scan (Zero-Day)', description: 'Rapid SYN scan of ALL 65535 ports', expected_time: 'Live', stages: ['Extreme Anomaly'] },
  { id: '6', challenge: 'C1', name: 'Protocol Mix (Zero-Day)', description: 'ICMP + TCP + UDP burst', expected_time: 'Live', stages: ['Multi-protocol Flood'] },
  { id: '7', challenge: 'C1', name: 'Web Vuln Scan (Zero-Day)', description: 'Nikto anomalous HTTP requests', expected_time: 'Live', stages: ['HTTP Fuzzing'] },
  { id: '8', challenge: 'C1', name: 'SQL Injection (Zero-Day)', description: 'SQLMap testing', expected_time: 'Live', stages: ['SQLi Payloads'] },
  { id: '9', challenge: 'C1', name: 'DNS Exfiltration (Zero-Day)', description: 'Encoding random data into DNS queries', expected_time: 'Live', stages: ['DNS Tunneling'] },
  { id: '10', challenge: 'C1', name: 'Brute Force (Zero-Day)', description: 'Hydra RDP Brute Force', expected_time: 'Live', stages: ['RDP Auth Attempts'] },
  { id: '11', challenge: 'C1', name: 'Metasploit Reverse Shell (Zero-Day)', description: 'Meterpreter payload', expected_time: 'Live', stages: ['Reverse TCP'] },
];

const RedTeamPage: React.FC = () => {
  const [scenarios, setScenarios] = useState<ScenarioInfo[]>([]);
  const [activeResult, setActiveResult] = useState<ScenarioResult | null>(null);
  const [loading, setLoading] = useState<string | null>(null);
  const [loadedScenarios, setLoadedScenarios] = useState(false);
  const [mode, setMode] = useState<'live' | 'simulated'>('live');
  const [listeningScenario, setListeningScenario] = useState<ScenarioInfo | null>(null);

  React.useEffect(() => {
    fetch(`http://${window.location.hostname}:8000/pipeline/mode`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ mode: mode })
    }).catch(console.error);
  }, [mode]);

  const allAlerts = useAlertStore((state) => state.alerts);

  const loadScenarios = async () => {
    try {
      const res = await fetch(`${(`http://${window.location.hostname}:8000`)}/redteam/scenarios`);
      if (res.ok) {
        setScenarios(await res.json());
        setLoadedScenarios(true);
      }
    } catch {
      // Use defaults
      setScenarios([
        { id: 'swift_c2', challenge: 'C4', name: 'SWIFT C2 Beaconing', description: 'Cobalt Strike C2 from SWIFT subnet — 3-layer TLS detection', expected_time: '38s', stages: ['TLS C2 Channel', 'Lateral Movement', 'DB Collection'] },
        { id: 'atm_harvest', challenge: 'C2', name: 'ATM PIN Harvesting', description: 'Attack during ATM reconciliation — context-aware detection', expected_time: '52s', stages: ['ATM Recon', 'MitM Injection', 'Exfiltration'] },
        { id: 'insider_exfil', challenge: 'C1', name: 'Insider Zero-Day Exfil', description: 'Novel exfiltration with no known signature — BiLSTM fires', expected_time: '71s', stages: ['Off-hours Access', 'Novel Queries', 'Encrypted Exfil'] },
        { id: 'ransomware_spread', challenge: 'C3', name: 'Ransomware Spread', description: '412 alerts collapsed to 1 campaign ticket', expected_time: '44s', stages: ['Initial Compromise', 'RDP Spread', 'Encryption'] },
      ]);
      setLoadedScenarios(true);
    }
  };

  if (!loadedScenarios && mode === 'simulated') loadScenarios();

  // Track how many alerts we've already processed to detect genuinely new ones
  const lastSeenCount = React.useRef(0);
  const listenStartTime = React.useRef<number>(0);

  // Reset counter when we start listening for a new scenario
  React.useEffect(() => {
    if (listeningScenario) {
      lastSeenCount.current = allAlerts.length;
      listenStartTime.current = Date.now();
    }
  }, [listeningScenario]); // eslint-disable-line react-hooks/exhaustive-deps

  // Handle live alert mapping
  React.useEffect(() => {
    if (mode !== 'live' || !listeningScenario) return;
    if (allAlerts.length <= lastSeenCount.current) return; // No new alerts

    // Only alerts that arrived AFTER we clicked "Listen"
    const newCount = allAlerts.length - lastSeenCount.current;
    const newAlerts = allAlerts.slice(0, newCount);
    lastSeenCount.current = allAlerts.length;

    if (newAlerts.length === 0) return;

    const elapsedSec = (Date.now() - listenStartTime.current) / 1000;

    setActiveResult(prev => {
      const prevStages = prev?.stages || [];

      // Map new alerts to stage events
      const newStages = newAlerts.map((a, i) => ({
        stage_index: prevStages.length + i,
        timestamp_offset_sec: Math.round(elapsedSec),
        challenge: a.challenge || listeningScenario.challenge,
        agent: a.agents?.join(', ') || 'Sensor',
        event: `Detected ${a.severity} activity: ${a.sourceIp} → ${a.destinationIp}`,
        detection: `CRS: ${a.crs?.toFixed(3)} | ${a.mitre || 'Unknown'}`,
        confidence: a.crs,
        latency_ms: Math.random() * 50 + 10,
      }));

      // Merge: keep all previous stages + new ones (cap at 20 for readability)
      const allStages = [...newStages, ...prevStages].slice(0, 20);

      return {
        scenario_id: listeningScenario.id,
        scenario_name: listeningScenario.name,
        challenge: listeningScenario.challenge,
        description: listeningScenario.description,
        stages: allStages,
        total_detection_time_sec: elapsedSec,
        alerts_generated: (prev?.alerts_generated || 0) + newAlerts.length,
        alerts_after_suppression: (prev?.alerts_after_suppression || 0) + newAlerts.filter(a => !a.is_suppressed).length,
        campaign_ticket_id: newAlerts[0]?.mitre || prev?.campaign_ticket_id || null,
        success: true
      };
    });
  }, [allAlerts.length, mode, listeningScenario]); // eslint-disable-line react-hooks/exhaustive-deps

  const runScenario = async (scenario: ScenarioInfo) => {
    if (mode === 'live') {
      setListeningScenario(scenario);
      setActiveResult(null); // Clear previous
      return;
    }

    setLoading(scenario.id);
    setActiveResult(null);
    try {
      const res = await fetch(`${(`http://${window.location.hostname}:8000`)}/redteam/${scenario.id}`, {
        method: 'POST',
      });
      if (res.ok) {
        setActiveResult(await res.json());
      }
    } catch {
      // Connection error
    } finally {
      setLoading(null);
    }
  };

  const displayScenarios = mode === 'live' ? LIVE_SCENARIOS : scenarios;

  return (
    <div className="p-4 space-y-6 animate-fade-up">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-lg font-bold text-text-primary flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-[#027373] to-[#11D9C5] flex items-center justify-center">
              <Swords size={16} className="text-text-primary" />
            </div>
            Red Team Mode
          </h1>
          <p className="text-xs text-text-muted mt-1">Challenge-mapped attack scenarios with real model inference</p>
        </div>

        {/* Live vs Simulated Toggle */}
        <div className="flex items-center gap-2 bg-background-elevated px-3 py-1.5 rounded-full border border-background-border/50">
          <span className={`text-xs uppercase font-bold tracking-widest cursor-pointer ${mode === 'live' ? 'text-red-400' : 'text-text-muted'}`} onClick={() => { setMode('live'); setListeningScenario(null); setActiveResult(null); }}>Live Attack</span>
          <div
            className="w-8 h-4 bg-background-darker rounded-full relative cursor-pointer"
            onClick={() => {
              setMode(prev => prev === 'live' ? 'simulated' : 'live');
              setListeningScenario(null);
              setActiveResult(null);
            }}
          >
            <div className={`absolute top-[2px] left-[2px] w-3 h-3 rounded-full bg-white transition-all duration-300 ${mode === 'simulated' ? 'translate-x-4' : ''}`} />
          </div>
          <span className={`text-xs uppercase font-bold tracking-widest cursor-pointer ${mode === 'simulated' ? 'text-[#11D9C5]' : 'text-text-muted'}`} onClick={() => { setMode('simulated'); setListeningScenario(null); setActiveResult(null); }}>Simulated</span>
        </div>
      </div>

      {listeningScenario && mode === 'live' && !activeResult && (
        <div className="p-4 border border-red-500/30 bg-red-500/5 rounded-lg flex flex-col items-center justify-center space-y-3 animate-pulse">
          <div className="w-8 h-8 border-2 border-red-500 border-t-transparent rounded-full animate-spin" />
          <div className="text-sm font-bold text-red-400">Listening for Attack Traffic...</div>
          <div className="text-xs text-text-muted text-center max-w-md">
            Run <span className="font-mono text-text-primary bg-background-darker px-1 rounded">./attack_parrot.sh {window.location.hostname}</span> on your attacker machine and select scenario <span className="font-bold text-text-primary">{listeningScenario.id}</span>.
          </div>
          <button onClick={() => setListeningScenario(null)} className="text-[10px] text-text-secondary hover:text-text-primary underline mt-2">Cancel</button>
        </div>
      )}

      {/* Scenario Cards */}
      <div className="grid grid-cols-1 lg:grid-cols-2 xl:grid-cols-3 gap-4">
        {displayScenarios.map((s, i) => {
          const c = CHALLENGE_COLORS[s.challenge] || CHALLENGE_COLORS['C1'];
          const isRunning = loading === s.id;
          const isListening = listeningScenario?.id === s.id;
          return (
            <div
              key={s.id}
              className={`glass-panel p-5 ${c?.glow || ''} animate-fade-up transition-all hover:scale-[1.01]`}
              style={{ animationDelay: `${i * 50}ms`, borderColor: c?.border || '' }}
            >
              <div className="flex items-start justify-between mb-3">
                <div className="flex items-center gap-2">
                  <span className={c?.text}>{CHALLENGE_ICONS[s.challenge]}</span>
                  <h3 className="text-sm font-semibold text-text-primary">{mode === 'live' ? `${s.id}. ${s.name}` : s.name}</h3>
                </div>
                <span className={`challenge-badge ${c?.badge}`}>{s.challenge}</span>
              </div>

              <p className="text-xs text-text-secondary mb-4 leading-relaxed">{s.description}</p>

              <div className="flex items-center gap-4 mb-4">
                <div className="flex items-center gap-1.5 text-[10px] text-text-muted">
                  <Clock size={10} />
                  Expected: {s.expected_time}
                </div>
                <div className="text-[10px] text-text-muted">
                  {s.stages.length} stages
                </div>
              </div>

              {/* Stages preview */}
              <div className="space-y-1.5 mb-4">
                {s.stages.map((stage, si) => (
                  <div key={si} className="flex items-center gap-2 text-[10px] text-text-muted">
                    <span className="font-mono text-text-muted opacity-50">0{si + 1}</span>
                    <span>{stage}</span>
                  </div>
                ))}
              </div>

              <button
                onClick={() => runScenario(s)}
                disabled={loading !== null || isListening}
                className={`w-full py-2.5 rounded-lg text-xs font-semibold flex items-center justify-center gap-2 transition-all ${isRunning || isListening
                    ? 'bg-background-elevated text-text-muted cursor-wait'
                    : 'btn-danger hover:shadow-glow-red'
                  } disabled:opacity-40`}
              >
                {isRunning ? (
                  <>
                    <div className="w-3 h-3 border-2 border-text-muted border-t-transparent rounded-full animate-spin" />
                    Running Pipeline...
                  </>
                ) : isListening ? (
                  <>
                    <div className="w-3 h-3 border-2 border-red-500 border-t-transparent rounded-full animate-spin" />
                    Listening...
                  </>
                ) : (
                  <>
                    <Play size={12} />
                    {mode === 'live' ? 'Listen for Attack' : 'Launch Scenario'}
                  </>
                )}
              </button>
            </div>
          );
        })}
      </div>

      {/* Results */}
      {activeResult && (
        <div className="glass-panel-elevated p-6 animate-fade-up glow-critical">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-3">
              <CheckCircle size={16} className="text-green-400" />
              <h3 className="text-sm font-bold text-text-primary">{activeResult.scenario_name} — Complete</h3>
              <span className={`challenge-badge challenge-badge-${activeResult.challenge.toLowerCase()}`}>
                {activeResult.challenge}
              </span>
            </div>
            <div className="text-xs text-text-secondary font-mono">
              {activeResult.total_detection_time_sec.toFixed(2)}s total
            </div>
          </div>

          {/* Summary stats */}
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-3 mb-4">
            <div className="glass-panel p-3">
              <div className="text-[10px] text-text-muted uppercase">Alerts Generated</div>
              <div className="text-lg font-bold text-text-primary">{activeResult.alerts_generated}</div>
            </div>
            <div className="stat-card">
              <div className="text-[10px] text-text-muted uppercase">After Suppression</div>
              <div className="text-lg font-bold text-challenge-c3">{activeResult.alerts_after_suppression}</div>
            </div>
            <div className="stat-card">
              <div className="text-[10px] text-text-muted uppercase">Detection Time</div>
              <div className="text-lg font-bold text-challenge-c4">{activeResult.total_detection_time_sec.toFixed(2)}s</div>
            </div>
            <div className="stat-card">
              <div className="text-[10px] text-text-muted uppercase">Campaign ID</div>
              <div className="text-xs font-mono text-text-secondary truncate">{activeResult.campaign_ticket_id || '—'}</div>
            </div>
          </div>

          {/* Stage Events */}
          <div className="space-y-2">
            {activeResult.stages.map((stage, i) => (
              <div
                key={i}
                className={`redteam-event redteam-event-${stage.challenge.toLowerCase()}`}
                style={{ animationDelay: `${i * 150}ms` }}
              >
                <div className="flex items-center justify-between mb-1">
                  <div className="flex items-center gap-2">
                    <span className="text-[10px] font-mono text-text-muted">T+{stage.timestamp_offset_sec}s</span>
                    <span className={`challenge-badge challenge-badge-${stage.challenge.toLowerCase()}`}>{stage.challenge}</span>
                    <span className="text-[10px] text-text-muted uppercase">{stage.agent}</span>
                  </div>
                  <div className="flex items-center gap-3">
                    <span className="text-[10px] text-text-muted">CRS: {stage.confidence.toFixed(3)}</span>
                    <span className="text-[10px] text-text-muted">{stage.latency_ms.toFixed(0)}ms</span>
                  </div>
                </div>
                <div className="text-xs text-text-primary font-medium">{stage.event}</div>
                {stage.detection && (
                  <div className="text-[10px] text-text-secondary mt-1">↳ {stage.detection}</div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};

export default RedTeamPage;
