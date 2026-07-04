import React from 'react';
import { Shield, Lock, Radio, Timer } from 'lucide-react';

const LAYERS = [
  { id: 'l1', name: 'L1: JA3 Hash Match', icon: <Lock size={12} />, description: 'abuse.ch fingerprint feed', rate: '14,200+ hashes', color: 'from-[#027373] to-[#11D9C5]' },
  { id: 'l2', name: 'L2: JA3S Cross-Signal', icon: <Radio size={12} />, description: 'Bidirectional TLS fingerprint', rate: 'Catches Cobalt Strike', color: 'from-[#11D9C5] to-[#027373]' },
  { id: 'l3', name: 'L3: Beacon IAT Analysis', icon: <Timer size={12} />, description: 'Inter-arrival timing variance', rate: 'Zero-day C2 detection', color: 'from-[#027373] to-[#11D9C5]' },
];

export const EncryptedTrafficPanel: React.FC = () => (
  <div className="glass-panel p-4 glow-c4">
    <div className="flex items-center justify-between mb-4">
      <div className="flex items-center gap-2">
        <Shield size={14} className="text-challenge-c4" />
        <span className="text-xs font-semibold text-text-secondary uppercase tracking-wider">Encrypted Traffic Analysis</span>
      </div>
      <span className="challenge-badge challenge-badge-c4">C4</span>
    </div>

    <div className="space-y-3">
      {LAYERS.map((layer, i) => (
        <div key={layer.id} className="animate-fade-up" style={{ animationDelay: `${i * 100}ms` }}>
          <div className="flex items-center justify-between mb-1.5">
            <div className="flex items-center gap-2">
              <span className="text-challenge-c4">{layer.icon}</span>
              <span className="text-xs font-medium text-text-primary">{layer.name}</span>
            </div>
            <span className="live-badge live-badge-active">
              <span className="status-dot-online" style={{ width: 4, height: 4 }} />
              ACTIVE
            </span>
          </div>
          <div className="progress-bar">
            <div
              className={`progress-bar-fill bg-gradient-to-r ${layer.color}`}
              style={{ width: '100%' }}
            />
          </div>
          <div className="flex items-center justify-between mt-1">
            <span className="text-[10px] text-text-muted">{layer.description}</span>
            <span className="text-[10px] text-text-muted font-mono">{layer.rate}</span>
          </div>
        </div>
      ))}
    </div>

    <div className="mt-4 p-3 rounded-lg bg-background-elevated border border-background-border">
      <div className="flex items-center gap-2 mb-1">
        <span className="text-[10px] font-semibold text-severity-low">✓ PAYLOAD DECRYPTED: NO</span>
      </div>
      <div className="text-[10px] text-text-muted">
        TLS 1.3 integrity preserved. 91.7% detection rate via metadata-only analysis.
      </div>
    </div>
  </div>
);
