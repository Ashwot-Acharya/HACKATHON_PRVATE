import React from 'react';

interface Props {
  /** Raw MITRE technique id from backend. */
  technique?: string;
  /** Severity to use as fallback. */
  severity?: string;
}

const PRIORITY_MITRE: Record<string, string> = {
  CRITICAL: 'T1071.001 - C2 Application Layer Protocol',
  HIGH:     'T1021.001 - Remote Services / Lateral Movement',
  MEDIUM:   'T1213 - Data from Information Repositories',
  LOW:      'T1046 - Network Service Discovery',
  INFO:     'Normal Traffic',
};

function getMitre(raw: string | undefined, severity: string | undefined): string {
  const s = severity || 'INFO';
  const fallback = PRIORITY_MITRE[s] ?? 'T1071 - Application Layer Protocol';
  if (!raw || raw.trim() === '') return fallback;
  // Campaign ticket IDs: 16-char uppercase hex
  if (/^[0-9A-F]{12,}$/i.test(raw)) return fallback;
  if (raw.toLowerCase() === 'unknown') return fallback;
  return raw;
}

export const MITRETag: React.FC<Props> = ({ technique, severity }) => {
  const cleanTechnique = getMitre(technique, severity);
  
  return (
    <span className="px-2 py-0.5 rounded bg-[#027373]/20 border border-[#027373]/30 text-[10px] text-[#11D9C5] font-mono truncate max-w-[200px] inline-block align-middle">
      {cleanTechnique}
    </span>
  );
};

