import React from 'react';

interface Props {
  techniques: string[];
}

const MITRE_MAP: Record<string, { name: string; challenge: string }> = {
  'T1071.001': { name: 'Application Layer Protocol: Web', challenge: 'C4' },
  'T1046': { name: 'Network Service Discovery', challenge: 'C2' },
  'T1213': { name: 'Data from Information Repositories', challenge: 'C1' },
  'T1021': { name: 'Remote Services', challenge: 'C3' },
  'T1078': { name: 'Valid Accounts', challenge: 'C1' },
  'T1048': { name: 'Exfiltration Over Alternative Protocol', challenge: 'C4' },
  'T1059': { name: 'Command and Scripting Interpreter', challenge: 'C1' },
  'T1053': { name: 'Scheduled Task/Job', challenge: 'C1' },
};

const challengeColor: Record<string, string> = {
  C1: 'bg-challenge-c1/20 border-challenge-c1/40 text-challenge-c1',
  C2: 'bg-challenge-c2/20 border-challenge-c2/40 text-challenge-c2',
  C3: 'bg-challenge-c3/20 border-challenge-c3/40 text-challenge-c3',
  C4: 'bg-challenge-c4/20 border-challenge-c4/40 text-challenge-c4',
};

export const MITRENavigator: React.FC<Props> = ({ techniques }) => (
  <div className="grid grid-cols-2 gap-2">
    {techniques.map((tid) => {
      const info = MITRE_MAP[tid] || { name: tid, challenge: 'C1' };
      return (
        <div
          key={tid}
          className={`p-2 rounded-lg border ${challengeColor[info.challenge]} transition-all hover:scale-[1.02]`}
        >
          <div className="text-[10px] font-mono opacity-70">{tid}</div>
          <div className="text-xs font-medium mt-0.5">{info.name}</div>
        </div>
      );
    })}
  </div>
);
