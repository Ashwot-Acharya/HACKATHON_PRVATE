import React from 'react';

interface Props {
  challenge: 'C1' | 'C2' | 'C3' | 'C4';
}

export const ChallengeBadge: React.FC<Props> = ({ challenge }) => {
  const cls = {
    C1: 'bg-[#11D9C5]/20 text-[#11D9C5] border border-[#11D9C5]/30',
    C2: 'bg-amber-500/20 text-amber-400 border border-amber-500/30',
    C3: 'bg-purple-500/20 text-purple-400 border border-purple-500/30',
    C4: 'bg-[#027373]/20 text-[#027373] border border-[#027373]/30'
  }[challenge];

  return <span className={`px-2 py-1 text-xs rounded ${cls} font-mono`}>{challenge}</span>;
};
