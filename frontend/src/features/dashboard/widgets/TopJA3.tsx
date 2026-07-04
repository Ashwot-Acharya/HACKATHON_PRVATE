import React, { useEffect, useState } from 'react';
import { apiClient } from '@lib/axios';

interface JA3Match {
  hash: string;
  description: string;
  count: number;
}

export const TopJA3: React.FC = () => {
  const [matches, setMatches] = useState<JA3Match[]>([]);

  useEffect(() => {
    const fetchJA3 = async () => {
      try {
        const res = await apiClient.get('/pipeline/metrics/ja3_top');
        setMatches(res.data);
      } catch (e) {
        console.error("Failed to fetch top JA3s", e);
      }
    };
    fetchJA3();
    const interval = setInterval(fetchJA3, 5000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="bg-panel border border-background-border rounded-lg p-4 h-full flex flex-col">
      <h3 className="text-sm font-semibold text-text-primary mb-3">Top JA3 matches (24h)</h3>
      <div className="space-y-2 flex-1 justify-center flex flex-col">
        {matches.length === 0 ? (
          <div className="text-xs text-text-muted text-center py-4">No JA3 data</div>
        ) : (
          matches.map((match, i) => (
            <div key={i} className="flex justify-between items-center text-xs p-1">
              <span className="text-text-secondary truncate pr-2" title={match.hash}>{match.description}</span>
              <span className="text-text-primary font-mono">{match.count}</span>
            </div>
          ))
        )}
      </div>
    </div>
  );
};
