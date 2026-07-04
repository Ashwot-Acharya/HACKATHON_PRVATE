import React, { useState, useEffect } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Globe, Shield, RefreshCw, Server, ArrowUpRight } from 'lucide-react';
import { intelService } from '@services/intel.service';

const ThreatIntelPage: React.FC = () => {
  const { data: feeds, isLoading: feedsLoading } = useQuery({
    queryKey: ['intel', 'feeds'], 
    queryFn: intelService.getFeeds,
    refetchInterval: 10000
  });

  const [federation, setFederation] = useState<any>(null); // eslint-disable-line @typescript-eslint/no-explicit-any
  const [loadingFed, setLoadingFed] = useState(false);

  useEffect(() => {
    const loadFed = async () => {
      setLoadingFed(true);
      try {
        const res = await fetch(`${(`http://${window.location.hostname}:8000`)}/federation/threat-feed`);
        if (res.ok) {
          setFederation(await res.json());
        }
      } catch (e) {
        console.error(e);
      } finally {
        setLoadingFed(false);
      }
    };
    loadFed();
  }, []);

  return (
    <div className="p-4 space-y-6 animate-fade-up h-full overflow-y-auto">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-lg font-bold text-text-primary flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-[#027373] to-[#11D9C5] flex items-center justify-center">
              <Globe size={16} className="text-text-primary" />
            </div>
            Threat Intelligence & Federation
          </h1>
          <p className="text-xs text-text-muted mt-1">Live OSINT feeds and NRB banking federation network</p>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Local Feeds (OSINT) */}
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-sm font-semibold text-text-primary flex items-center gap-2">
              <Shield size={16} className="text-challenge-c4" /> Local OSINT Feeds
            </h2>
            <span className="challenge-badge challenge-badge-c4">C4</span>
          </div>

          <div className="glass-panel p-4">
            {feedsLoading ? (
              <div className="text-xs text-text-muted text-center py-4">Loading OSINT feeds...</div>
            ) : (
              <div className="space-y-4">
                {(feeds ?? []).map((feed: any) => ( // eslint-disable-line @typescript-eslint/no-explicit-any
                  <div key={feed.name} className="p-3 rounded-lg bg-background-elevated border border-background-border">
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-xs font-semibold text-text-primary">{feed.name}</span>
                      <span className={`live-badge ${feed.status === 'LIVE' ? 'live-badge-active' : ''}`}>
                        <span className={feed.status === 'LIVE' ? "status-dot-online" : "status-dot-offline"} style={{ width: 4, height: 4 }} /> {feed.status}
                      </span>
                    </div>
                    <div className="flex items-center gap-4 mb-2">
                      <div className="text-[10px] text-text-muted">
                        <span className="font-semibold text-text-secondary">{feed.count}</span> indicators
                      </div>
                    </div>
                    <div className="text-[10px] text-text-muted flex items-center gap-1">
                      <RefreshCw size={10} /> Last sync: {new Date(feed.lastUpdated).toLocaleString()}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* Federation Net */}
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-sm font-semibold text-text-primary flex items-center gap-2">
              <Server size={16} className="text-challenge-c1" /> Banking Federation Network
            </h2>
            <div className="flex items-center gap-2">
              <span className="text-[10px] font-mono text-[#11D9C5]">CONNECTED</span>
            </div>
          </div>

          <div className="glass-panel p-4 h-full relative overflow-hidden">
            {/* Background Grid */}
            <div className="absolute inset-0 bg-grid-pattern opacity-10 pointer-events-none" />
            
            {loadingFed ? (
              <div className="text-xs text-text-muted text-center py-4">Syncing with NRB Federation...</div>
            ) : federation ? (
              <div className="relative z-10 space-y-4">
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 mb-6">
                  <div className="p-3 rounded-lg bg-challenge-c1/10 border border-challenge-c1/20">
                    <div className="text-[10px] text-text-muted uppercase mb-1">Member Banks</div>
                    <div className="text-xl font-bold text-challenge-c1">{federation.member_banks}</div>
                  </div>
                  <div className="p-3 rounded-lg bg-challenge-c3/10 border border-challenge-c3/20">
                    <div className="text-[10px] text-text-muted uppercase mb-1">Shared IOCs</div>
                    <div className="text-xl font-bold text-challenge-c3">{federation.total_iocs}</div>
                  </div>
                </div>

                <div className="text-xs font-semibold text-text-primary mb-2">Recent Community Signatures</div>
                <div className="space-y-2">
                  {federation.iocs.map((ioc: any, i: number) => ( // eslint-disable-line @typescript-eslint/no-explicit-any
                    <div key={i} className="p-3 rounded-lg bg-background-primary border border-background-border animate-fade-up" style={{ animationDelay: `${i * 100}ms` }}>
                      <div className="flex items-center justify-between mb-1">
                        <span className="text-[10px] text-challenge-c1 font-mono">{ioc.ioc_type}</span>
                        <span className="text-[10px] text-text-muted">Conf: {(ioc.confidence * 100).toFixed(0)}%</span>
                      </div>
                      <div className="text-[10px] font-mono text-text-secondary truncate mb-2">
                        {ioc.ioc_hash}
                      </div>
                      <div className="flex items-center justify-between">
                        <div className="text-[10px] text-text-muted flex items-center gap-1">
                          <ArrowUpRight size={10} /> {ioc.contributing_bank}
                        </div>
                        <div className="text-[10px] font-semibold text-challenge-c2">{ioc.attack_type}</div>
                      </div>
                    </div>
                  ))}
                </div>

                <div className="mt-4 p-3 rounded-lg bg-background-elevated border border-background-border">
                  <div className="text-[10px] text-text-muted leading-relaxed">
                    <strong>Privacy Note:</strong> {federation.privacy_note}
                  </div>
                </div>
              </div>
            ) : (
              <div className="text-xs text-text-muted text-center py-4">Federation API unreachable.</div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

export default ThreatIntelPage;
