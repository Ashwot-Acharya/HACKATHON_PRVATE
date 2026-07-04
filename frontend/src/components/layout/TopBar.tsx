import React, { useEffect, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { dashboardService } from '@services/dashboard.service';
import { queryKeys } from '@lib/queryKeys';
import { useUIStore } from '@stores/ui.store';
import { ShieldAlert, TrendingDown, Wifi, Clock, Zap, Menu } from 'lucide-react';

const AnimatedCounter: React.FC<{ value: number | string; suffix?: string }> = ({ value, suffix = '' }) => (
  <div className="animate-count-up">
    <span className="text-xl font-bold text-text-primary tabular-nums">{value}</span>
    {suffix && <span className="text-sm text-text-secondary ml-1">{suffix}</span>}
  </div>
);

export const TopBar: React.FC = () => {
  const setMobileMenuOpen = useUIStore(s => s.setMobileMenuOpen);
  const { data } = useQuery({
    queryKey: queryKeys.dashboard.kpis,
    queryFn: dashboardService.getKpis,
    refetchInterval: 5000
  });

  const [nepalTime, setNepalTime] = useState('');
  useEffect(() => {
    const update = () => {
      const now = new Date();
      const nepal = new Date(now.getTime() + (5 * 60 + 45) * 60000 + now.getTimezoneOffset() * 60000);
      setNepalTime(nepal.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false }));
    };
    update();
    const id = setInterval(update, 1000);
    return () => clearInterval(id);
  }, []);

  const kpis = [
    {
      label: 'FLOWS PROCESSED',
      challenge: 'C3',
      challengeClass: 'challenge-badge-c3',
      icon: <ShieldAlert size={14} />,
      value: data?.threatsToday ?? 0,
      sub: `▼ ${data?.suppressionRate ?? 0}% suppressed`,
      glowClass: 'glow-c3',
    },
    {
      label: 'FALSE POSITIVE RATE',
      challenge: 'C2',
      challengeClass: 'challenge-badge-c2',
      icon: <TrendingDown size={14} />,
      value: `${data?.falsePositiveRate ?? 2.4}%`,
      sub: 'Context-aware model',
      glowClass: 'glow-c2',
    },
    {
      label: 'THREAT INTEL FEED',
      challenge: 'C4',
      challengeClass: 'challenge-badge-c4',
      icon: <Wifi size={14} />,
      value: `${data?.intelFeedAgeMin ?? '—'}`,
      suffix: 'min ago',
      sub: 'abuse.ch live feed',
      glowClass: 'glow-c4',
      isLive: (data?.intelFeedAgeMin ?? 999) < 60,
    },
    {
      label: 'MEAN RESPONSE',
      challenge: 'C3',
      challengeClass: 'challenge-badge-c3',
      icon: <Clock size={14} />,
      value: `${data?.meanResponseTimeMs ?? 38.5}`,
      suffix: 'ms',
      sub: `Emitted: ${data?.alertsEmitted ?? 0} alerts`,
      glowClass: 'glow-c3',
    },
  ];

  return (
    <header className="px-2 md:px-4 py-3 flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
      <div className="flex w-full md:w-auto justify-between items-center md:hidden mb-2">
        <div className="text-text-primary font-bold text-lg">BankSentinel</div>
        <button 
          onClick={() => setMobileMenuOpen(true)}
          className="p-2 hover:bg-background-elevated rounded-lg text-text-muted hover:text-text-primary transition-colors"
        >
          <Menu size={24} />
        </button>
      </div>

      <div className="flex-1 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 w-full">
        {kpis.map((kpi, i) => (
          <div
            key={kpi.label}
            className={`stat-card ${kpi.glowClass} animate-fade-up`}
            style={{ animationDelay: `${i * 60}ms` }}
          >
            <div className="flex items-center justify-between mb-2">
              <div className="flex items-center gap-1.5">
                <span className="text-text-muted">{kpi.icon}</span>
                <span className="text-[10px] text-text-muted uppercase tracking-wider font-semibold">
                  {kpi.label}
                </span>
              </div>
              <span className={`challenge-badge ${kpi.challengeClass}`}>{kpi.challenge}</span>
            </div>
            <div className="flex items-baseline gap-1">
              <AnimatedCounter value={kpi.value} suffix={kpi.suffix} />
            </div>
            <div className="flex items-center gap-2 mt-1.5">
              <span className="text-[10px] text-text-muted">{kpi.sub}</span>
              {kpi.isLive !== undefined && (
                <span className={`live-badge ${kpi.isLive ? 'live-badge-active' : 'live-badge-inactive'}`}>
                  <span className={kpi.isLive ? 'status-dot-online' : 'status-dot-offline'} style={{ width: 5, height: 5 }} />
                  {kpi.isLive ? 'LIVE' : 'STALE'}
                </span>
              )}
            </div>
          </div>
        ))}
      </div>

      <div className="flex items-center gap-3 flex-shrink-0">
        <div className="glass-panel px-3 py-2 flex items-center gap-2">
          <Zap size={12} className="text-challenge-c2" />
          <span className="text-xs text-text-secondary font-mono">{nepalTime}</span>
          <span className="text-[10px] text-text-muted">NPT</span>
        </div>
      </div>
    </header>
  );
};
