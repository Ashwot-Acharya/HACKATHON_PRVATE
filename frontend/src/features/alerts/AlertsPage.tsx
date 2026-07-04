import React, { useState } from 'react';
import { useAlertStore } from '@stores/alertStore';
import type { Alert } from '@/types/alert.types';
import { AlertFilters } from './AlertFilters';
import { AlertTable } from './AlertTable';
import { AlertDetailDrawer } from './AlertDetailDrawer';
import { ShieldAlert, Activity } from 'lucide-react';

const AlertsPage: React.FC = () => {
  const alerts = useAlertStore((state) => state.alerts);
  const clearAlerts = useAlertStore((state) => state.clearAlerts);
  const [selected, setSelected] = useState<Alert | null>(null);

  // Filter out INFO background traffic so it doesn't clutter the threat alerts table
  const displayAlerts = alerts.filter(a => a.severity !== 'INFO').slice(0, 100);
  const criticalCount = alerts.filter(a => a.severity === 'CRITICAL').length;
  const highCount = alerts.filter(a => a.severity === 'HIGH').length;

  return (
    <div className="flex flex-col h-[calc(100vh-6rem)] animate-fade-up">
      {/* Header section with Stats */}
      <div className="mb-4 glass-panel p-4 flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div>
          <h1 className="text-lg font-bold text-text-primary flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-[#027373] to-[#11D9C5] flex items-center justify-center">
              <ShieldAlert size={16} className="text-text-primary" />
            </div>
            Live Logs & Alerts
          </h1>
          <p className="text-xs text-text-muted mt-1">Real-time pipeline ingestion and multi-agent detection events</p>
        </div>
        
        <div className="flex items-center gap-4 text-sm w-full md:w-auto overflow-x-auto pb-1 md:pb-0">
          <div className="flex items-center gap-2 px-3 py-1.5 bg-background-elevated rounded-lg border border-background-border whitespace-nowrap">
            <Activity size={14} className="text-green-400" />
            <span className="text-text-secondary">Total Processed:</span>
            <span className="font-bold text-text-primary tabular-nums">{alerts.length}</span>
          </div>
          <div className="flex items-center gap-2 px-3 py-1.5 bg-red-500/10 rounded-lg border border-red-500/30 whitespace-nowrap">
            <div className="w-2 h-2 rounded-full bg-red-500 animate-pulse" />
            <span className="text-red-400 font-semibold">Critical:</span>
            <span className="font-bold text-red-400 tabular-nums">{criticalCount}</span>
          </div>
          <div className="flex items-center gap-2 px-3 py-1.5 bg-orange-500/10 rounded-lg border border-orange-500/30 whitespace-nowrap">
            <div className="w-2 h-2 rounded-full bg-orange-500" />
            <span className="text-orange-400 font-semibold">High:</span>
            <span className="font-bold text-orange-400 tabular-nums">{highCount}</span>
          </div>
        </div>
      </div>

      <div className="flex flex-col lg:grid lg:grid-cols-4 gap-4 flex-1 min-h-0">
        <div className="lg:col-span-1 glass-panel overflow-y-auto">
          <AlertFilters count={alerts.length} onClear={clearAlerts} />
        </div>
        <div className="lg:col-span-3 glass-panel flex flex-col min-h-0 overflow-hidden relative">
          <AlertTable alerts={displayAlerts} onAlertClick={(id) => setSelected(alerts.find((a) => a.id === id) ?? null)} />
        </div>
        <AlertDetailDrawer alert={selected} onClose={() => setSelected(null)} />
      </div>
    </div>
  );
};

export default AlertsPage;
