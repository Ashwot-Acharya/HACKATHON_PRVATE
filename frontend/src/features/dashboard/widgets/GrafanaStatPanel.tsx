import React from 'react';

interface GrafanaStatPanelProps {
  title: string;
  value: string | number;
  colorClass?: string; // e.g., 'text-[#73BF69]' (green) or 'text-[#FF9830]' (orange)
}

export const GrafanaStatPanel: React.FC<GrafanaStatPanelProps> = ({
  title,
  value,
  colorClass = 'text-text-primary'
}) => {
  return (
    <div className="bg-bg-panel border border-bg-border rounded-lg shadow-sm flex flex-col h-full relative overflow-hidden group">
      <div className="absolute inset-0 bg-white/5 opacity-0 group-hover:opacity-100 transition-opacity pointer-events-none" />

      <div className="p-3 pb-0 flex items-center justify-between z-10">
        <span className="text-[12px] font-semibold text-text-secondary tracking-wide uppercase truncate" title={title}>
          {title}
        </span>
      </div>
      <div className="flex-1 flex items-center justify-center p-3 z-10 min-h-[60px]">
        <span className={`text-3xl md:text-4xl font-bold truncate ${colorClass}`}>
          {value}
        </span>
      </div>
    </div>
  );
};
