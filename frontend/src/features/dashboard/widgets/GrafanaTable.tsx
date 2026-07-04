import React from 'react';

export interface TableRowData {
  id: string;
  timestamp: string;
  signatureId: string;
  alertSignature: string;
  sourceIp: string;
  protocol: string;
  destinationIp: string;
  destinationPort: string | number;
}

interface GrafanaTableProps {
  title: string;
  data: TableRowData[];
}

export const GrafanaTable: React.FC<GrafanaTableProps> = ({ title, data }) => {
  return (
    <div className="bg-bg-panel border border-bg-border rounded-lg shadow-sm flex flex-col h-full relative group">
      {/* Title */}
      <div className="p-3 pb-2 flex items-center justify-between z-10 border-b border-bg-border">
        <span className="text-[12px] font-semibold text-text-secondary tracking-wide uppercase truncate" title={title}>
          {title}
        </span>
      </div>

      <div className="flex-1 w-full overflow-auto">
        <table className="w-full text-left border-collapse text-[11px] whitespace-nowrap">
          <thead className="bg-bg-elevated sticky top-0 z-20 shadow-sm">
            <tr>
              <th className="py-2 px-3 text-text-secondary font-semibold border-b border-bg-border">@timestamp</th>
              <th className="py-2 px-3 text-text-secondary font-semibold border-b border-bg-border">Sigature ID</th>
              <th className="py-2 px-3 text-text-secondary font-semibold border-b border-bg-border">Alert Signature</th>
              <th className="py-2 px-3 text-text-secondary font-semibold border-b border-bg-border">Source IP</th>
              <th className="py-2 px-3 text-text-secondary font-semibold border-b border-bg-border">Protocol</th>
              <th className="py-2 px-3 text-text-secondary font-semibold border-b border-bg-border">Destination IP</th>
              <th className="py-2 px-3 text-text-secondary font-semibold border-b border-bg-border">Destination Port</th>
            </tr>
          </thead>
          <tbody className="text-text-primary">
            {data.map((row, idx) => (
              <tr 
                key={row.id} 
                className={`hover:bg-bg-elevated transition-colors border-b border-bg-border/50 ${idx % 2 === 0 ? 'bg-bg-panel' : 'bg-bg-elevated/30'}`}
              >
                <td className="py-1.5 px-3 text-accent-teal">{row.timestamp}</td>
                <td className="py-1.5 px-3">{row.signatureId}</td>
                <td className="py-1.5 px-3 truncate max-w-[250px]" title={row.alertSignature}>{row.alertSignature}</td>
                <td className="py-1.5 px-3">{row.sourceIp}</td>
                <td className="py-1.5 px-3">{row.protocol}</td>
                <td className="py-1.5 px-3">{row.destinationIp}</td>
                <td className="py-1.5 px-3">{row.destinationPort}</td>
              </tr>
            ))}
            {data.length === 0 && (
              <tr>
                <td colSpan={7} className="py-4 text-center text-text-muted">No data available</td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};
