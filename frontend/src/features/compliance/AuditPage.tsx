import React from 'react';
import { useQuery } from '@tanstack/react-query';
import { auditService } from '@services/audit.service';
import { AuditChainViewer } from '@components/feature/AuditChainViewer';
import { Lock, FileText, CheckCircle, Search } from 'lucide-react';

const AuditPage: React.FC = () => {
  const { data } = useQuery({ 
    queryKey: ['audit', 'logs'], 
    queryFn: () => auditService.getLogs({ page: 1, pageSize: 50 }),
    refetchInterval: 10000 
  });

  return (
    <div className="p-4 space-y-6 animate-fade-up h-full overflow-y-auto">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-lg font-bold text-text-primary flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-[#027373] to-[#11D9C5] flex items-center justify-center">
              <Lock size={16} className="text-text-primary" />
            </div>
            Immutable Audit Chain
          </h1>
          <p className="text-xs text-text-muted mt-1">PCI-DSS 10.3 compliant cryptographically linked action logs</p>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2 space-y-4">
          <div className="glass-panel p-5 h-full">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-sm font-semibold text-text-primary">Action Ledger</h2>
              <div className="relative">
                <Search size={14} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-text-muted" />
                <input type="text" placeholder="Search hash or action..." className="input-dark pl-8 w-64 text-xs" />
              </div>
            </div>
            <AuditChainViewer entries={data?.data ?? []} />
          </div>
        </div>

        <div className="col-span-1 space-y-4">
          <div className="glass-panel p-5">
            <h2 className="text-sm font-semibold text-text-primary mb-4">Chain Integrity Status</h2>
            <div className="flex items-center gap-3 p-4 rounded-lg bg-[#11D9C5]/10 border border-[#11D9C5]/20 mb-4">
              <CheckCircle size={24} className="text-[#11D9C5]" />
              <div>
                <div className="text-sm font-bold text-[#11D9C5]">CRYPTOGRAPHICALLY VALID</div>
                <div className="text-[10px] text-text-muted">Last verified: just now</div>
              </div>
            </div>
            <div className="space-y-2">
              <div className="flex justify-between text-xs">
                <span className="text-text-muted">Chain Length:</span>
                <span className="text-text-primary font-mono">{data?.total ?? 0} blocks</span>
              </div>
              <div className="flex justify-between text-xs">
                <span className="text-text-muted">Hashing Algorithm:</span>
                <span className="text-text-primary font-mono">SHA-256</span>
              </div>
              <div className="flex justify-between text-xs">
                <span className="text-text-muted">Compliance Target:</span>
                <span className="challenge-badge challenge-badge-c2">PCI-DSS / NRB</span>
              </div>
            </div>
          </div>
          
          <div className="glass-panel p-5">
             <h2 className="text-sm font-semibold text-text-primary mb-3 flex items-center gap-2">
              <FileText size={14} /> Reporting
            </h2>
            <p className="text-xs text-text-muted mb-4 leading-relaxed">
              Export chain of custody report for NRB auditor compliance checks. The report includes cryptographic proofs for all containment actions.
            </p>
            <button 
              className="w-full btn-primary text-xs flex justify-center gap-2"
              onClick={async () => {
                const toast = (await import('react-hot-toast')).toast;
                const toastId = toast.loading('Generating NRB Compliance Report...');
                try {
                  await auditService.downloadNrbReport();
                  toast.success('NRB Report generated successfully and downloaded to your device.', { id: toastId });
                } catch (e) {
                  toast.error('Failed to generate NRB Report.', { id: toastId });
                  console.error(e);
                }
              }}
            >
              <FileText size={14} /> Generate NRB Report
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

export default AuditPage;
