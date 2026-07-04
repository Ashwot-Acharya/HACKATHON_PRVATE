import React, { useState } from 'react';
import { responseService } from '@services/response.service';
import { usePermissions } from '@hooks/usePermissions';
import { PERMISSIONS } from '@lib/constants';
import { toast } from 'react-hot-toast';

interface Props {
  /** Alert id to act on. */
  alertId: string;
}

export const ResponseActionPanel: React.FC<Props> = ({ alertId }) => {
  const { can } = usePermissions();
  const [reason, setReason] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const canAct = can(PERMISSIONS.TRIGGER_CONTAINMENT);

  const onAction = async (action: 'quarantine' | 'suspend' | 'block' | 'snapshot') => {
    if (!canAct) return;
    if (reason.trim().length < 10) {
      toast.error('Reason must be at least 10 characters');
      return;
    }
    setIsLoading(true);
    try {
      const res =
        action === 'quarantine'
          ? await responseService.quarantine(alertId, reason)
          : action === 'suspend'
          ? await responseService.suspendAccount(alertId, reason)
          : action === 'block'
          ? await responseService.blockIp(alertId, reason)
          : await responseService.snapshot(alertId, reason);
      toast.success(`Action ${res.actionId} completed`);
    } catch (err) {
      toast.error('Service unavailable');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="bg-panel border border-background-border rounded p-4 space-y-3">
      <div className="text-sm font-semibold text-text.primary">Response Actions</div>
      <textarea
        value={reason}
        onChange={(e) => setReason(e.target.value)}
        placeholder="Enter reason (min 10 chars)"
        className="w-full p-2 rounded bg-background-border text-text.primary text-sm"
        rows={3}
      />
      <div className="grid grid-cols-2 gap-2">
        <button disabled={!canAct || isLoading} onClick={() => onAction('quarantine')} className="px-3 py-2 rounded bg-severity-critical text-white text-xs">Quarantine Host</button>
        <button disabled={!canAct || isLoading} onClick={() => onAction('suspend')} className="px-3 py-2 rounded bg-severity-high text-white text-xs">Suspend Account</button>
        <button disabled={!canAct || isLoading} onClick={() => onAction('block')} className="px-3 py-2 rounded bg-challenge-c4 text-white text-xs">Block External IP</button>
        <button disabled={!canAct || isLoading} onClick={() => onAction('snapshot')} className="px-3 py-2 rounded bg-background-elevated text-text.primary text-xs">Forensic Snapshot</button>
      </div>
      {!canAct && <div className="text-xs text-text.secondary">Requires containment permission.</div>}
    </div>
  );
};
