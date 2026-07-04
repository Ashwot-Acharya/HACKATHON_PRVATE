import { useMemo } from 'react';
import { useAuthStore } from '@stores/auth.store';
import { PERMISSIONS } from '@lib/constants';
import type { Role } from '@/types/auth.types';

export const usePermissions = () => {
  const user = useAuthStore((s) => s.user);

  const currentUser = user;
  const isAuthenticated = Boolean(user);

  const rolePermissions = useMemo(() => {
    const role = (user?.role ?? null) as Role | null;
    switch (role) {
      case 'ADMIN':
        return Object.values(PERMISSIONS);
      case 'COMPLIANCE_OFFICER':
        return [PERMISSIONS.VIEW_BEHAVIORAL_DATA];
      case 'SOC_ANALYST':
        return [PERMISSIONS.TRIGGER_CONTAINMENT, PERMISSIONS.VIEW_BEHAVIORAL_DATA];
      default:
        return [] as string[];
    }
  }, [user]);

  const hasRole = (r: Role) => user?.role === r;
  const can = (permission: string) => rolePermissions.includes(permission);

  return { hasRole, can, isAuthenticated, currentUser } as const;
};
