import React from 'react';
import { Navigate } from 'react-router-dom';
import { useAuthStore } from '@stores/auth.store';
import type { Role } from '@/types/auth.types';

interface Props {
  allowedRoles: Role[];
  children: React.ReactElement;
}

export const ProtectedRoute: React.FC<Props> = ({ allowedRoles, children }) => {
  const user = useAuthStore((s) => s.user);
  if (!user) return <Navigate to="/login" replace />;
  if (!allowedRoles.includes(user.role as Role)) return <Navigate to="/unauthorized" replace />;
  return children;
};
