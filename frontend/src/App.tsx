import React, { Suspense } from 'react';
import { createBrowserRouter, Navigate, RouterProvider } from 'react-router-dom';
import { STRINGS, ROLE } from '@lib/constants';
import { ErrorFallback } from '@components/common/ErrorFallback';
import { AppShell } from '@components/layout/AppShell';
import { ProtectedRoute } from '@components/layout/ProtectedRoute';

const LoginPage = React.lazy(() => import('@features/auth/LoginPage'));
const DashboardPage = React.lazy(() => import('@features/dashboard/DashboardPage'));
const AlertsPage = React.lazy(() => import('@features/alerts/AlertsPage'));
const ThreatIntelPage = React.lazy(() => import('@features/intel/ThreatIntelPage'));
const AuditPage = React.lazy(() => import('@features/compliance/AuditPage'));
const ReportingPage = React.lazy(() => import('@features/reporting/ReportingPage'));
const SettingsPage = React.lazy(() => import('@features/settings/SettingsPage'));
const RedTeamPage = React.lazy(() => import('@features/redteam/RedTeamPage'));
const PipelinePage = React.lazy(() => import('@features/orchestration/PipelinePage'));

const ErrorPage = () => (
  <div className="p-6">
    <ErrorFallback resetErrorBoundary={() => window.location.reload()} />
  </div>
);

const router = createBrowserRouter([
  
  {
    path: '/',
    element: <AppShell />,
    errorElement: <ErrorPage />,
    children: [
      { index: true, element: <Navigate to="/dashboard" replace /> },
      {
        path: 'dashboard',
        element: (
          <ProtectedRoute allowedRoles={[ROLE.SOC_ANALYST, ROLE.COMPLIANCE_OFFICER, ROLE.ADMIN]}>
            <Suspense fallback={<div>Loading...</div>}>
              <DashboardPage />
            </Suspense>
          </ProtectedRoute>
        )
      },
      {
        path: 'alerts',
        element: (
          <ProtectedRoute allowedRoles={[ROLE.SOC_ANALYST, ROLE.COMPLIANCE_OFFICER, ROLE.ADMIN]}>
            <Suspense fallback={<div>Loading...</div>}>
              <AlertsPage />
            </Suspense>
          </ProtectedRoute>
        )
      },
      {
        path: 'intel',
        element: (
          <ProtectedRoute allowedRoles={[ROLE.SOC_ANALYST, ROLE.COMPLIANCE_OFFICER, ROLE.ADMIN]}>
            <Suspense fallback={<div>Loading...</div>}>
              <ThreatIntelPage />
            </Suspense>
          </ProtectedRoute>
        )
      },
      {
        path: 'audit',
        element: (
          <ProtectedRoute allowedRoles={[ROLE.COMPLIANCE_OFFICER, ROLE.ADMIN]}>
            <Suspense fallback={<div>Loading...</div>}>
              <AuditPage />
            </Suspense>
          </ProtectedRoute>
        )
      },
      {
        path: 'reporting',
        element: (
          <ProtectedRoute allowedRoles={[ROLE.COMPLIANCE_OFFICER, ROLE.ADMIN]}>
            <Suspense fallback={<div>Loading...</div>}>
              <ReportingPage />
            </Suspense>
          </ProtectedRoute>
        )
      },
      {
        path: 'orchestration',
        element: (
          <ProtectedRoute allowedRoles={[ROLE.SOC_ANALYST, ROLE.COMPLIANCE_OFFICER, ROLE.ADMIN]}>
            <Suspense fallback={<div>Loading...</div>}>
              <PipelinePage />
            </Suspense>
          </ProtectedRoute>
        )
      },
      {
        path: 'settings',
        element: (
          <ProtectedRoute allowedRoles={[ROLE.ADMIN]}>
            <Suspense fallback={<div>Loading...</div>}>
              <SettingsPage />
            </Suspense>
          </ProtectedRoute>
        )
      },
      {
        path: 'redteam',
        element: (
          <ProtectedRoute allowedRoles={[ROLE.SOC_ANALYST, ROLE.COMPLIANCE_OFFICER, ROLE.ADMIN]}>
            <Suspense fallback={<div>Loading...</div>}>
              <RedTeamPage />
            </Suspense>
          </ProtectedRoute>
        )
      }
    ]
  },
  {
    path: '/login',
    element: (
      <Suspense fallback={<div>Loading...</div>}>
        <LoginPage />
      </Suspense>
    )
  },
  { path: '/unauthorized', element: <div>{STRINGS.ERRORS.INVALID_CREDENTIALS}</div> }
]);

export default function App() {
  return <RouterProvider router={router} />;
}
