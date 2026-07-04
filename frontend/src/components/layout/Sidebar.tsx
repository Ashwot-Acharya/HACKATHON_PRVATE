import React from 'react';
import { Link, useLocation } from 'react-router-dom';
import { useUIStore } from '@stores/ui.store';
import { usePermissions } from '@hooks/usePermissions';
import {
  LayoutDashboard, AlertTriangle, Globe, Lock, Settings,
  Swords, Shield, ChevronLeft, ChevronRight, Activity, X, FileText, Network
} from 'lucide-react';

const challengeColors: Record<string, string> = {
  C1: 'challenge-badge-c1',
  C2: 'challenge-badge-c2',
  C3: 'challenge-badge-c3',
  C4: 'challenge-badge-c4',
};

interface NavItemProps {
  to: string;
  label: string;
  challenge?: 'C1' | 'C2' | 'C3' | 'C4';
  icon: React.ReactNode;
  disabled?: boolean;
  collapsed: boolean;
}

const NavItem: React.FC<NavItemProps> = ({ to, label, challenge, icon, disabled, collapsed }) => {
  const loc = useLocation();
  const active = loc.pathname === to || loc.pathname.startsWith(to + '/');

  return (
    <Link
      to={disabled ? '#' : to}
      className={`sidebar-nav-item ${active ? 'sidebar-nav-item-active' : ''} ${disabled ? 'opacity-30 pointer-events-none' : ''}`}
    >
      <div className="w-5 h-5 flex-shrink-0">{icon}</div>
      {(!collapsed || window.innerWidth < 768) && (
        <>
          <span className="flex-1 truncate">{label}</span>
          {challenge && (
            <span className={`challenge-badge ${challengeColors[challenge]}`}>{challenge}</span>
          )}
        </>
      )}
    </Link>
  );
};

export const Sidebar: React.FC = () => {
  const { sidebarCollapsed, mobileMenuOpen, toggleSidebar, setMobileMenuOpen } = useUIStore();
  const { hasRole } = usePermissions();

  const handleLinkClick = () => {
    if (window.innerWidth < 768) {
      setMobileMenuOpen(false);
    }
  };

  return (
    <>
      {/* Mobile Backdrop */}
      {mobileMenuOpen && (
        <div
          className="md:hidden fixed inset-0 z-40 bg-black/50 backdrop-blur-sm"
          onClick={() => setMobileMenuOpen(false)}
        />
      )}

      <aside
        className={`glass-panel flex flex-col justify-between transition-all duration-300 ease-in-out fixed md:relative z-50 h-full m-0 md:m-2 md:mr-0 p-3 
        ${mobileMenuOpen ? 'translate-x-0 w-[280px]' : '-translate-x-full md:translate-x-0'} 
        ${sidebarCollapsed ? 'md:w-[64px]' : 'md:w-[240px]'}`}
      >
        {/* Top section */}
        <div className="space-y-1">
          {/* Logo */}
          <div className="flex items-center gap-3 px-2 py-3 mb-2 justify-between">
            <div className="flex items-center gap-3">
              <div className="w-8 h-8 rounded-lg bg-bg-panel border border-bg-border flex items-center justify-center flex-shrink-0">
                <Shield size={16} className="text-accent-teal" />
              </div>
              {(!sidebarCollapsed || mobileMenuOpen) && (
                <div className="animate-fade-up">
                  <div className="text-sm font-bold text-text-primary tracking-wide">BankSentinel</div>
                  <div className="text-[10px] text-text-secondary font-medium tracking-wider uppercase">SOC Dashboard</div>
                </div>
              )}
            </div>
            {/* Mobile Close Button */}
            <button
              className="md:hidden p-2 hover:bg-background-elevated rounded-lg"
              onClick={() => setMobileMenuOpen(false)}
            >
              <X size={18} className="text-text-muted" />
            </button>
          </div>

          {/* Monitoring Section */}
          {(!sidebarCollapsed || mobileMenuOpen) && (
            <div className="text-[10px] text-text-muted uppercase tracking-[0.15em] px-3 pt-4 pb-1 font-semibold">
              Monitoring
            </div>
          )}
          <div onClick={handleLinkClick}>
            <NavItem to="/dashboard" label="SOC Dashboard" icon={<LayoutDashboard size={16} />} collapsed={sidebarCollapsed} />
          </div>
          <div onClick={handleLinkClick}>
            <NavItem to="/orchestration" label="Pipeline Orchestration" icon={<Network size={16} />} collapsed={sidebarCollapsed} />
          </div>
          <div onClick={handleLinkClick}>
            <NavItem to="/alerts" label="Alert Triage" icon={<AlertTriangle size={16} />} collapsed={sidebarCollapsed} />
          </div>

          {/* Analysis Section */}
          {(!sidebarCollapsed || mobileMenuOpen) && (
            <div className="text-[10px] text-text-muted uppercase tracking-[0.15em] px-3 pt-5 pb-1 font-semibold">
              Analysis
            </div>
          )}
          <div onClick={handleLinkClick}><NavItem to="/intel" label="Threat Intel" challenge="C4" icon={<Globe size={16} />} collapsed={sidebarCollapsed} /></div>
          <div onClick={handleLinkClick}><NavItem to="/redteam" label="Red Team" icon={<Swords size={16} />} collapsed={sidebarCollapsed} /></div>

          {/* Operations Section */}
          {(!sidebarCollapsed || mobileMenuOpen) && (
            <div className="text-[10px] text-text-muted uppercase tracking-[0.15em] px-3 pt-5 pb-1 font-semibold">
              Operations
            </div>
          )}
          <div onClick={handleLinkClick}>
            <NavItem
              to="/audit" label="Audit Chain" challenge="C2" icon={<Lock size={16} />}
              disabled={!hasRole('COMPLIANCE_OFFICER') && !hasRole('ADMIN')} collapsed={sidebarCollapsed}
            />
          </div>
          <div onClick={handleLinkClick}>
            <NavItem
              to="/reporting" label="Reporting" icon={<FileText size={16} />}
              disabled={!hasRole('COMPLIANCE_OFFICER') && !hasRole('ADMIN')} collapsed={sidebarCollapsed}
            />
          </div>
          <div onClick={handleLinkClick}>
            <NavItem
              to="/settings" label="Settings" icon={<Settings size={16} />}
              disabled={!hasRole('ADMIN')} collapsed={sidebarCollapsed}
            />
          </div>
        </div>

        {/* Bottom section */}
        <div className="space-y-3">
          {/* Agent Status indicator removed as requested */}

          {/* Collapse toggle */}
          <button
            onClick={toggleSidebar}
            className="w-full hidden md:flex items-center justify-center p-2 rounded-lg hover:bg-background-elevated transition-colors text-text-muted hover:text-text-primary"
          >
            {sidebarCollapsed ? <ChevronRight size={16} /> : <ChevronLeft size={16} />}
          </button>

          {/* User */}
          <div className="flex items-center gap-3 px-2 py-2">
            <div className="w-8 h-8 rounded-full bg-bg-panel border border-bg-border flex items-center justify-center flex-shrink-0">
              <span className="text-xs font-bold text-text-primary">KK</span>
            </div>
            {(!sidebarCollapsed || mobileMenuOpen) && (
              <div className="min-w-0">
                <div className="text-sm text-text-primary font-medium truncate">Kshitiz Khanal</div>
                <div className="text-[10px] text-text-muted uppercase tracking-wider">Admin</div>
              </div>
            )}
          </div>
        </div>
      </aside>
    </>
  );
};
