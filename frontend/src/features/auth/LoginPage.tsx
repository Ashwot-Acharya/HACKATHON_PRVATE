import React from 'react';
import { STRINGS } from '@lib/constants';
import { LoginForm } from './LoginForm';
import { Shield } from 'lucide-react';

const LoginPage: React.FC = () => {
  return (
    <div className="min-h-screen bg-[#011126] flex items-center justify-center relative overflow-hidden">
      {/* Background glowing blobs */}
      <div className="absolute top-1/4 left-1/4 w-96 h-96 bg-[#027373]/15 rounded-full blur-[120px]" />
      <div className="absolute bottom-1/4 right-1/4 w-96 h-96 bg-[#11D9C5]/10 rounded-full blur-[120px]" />

      <div className="relative z-10 w-full max-w-md p-8 bg-[#011640]/60 backdrop-blur-xl border border-[#0a3060]/50 rounded-2xl shadow-2xl animate-fade-up">
        <div className="flex flex-col items-center mb-8">
          <div className="w-16 h-16 rounded-2xl bg-gradient-to-br from-[#027373] to-[#11D9C5] flex items-center justify-center shadow-lg shadow-[#11D9C5]/20 mb-6">
            <Shield size={32} className="text-text-primary" />
          </div>
          <h1 className="text-2xl font-bold text-text-primary tracking-tight mb-2">
            {STRINGS.APP_NAME}
          </h1>
          <p className="text-sm text-[#8BB8CC] text-center px-4">
            {STRINGS.SUBTITLE}
          </p>
        </div>

        <LoginForm />

        <div className="mt-8 pt-6 border-t border-[#0a3060]/50 text-center">
          <p className="text-xs text-[#4A7A8F]">
            Protected by Advanced AI Threat Detection
          </p>
        </div>
      </div>
    </div>
  );
};

export default LoginPage;
