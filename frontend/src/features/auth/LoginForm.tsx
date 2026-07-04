import React, { useState } from 'react';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import { useAuth } from '@hooks/useAuth';
import { Mail, Lock, ArrowRight, Loader2 } from 'lucide-react';

const schema = z.object({
  email: z.string().email('Please enter a valid email address'),
  password: z.string().min(8, 'Password must be at least 8 characters')
});

type FormValues = z.infer<typeof schema>;

export const LoginForm: React.FC = () => {
  const { login } = useAuth();
  const [isLoading, setIsLoading] = useState(false);
  const { register, handleSubmit, formState: { errors } } = useForm<FormValues>({ 
    resolver: zodResolver(schema) 
  });

  const onSubmit = async (data: FormValues) => {
    setIsLoading(true);
    try {
      await login(data.email, data.password);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <form onSubmit={handleSubmit(onSubmit)} className="space-y-5">
      <div className="space-y-1">
        <label htmlFor="email" className="block text-xs font-medium text-[#8BB8CC] ml-1">
          Email Address
        </label>
        <div className="relative">
          <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
            <Mail size={16} className="text-[#4A7A8F]" />
          </div>
          <input 
            id="email" 
            type="email" 
            placeholder="analyst@banksentinel.ai"
            {...register('email')} 
            className="w-full pl-10 pr-4 py-2.5 bg-[#011126]/60 border border-[#0a3060] rounded-lg text-text-primary placeholder:text-[#4A7A8F] focus:outline-none focus:ring-2 focus:ring-[#11D9C5]/50 focus:border-transparent transition-all" 
          />
        </div>
        {errors.email && (
          <p className="text-xs text-red-400 mt-1 ml-1">{errors.email.message}</p>
        )}
      </div>

      <div className="space-y-1">
        <label htmlFor="password" className="block text-xs font-medium text-[#8BB8CC] ml-1">
          Password
        </label>
        <div className="relative">
          <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
            <Lock size={16} className="text-[#4A7A8F]" />
          </div>
          <input 
            id="password" 
            type="password" 
            placeholder="••••••••"
            {...register('password')} 
            className="w-full pl-10 pr-4 py-2.5 bg-[#011126]/60 border border-[#0a3060] rounded-lg text-text-primary placeholder:text-[#4A7A8F] focus:outline-none focus:ring-2 focus:ring-[#11D9C5]/50 focus:border-transparent transition-all" 
          />
        </div>
        {errors.password && (
          <p className="text-xs text-red-400 mt-1 ml-1">{errors.password.message}</p>
        )}
      </div>

      <button 
        type="submit" 
        disabled={isLoading}
        className="w-full flex items-center justify-center gap-2 py-2.5 mt-2 bg-gradient-to-r from-[#027373] to-[#11D9C5] text-text-primary rounded-lg font-semibold shadow-lg shadow-[#11D9C5]/10 border border-[#11D9C5]/30 hover:border-[#11D9C5]/60 hover:shadow-[0_0_20px_rgba(17,217,197,0.45),0_0_40px_rgba(2,115,115,0.25)] hover:-translate-y-0.5 transition-all duration-300 disabled:opacity-70 disabled:cursor-not-allowed group"
      >
        {isLoading ? (
          <Loader2 size={18} className="animate-spin" />
        ) : (
          <>
            Secure Login
            <ArrowRight size={16} className="group-hover:translate-x-1 transition-transform" />
          </>
        )}
      </button>
    </form>
  );
};
