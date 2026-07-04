import { useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuthStore } from '@stores/auth.store';
import { authService } from '@services/auth.service';
import { ROLE } from '@lib/constants';
import { toast } from 'react-hot-toast';
import { STRINGS } from '@lib/constants';

export const useAuth = () => {
  const setTokens = useAuthStore((s) => s.setTokens);
  const clearAuth = useAuthStore((s) => s.clearAuth);
  const navigate = useNavigate();

  const login = useCallback(async (email: string, password: string) => {
    try {
      const res = await authService.login(email, password);
      setTokens(res.accessToken, { id: res.user.id, name: res.user.name, role: res.user.role as ROLE });
      navigate('/dashboard');
    } catch (err) {
      toast.error(STRINGS.ERRORS.INVALID_CREDENTIALS);
      throw err;
    }
  }, [navigate, setTokens]);

  const logout = useCallback(() => {
    clearAuth();
    navigate('/login');
  }, [clearAuth, navigate]);

  return { login, logout };
};
