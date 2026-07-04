import { z } from 'zod';
import { UserSchema } from '@/types/auth.types';
import { apiClient } from '@lib/axios';

const LoginSchema = z.object({ accessToken: z.string(), user: UserSchema });

export const authService = {
  login: async (email: string, password: string) => {
    try {
      const res = await apiClient.post('/auth/login', { email, password });
      return LoginSchema.parse(res.data);
    } catch (err: any) {
      throw new Error(err.response?.data?.detail || 'Invalid credentials');
    }
  },
  refresh: async () => {
    return z.object({ accessToken: z.string() }).parse({ accessToken: 'mock.access.token' });
  },
  logout: async () => {
    return true;
  }
};
