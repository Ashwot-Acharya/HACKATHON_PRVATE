import { z } from 'zod';

export const ROLE = z.enum(['SOC_ANALYST', 'COMPLIANCE_OFFICER', 'ADMIN']);

export const UserSchema = z.object({
  id: z.string(),
  email: z.string().email(),
  name: z.string(),
  role: ROLE
});

export type Role = z.infer<typeof ROLE>;
export type AuthUser = z.infer<typeof UserSchema>;
