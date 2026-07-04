import { z } from 'zod';

export const ComplianceItemSchema = z.object({
  status: z.enum(['GREEN', 'AMBER', 'RED']),
  lastChecked: z.string()
});

export const ComplianceStatusSchema = z.object({
  pci: ComplianceItemSchema,
  sox: ComplianceItemSchema,
  gdpr: ComplianceItemSchema
});

export const ComplianceReportSchema = z.object({
  id: z.string(),
  status: z.enum(['READY', 'PROCESSING']),
  url: z.string().optional()
});

export type ComplianceItem = z.infer<typeof ComplianceItemSchema>;
export type ComplianceStatus = z.infer<typeof ComplianceStatusSchema>;
export type ComplianceReport = z.infer<typeof ComplianceReportSchema>;
