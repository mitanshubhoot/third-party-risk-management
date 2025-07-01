export interface SecurityCheck {
  id: string;
  name: string;
  description: string;
  status: 'pass' | 'fail' | 'warning' | 'info';
  details?: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
} 