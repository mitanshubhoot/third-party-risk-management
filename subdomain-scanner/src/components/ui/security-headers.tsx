import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "./card";
import { SecurityCheck } from "@/types/security";

interface SecurityHeadersProps {
  checks: SecurityCheck[];
}

export function SecurityHeaders({ checks }: SecurityHeadersProps) {
  // Filter security header related checks
  const headerChecks = checks.filter(check => 
    ['hsts-enforced', 'x-frame-options', 'csp-implemented', 'x-content-type-options'].includes(check.id)
  );

  return (
    <Card>
      <CardHeader>
        <CardTitle>Security Headers</CardTitle>
        <CardDescription>Analysis of security-related HTTP headers</CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        {headerChecks.map((check) => (
          <div key={check.id} className="border-b pb-4 last:border-0">
            <h3 className="font-medium mb-2">{check.name}</h3>
            <p className={`text-sm ${
              check.status === 'pass' ? 'text-green-600' : 
              check.status === 'fail' ? 'text-red-600' : 
              'text-yellow-600'
            }`}>
              {check.details}
            </p>
          </div>
        ))}
        {headerChecks.length === 0 && (
          <p className="text-sm text-gray-500">No security header information available</p>
        )}
      </CardContent>
    </Card>
  );
} 