'use client';

import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { IPAddresses } from '@/components/ui/ip-addresses';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { SecurityHeaders } from '@/components/ui/security-headers';
import {
  Sheet,
  SheetContent,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/sheet";
import { SecurityAssessment } from "@/components/ui/security-assessment";
import { FourthPartyIntegrations } from "@/components/ui/fourth-party-integrations";

interface SecurityHeadersData {
  hsts: {
    present: boolean;
    maxAge?: number;
    includeSubDomains?: boolean;
    preload?: boolean;
  };
  xFrameOptions: {
    present: boolean;
    value?: string;
  };
  contentSecurityPolicy: {
    present: boolean;
    policies?: Record<string, string[]>;
    unsafeDirectives?: string[];
  };
  xContentTypeOptions: {
    present: boolean;
    value?: string;
  };
  serverInfo: {
    present: boolean;
    value?: string;
  };
}

interface SecurityCheck {
  id: string;
  name: string;
  description: string;
  status: 'pass' | 'fail' | 'warning' | 'info';
  details?: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
}

interface RiskScore {
  overallScore: number;
  letterGrade: 'A' | 'B' | 'C' | 'D' | 'F';
  categoryScores: {
    websiteSecurity: number;
    encryption: number;
    ipReputation: number;
    vulnerabilityManagement: number;
    attackSurface: number;
    networkSecurity: number;
    emailSecurity: number;
    dataLeakage: number;
    dnsSecurity: number;
    brandReputation: number;
  };
  totalChecks: number;
  passedChecks: number;
  failedChecks: number;
  warningChecks: number;
  riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
}

interface SecurityAssessment {
  domain: string;
  lastChecked: string;
  checks: SecurityCheck[];
  overallRisk: 'low' | 'medium' | 'high' | 'critical';
  passedChecks: number;
  totalChecks: number;
  riskScore?: RiskScore;
}

interface FourthPartyIntegration {
  vendor: string;
  category: string;
  products: string[];
  domains: string[];
  confidence: 'HIGH' | 'MEDIUM' | 'LOW';
  detection_method: 'DNS' | 'HTTP_HEADERS' | 'JAVASCRIPT' | 'CONTENT' | 'SSL_CERT';
  risk_level?: 'LOW' | 'MEDIUM' | 'HIGH';
  privacy_implications?: string;
}

interface TechnologyStack {
  domain: string;
  technologies: {
    webServers: string[];
    frameworks: string[];
    cms: string[];
    analytics: string[];
    cdn: string[];
    security: string[];
    marketing: string[];
    ecommerce: string[];
    hosting: string[];
  };
  fourth_parties: FourthPartyIntegration[];
}

interface Subdomain {
  domain: string;
  source: string;
  ip_addresses: string[];
  is_active: boolean;
  security_headers?: SecurityHeadersData;
  security_assessment?: SecurityAssessment;
  technology_stack?: TechnologyStack;
}

interface IPAddress {
  address: string;
  domains: string[];
  services: ServiceInfo[];
  is_cloud?: boolean;
  source: string;
  owner?: string;
  autonomous_system?: string;
  country?: string;
  risk_level?: 'LOW' | 'MEDIUM' | 'HIGH';
  risk_details?: string[];
}

interface ServiceInfo {
  port: number;
  service: string;
  risk?: 'LOW' | 'MEDIUM' | 'HIGH';
  details?: string;
}

interface ScanResponse {
  data: Subdomain[];
  ip_addresses: IPAddress[];
  stats: {
    totalTime: string;
    sources: Record<string, number>;
    totalUnique: number;
    activeCount: number;
    inactiveCount: number;
  };
  ip_sources?: {
    totalUnique: number;
    sources: {
      [key: string]: {
        count: number;
        active: boolean;
        ips: string[];
      };
    };
  };
}

const sortDomains = (domain: string, subdomains: Subdomain[]): Subdomain[] => {
  // Find the primary domain (exact match)
  const primaryDomain = subdomains.find(sub => sub.domain === domain);
  const otherDomains = subdomains.filter(sub => sub.domain !== domain);
  
  // Sort other domains alphabetically
  const sortedOtherDomains = otherDomains.sort((a, b) => a.domain.localeCompare(b.domain));
  
  // Return primary domain first, followed by sorted other domains
  return primaryDomain ? [primaryDomain, ...sortedOtherDomains] : sortedOtherDomains;
};

export default function Home() {
  const [domain, setDomain] = useState('');
  const [isScanning, setIsScanning] = useState(false);
  const [selectedDomain, setSelectedDomain] = useState<string | null>(null);
  const [, setSecurityData] = useState<{
    headers?: any; // eslint-disable-line @typescript-eslint/no-explicit-any
    assessment?: SecurityAssessment;
  } | null>(null);
  const [isSheetOpen, setIsSheetOpen] = useState(false);

  const { data: scanResults, refetch: scanDomain } = useQuery<ScanResponse>({
    queryKey: ['scan', domain],
    queryFn: async () => {
      const response = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domain }),
      });
      if (!response.ok) {
        throw new Error('Scan failed');
      }
      return response.json();
    },
    enabled: false,
  });

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsScanning(true);
    try {
      await scanDomain();
    } finally {
      setIsScanning(false);
    }
  };

  // Sort the domains before displaying
  const sortedDomains = scanResults?.data ? sortDomains(domain, scanResults.data) : [];
  
  // Get the selected domain's security headers
  const selectedDomainData = selectedDomain 
    ? sortedDomains.find(d => d.domain === selectedDomain)
    : null;

  const handleViewSecurity = (subdomain: Subdomain) => {
    setSelectedDomain(subdomain.domain);
    setSecurityData({
      headers: subdomain.security_headers,
      assessment: subdomain.security_assessment
    });
    setIsSheetOpen(true);
  };

  return (
    <main className="min-h-screen p-8">
      <div className="max-w-7xl mx-auto">
        <h1 className="text-4xl font-bold mb-8">Subdomain Scanner</h1>
        
        <form onSubmit={handleSubmit} className="mb-8">
          <div className="flex gap-4">
            <Input
              type="text"
              placeholder="Enter domain (e.g., example.com)"
              value={domain}
              onChange={(e) => setDomain(e.target.value)}
              className="flex-1"
            />
            <Button type="submit" disabled={isScanning}>
              {isScanning ? 'Scanning...' : 'Scan Domain'}
            </Button>
          </div>
        </form>

        {scanResults && (
          <>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-8">
              <Card>
                <CardHeader className="pb-2">
                  <CardTitle className="text-sm font-medium">
                    Total Domains
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="text-2xl font-bold">{scanResults.stats.totalUnique}</div>
                </CardContent>
              </Card>
              <Card>
                <CardHeader className="pb-2">
                  <CardTitle className="text-sm font-medium">
                    Active Domains
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="text-2xl font-bold text-green-600">{scanResults.stats.activeCount}</div>
                </CardContent>
              </Card>
              <Card>
                <CardHeader className="pb-2">
                  <CardTitle className="text-sm font-medium">
                    Inactive Domains
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="text-2xl font-bold text-red-600">{scanResults.stats.inactiveCount}</div>
                </CardContent>
              </Card>
            </div>

            <Tabs defaultValue="domains" className="mb-8">
              <TabsList>
                <TabsTrigger value="domains">Domains</TabsTrigger>
                <TabsTrigger value="ips">IP Addresses</TabsTrigger>
                <TabsTrigger value="integrations">Fourth Parties</TabsTrigger>
              </TabsList>
              <TabsContent value="domains">
                <div className="rounded-lg border">
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead>Domain</TableHead>
                        <TableHead>Source</TableHead>
                        <TableHead>Status</TableHead>
                        <TableHead>Actions</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {sortedDomains.map((subdomain, index) => (
                        <TableRow key={index} className={subdomain.domain === domain ? "bg-blue-50" : ""}>
                          <TableCell className="font-mono">
                            {subdomain.domain}
                            {subdomain.domain === domain && (
                              <Badge variant="secondary" className="ml-2">Primary</Badge>
                            )}
                          </TableCell>
                          <TableCell>
                            <Badge variant="secondary">{subdomain.source}</Badge>
                          </TableCell>
                          <TableCell>
                            <Badge 
                              variant={subdomain.is_active ? "default" : "destructive"}
                              className={subdomain.is_active ? "bg-green-100 text-green-800" : ""}
                            >
                              {subdomain.is_active ? 'Active' : 'Inactive'}
                            </Badge>
                          </TableCell>
                          <TableCell>
                            {subdomain.is_active && (subdomain.security_headers || subdomain.security_assessment) && (
                              <Button
                                variant="outline"
                                size="sm"
                                onClick={() => handleViewSecurity(subdomain)}
                              >
                                View Security Assessment
                              </Button>
                            )}
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </div>
              </TabsContent>
              <TabsContent value="ips">
                <IPAddresses 
                  ipAddresses={scanResults.ip_addresses} 
                  sourceStats={scanResults.ip_sources}
                />
              </TabsContent>
              <TabsContent value="integrations">
                <FourthPartyIntegrations 
                  integrations={scanResults.data
                    .filter(d => d.is_active && d.technology_stack)
                    .map(d => d.technology_stack!)
                  } 
                />
              </TabsContent>
            </Tabs>

            {/* Security Headers Sheet */}
            <Sheet
              open={isSheetOpen}
              onOpenChange={(open) => {
                setIsSheetOpen(open);
                if (!open) {
                  setSelectedDomain(null);
                  setSecurityData(null);
                }
              }}
            >
              <SheetContent
                side="right"
                className="w-[600px] sm:w-[540px] overflow-y-auto"
              >
                <SheetHeader>
                  <SheetTitle className="flex items-center justify-between">
                    <span>Security Analysis for {selectedDomainData?.domain}</span>
                    <Button 
                      variant="outline" 
                      size="sm"
                      onClick={() => setIsSheetOpen(false)}
                    >
                      Close
                    </Button>
                  </SheetTitle>
                </SheetHeader>
                
                {selectedDomainData?.security_assessment && (
                  <div className="mt-6 mb-8">
                    <h3 className="text-lg font-semibold mb-4">Security Assessment</h3>
                    <SecurityAssessment assessment={selectedDomainData.security_assessment} />
                  </div>
                )}

                {selectedDomainData?.security_assessment && (
                  <div className="mt-6">
                    <h3 className="text-lg font-semibold mb-4">Security Headers</h3>
                    <SecurityHeaders checks={selectedDomainData.security_assessment.checks} />
                  </div>
                )}
              </SheetContent>
            </Sheet>
          </>
        )}
      </div>
    </main>
  );
} 