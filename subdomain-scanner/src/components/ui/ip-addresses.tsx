import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import { Badge } from '@/components/ui/badge';
import { Card } from '@/components/ui/card';

interface ServiceInfo {
  port: number;
  service: string;
  risk?: 'LOW' | 'MEDIUM' | 'HIGH';
  details?: string;
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

interface IPAddressesProps {
  ipAddresses: IPAddress[];
  sourceStats?: {
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

function getRiskBadgeVariant(risk: 'LOW' | 'MEDIUM' | 'HIGH' | undefined): 'destructive' | 'secondary' | 'default' | 'outline' {
  switch (risk) {
    case 'HIGH':
      return 'destructive';
    case 'MEDIUM':
      return 'secondary';
    case 'LOW':
      return 'outline';
    default:
      return 'default';
  }
}

function getUniqueServices(services: ServiceInfo[]): ServiceInfo[] {
  const uniqueMap = new Map<string, ServiceInfo>();
  
  for (const service of services) {
    const key = `${service.port}-${service.service}`;
    if (!uniqueMap.has(key)) {
      uniqueMap.set(key, service);
    }
  }
  
  return Array.from(uniqueMap.values());
}

export function IPAddresses({ ipAddresses, sourceStats }: IPAddressesProps) {
  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h2 className="text-2xl font-bold">IP Addresses</h2>
        <Badge variant="secondary">{ipAddresses.length} addresses found</Badge>
      </div>



      <div className="rounded-lg border">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Source</TableHead>
              <TableHead>IP Address</TableHead>
              <TableHead>Owner</TableHead>
              <TableHead>Autonomous System</TableHead>
              <TableHead>Country</TableHead>
              <TableHead>Risk Level</TableHead>
              <TableHead>Services</TableHead>
              <TableHead>Domains</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {ipAddresses.map((ip, index) => (
              <TableRow key={index} className="group">
                <TableCell>{ip.source}</TableCell>
                <TableCell className="font-mono">
                  {ip.address}
                  {ip.is_cloud && (
                    <Badge variant="outline" className="ml-2">Cloud</Badge>
                  )}
                </TableCell>
                <TableCell>{ip.owner || '-'}</TableCell>
                <TableCell>{ip.autonomous_system || '-'}</TableCell>
                <TableCell>{ip.country || '-'}</TableCell>
                <TableCell>
                  <Badge variant={getRiskBadgeVariant(ip.risk_level)}>
                    {ip.risk_level || 'UNKNOWN'}
                  </Badge>
                </TableCell>
                <TableCell>
                  <div className="flex flex-wrap gap-1">
                    {getUniqueServices(ip.services).map((service, i) => (
                      <Badge 
                        key={i} 
                        variant={getRiskBadgeVariant(service.risk)}
                        className="cursor-help"
                        title={`${service.port}/tcp - ${service.details || 'No details available'}`}
                      >
                        {service.service}
                      </Badge>
                    ))}
                  </div>
                </TableCell>
                <TableCell>
                  <div className="flex flex-wrap gap-1">
                    {ip.domains.map((domain, i) => (
                      <Badge key={i} variant="outline">{domain}</Badge>
                    ))}
                  </div>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </div>

      {/* Risk Details Section */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 mt-8">
        {ipAddresses.filter(ip => ip.risk_level === 'HIGH' || (ip.risk_details && ip.risk_details.length > 0)).map((ip, index) => (
          <Card key={index} className="p-4">
            <div className="flex items-center justify-between mb-2">
              <h3 className="font-bold">{ip.address}</h3>
              <Badge variant={getRiskBadgeVariant(ip.risk_level)}>
                {ip.risk_level || 'UNKNOWN'}
              </Badge>
            </div>
            <div className="space-y-2">
              {ip.risk_details?.map((detail, i) => (
                <div key={i} className="text-sm text-gray-600 dark:text-gray-400">
                  • {detail}
                </div>
              ))}
              <div className="text-sm text-gray-600 dark:text-gray-400 mt-2">
                Open Services:
                <div className="flex flex-wrap gap-1 mt-1">
                  {getUniqueServices(ip.services).map((service, i) => (
                    <Badge 
                      key={i} 
                      variant={getRiskBadgeVariant(service.risk)}
                      className="cursor-help"
                      title={service.details}
                    >
                      {service.port}/tcp {service.service}
                    </Badge>
                  ))}
                </div>
              </div>
            </div>
          </Card>
        ))}
      </div>
    </div>
  );
} 