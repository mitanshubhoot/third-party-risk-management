import { Badge } from '@/components/ui/badge';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { ChevronRight, Shield, Globe, Package } from 'lucide-react';
import { useState } from 'react';

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

interface FourthPartyIntegrationsProps {
  integrations: TechnologyStack[];
}

// Get vendor icon/logo
const getVendorIcon = (vendor: string) => {
  const vendorLower = vendor.toLowerCase();
  
  // Return emoji icons for common vendors
  if (vendorLower.includes('cloudflare')) return '☁️';
  if (vendorLower.includes('amazon') || vendorLower.includes('aws')) return '📦';
  if (vendorLower.includes('google')) return '🔍';
  if (vendorLower.includes('microsoft')) return '🪟';
  if (vendorLower.includes('meta') || vendorLower.includes('facebook')) return '📘';
  if (vendorLower.includes('stripe')) return '💳';
  if (vendorLower.includes('shopify')) return '🛒';
  if (vendorLower.includes('github')) return '🐙';
  if (vendorLower.includes('netlify')) return '🌐';
  if (vendorLower.includes('vercel')) return '▲';
  if (vendorLower.includes('framer')) return '🎨';
  
  // Default icons by category
  return '🏢';
};

// Get vendor domain
const getVendorDomain = (vendor: string) => {
  const vendorLower = vendor.toLowerCase();
  
  if (vendorLower.includes('cloudflare')) return 'cloudflare.com';
  if (vendorLower.includes('amazon')) return 'amazon.com';
  if (vendorLower.includes('google')) return 'google.com';
  if (vendorLower.includes('microsoft')) return 'microsoft.com';
  if (vendorLower.includes('meta')) return 'meta.com';
  if (vendorLower.includes('stripe')) return 'stripe.com';
  if (vendorLower.includes('shopify')) return 'shopify.com';
  if (vendorLower.includes('github')) return 'github.com';
  if (vendorLower.includes('netlify')) return 'netlify.com';
  if (vendorLower.includes('vercel')) return 'vercel.com';
  if (vendorLower.includes('framer')) return 'framer.com';
  
  // Fallback to generic domain
  return `${vendorLower.replace(/\s+/g, '').toLowerCase()}.com`;
};

const getCategoryColor = (category: string) => {
  switch (category.toLowerCase()) {
    case 'cdn': return 'bg-blue-100 text-blue-800 border-blue-200';
    case 'analytics': return 'bg-purple-100 text-purple-800 border-purple-200';
    case 'marketing': return 'bg-pink-100 text-pink-800 border-pink-200';
    case 'e-commerce': 
    case 'ecommerce': return 'bg-emerald-100 text-emerald-800 border-emerald-200';
    case 'hosting provider':
    case 'hosting': return 'bg-indigo-100 text-indigo-800 border-indigo-200';
    case 'security': return 'bg-amber-100 text-amber-800 border-amber-200';
    case 'cms': return 'bg-orange-100 text-orange-800 border-orange-200';
    case 'framework': return 'bg-gray-100 text-gray-800 border-gray-200';
    case 'web server': return 'bg-slate-100 text-slate-800 border-slate-200';
    case 'mx records': return 'bg-teal-100 text-teal-800 border-teal-200';
    case 'nameservers': return 'bg-cyan-100 text-cyan-800 border-cyan-200';
    default: return 'bg-gray-100 text-gray-800 border-gray-200';
  }
};

export function FourthPartyIntegrations({ integrations }: FourthPartyIntegrationsProps) {
  const [viewMode, setViewMode] = useState<'vendor' | 'category'>('vendor');
  const [expandedVendors, setExpandedVendors] = useState<Set<string>>(new Set());

  // Aggregate all integrations across domains
  const allIntegrations = integrations.flatMap(stack => 
    stack.fourth_parties.map(integration => ({
      ...integration,
      sourceDomain: stack.domain
    }))
  );

  // Group by vendor
  const vendorGroups = allIntegrations.reduce((acc, integration) => {
    const key = integration.vendor;
    if (!acc[key]) {
      acc[key] = [];
    }
    acc[key].push(integration);
    return acc;
  }, {} as Record<string, (FourthPartyIntegration & { sourceDomain: string })[]>);

  // Sort vendors by product count (descending)
  const sortedVendors = Object.entries(vendorGroups).sort(([, a], [, b]) => {
    const productsA = [...new Set(a.flatMap(i => i.products))].length;
    const productsB = [...new Set(b.flatMap(i => i.products))].length;
    return productsB - productsA;
  });

  const toggleVendorExpanded = (vendor: string) => {
    const newExpanded = new Set(expandedVendors);
    if (newExpanded.has(vendor)) {
      newExpanded.delete(vendor);
    } else {
      newExpanded.add(vendor);
    }
    setExpandedVendors(newExpanded);
  };

  if (allIntegrations.length === 0) {
    return (
      <Card>
        <CardContent className="text-center py-8">
          <div className="text-gray-500">
            No fourth-party integrations detected for active domains.
          </div>
        </CardContent>
      </Card>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header with toggle */}
      <div className="flex items-center justify-between">
        <h2 className="text-xl font-semibold">Fourth Parties for {integrations[0]?.domain || 'domains'}</h2>
        <div className="flex items-center space-x-4">
          <div className="flex items-center space-x-2">
            <input
              type="radio"
              id="view-vendor"
              name="viewMode"
              checked={viewMode === 'vendor'}
              onChange={() => setViewMode('vendor')}
              className="text-blue-600"
            />
            <label htmlFor="view-vendor" className="text-sm font-medium">View by 4th party</label>
          </div>
          <div className="flex items-center space-x-2">
            <input
              type="radio"
              id="view-category"
              name="viewMode"
              checked={viewMode === 'category'}
              onChange={() => setViewMode('category')}
              className="text-blue-600"
            />
            <label htmlFor="view-category" className="text-sm font-medium">View by category</label>
          </div>
        </div>
      </div>

      {/* Vendor List */}
      <Card>
        <CardContent className="p-0">
          <div className="divide-y divide-gray-100">
            {/* Header Row */}
            <div className="grid grid-cols-12 gap-4 p-4 bg-gray-50 text-sm font-medium text-gray-600">
              <div className="col-span-5">4th party vendor</div>
              <div className="col-span-2 text-center">Score</div>
              <div className="col-span-2 text-center flex items-center justify-center">
                <Package className="h-4 w-4 mr-1" />
                # of products
              </div>
              <div className="col-span-3"></div>
            </div>

            {/* Vendor Rows */}
            {sortedVendors.map(([vendor, integrations]) => {
              const primaryIntegration = integrations[0];
              const uniqueProducts = [...new Set(integrations.flatMap(i => i.products))];
              const productCount = uniqueProducts.length;
              const vendorDomain = getVendorDomain(vendor);
              const isExpanded = expandedVendors.has(vendor);
              
              return (
                <div key={vendor} className="hover:bg-gray-50 transition-colors">
                  {/* Main Vendor Row */}
                  <div className="grid grid-cols-12 gap-4 p-4 items-center">
                    {/* Vendor Info */}
                    <div className="col-span-5 flex items-center space-x-3">
                      <div className="text-2xl">{getVendorIcon(vendor)}</div>
                      <div>
                        <div className="font-medium text-gray-900">{vendor}</div>
                        <div className="text-sm text-gray-500 flex items-center">
                          <Globe className="h-3 w-3 mr-1" />
                          {vendorDomain}
                        </div>
                      </div>
                    </div>

                    {/* Score (Placeholder) */}
                    <div className="col-span-2 text-center">
                      <div className="inline-flex items-center px-2 py-1 rounded-full text-sm bg-gray-100 text-gray-600">
                        <Shield className="h-3 w-3 mr-1" />
                        N/A
                      </div>
                    </div>

                    {/* Product Count */}
                    <div className="col-span-2 text-center">
                      <span className="text-lg font-semibold">{productCount}</span>
                    </div>

                    {/* Actions */}
                    <div className="col-span-3 flex items-center justify-end space-x-2">
                      <Badge className={getCategoryColor(primaryIntegration.category)}>
                        {primaryIntegration.category}
                      </Badge>
                      <button
                        onClick={() => toggleVendorExpanded(vendor)}
                        className="p-1 rounded hover:bg-gray-200 transition-colors"
                      >
                        <ChevronRight 
                          className={`h-4 w-4 transition-transform ${isExpanded ? 'rotate-90' : ''}`} 
                        />
                      </button>
                    </div>
                  </div>

                  {/* Expanded Product Details */}
                  {isExpanded && (
                    <div className="px-4 pb-4 border-t border-gray-100 bg-gray-50">
                      <div className="mt-3 space-y-3">
                        {/* Products List */}
                        <div>
                          <h4 className="text-sm font-medium text-gray-700 mb-2">Products Used:</h4>
                          <div className="flex flex-wrap gap-2">
                            {uniqueProducts.map((product, index) => (
                              <Badge key={index} variant="outline" className="text-xs">
                                {product}
                              </Badge>
                            ))}
                          </div>
                        </div>

                        {/* Detection Details */}
                        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs">
                          <div>
                            <span className="font-medium text-gray-600">Detection Method:</span>
                            <div className="text-gray-800">{primaryIntegration.detection_method.replace('_', ' ')}</div>
                          </div>
                          <div>
                            <span className="font-medium text-gray-600">Confidence:</span>
                            <div className="text-gray-800">{primaryIntegration.confidence}</div>
                          </div>
                          {primaryIntegration.risk_level && (
                            <div>
                              <span className="font-medium text-gray-600">Risk Level:</span>
                              <div className="text-gray-800">{primaryIntegration.risk_level}</div>
                            </div>
                          )}
                        </div>

                        {/* Privacy Implications */}
                        {primaryIntegration.privacy_implications && (
                          <div className="bg-orange-50 border border-orange-200 rounded-lg p-3">
                            <div className="text-xs font-medium text-orange-800 mb-1">Privacy Notice:</div>
                            <div className="text-xs text-orange-700">{primaryIntegration.privacy_implications}</div>
                          </div>
                        )}

                        {/* Source Domains */}
                        <div>
                          <span className="text-xs font-medium text-gray-600">Detected on domains:</span>
                          <div className="flex flex-wrap gap-1 mt-1">
                            {[...new Set(integrations.map(i => i.sourceDomain))].map(domain => (
                              <Badge key={domain} variant="outline" className="text-xs">
                                {domain}
                              </Badge>
                            ))}
                          </div>
                        </div>
                      </div>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </CardContent>
      </Card>

      {/* Summary Stats */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium">Total Vendors</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{Object.keys(vendorGroups).length}</div>
          </CardContent>
        </Card>
        
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium">Total Products</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {[...new Set(allIntegrations.flatMap(i => i.products))].length}
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium">High Risk Vendors</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-red-600">
              {Object.values(vendorGroups).filter(integrations => 
                integrations.some(i => i.risk_level === 'HIGH')
              ).length}
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium">Categories</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {[...new Set(allIntegrations.map(i => i.category))].length}
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
} 