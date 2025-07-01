# Domain Security Assessment Scanner

A comprehensive security assessment tool for domains that performs subdomain discovery and extensive security checks, built with Next.js and TypeScript.

## Features

### Subdomain Discovery
- **Subfinder integration**: Uses the powerful FOSS tool for subdomain enumeration
- **Certificate Transparency**: Queries crt.sh for certificate-based subdomain discovery
- **Multiple source aggregation**: Combines results from various sources for comprehensive coverage

### Security Assessment
- **13+ Security Checks**: Comprehensive security analysis including:
  - SSL/TLS Certificate validation and expiration
  - Security headers analysis (HSTS, CSP, X-Frame-Options, etc.)
  - Domain expiration monitoring with tiered warnings
  - SSL/TLS configuration and cipher suite analysis
  - DMARC and SPF record validation
  - Subdomain takeover vulnerability detection
  - HTTP to HTTPS redirect verification
  - DNS configuration checks (MX records)
  - SSL certificate revocation status

### Modern UI
- **Real-time scanning**: Live status updates during scan operations
- **Interactive security panel**: Sliding panel with detailed security assessment results
- **Color-coded results**: Visual indicators for security status (pass/fail/warning/info)
- **Severity levels**: Clear risk categorization (low/medium/high/critical)
- **Responsive design**: Built with Tailwind CSS and shadcn/ui components

## Tech Stack

- **Framework**: [Next.js](https://nextjs.org/) 15.3+ with React 19
- **Language**: [TypeScript](https://www.typescriptlang.org/) for type safety
- **Styling**: [Tailwind CSS](https://tailwindcss.com/) with custom design system
- **UI Components**: [shadcn/ui](https://ui.shadcn.com/) and [Radix UI](https://www.radix-ui.com/)
- **State Management**: [TanStack Query](https://tanstack.com/query/latest) for data fetching
- **Security Libraries**: 
  - `node-forge` for certificate analysis
  - `whois-json` for domain information
  - Native Node.js `tls` and `https` modules
- **Schema Validation**: [Zod](https://zod.dev/) for runtime type checking

## Prerequisites

- **Node.js** 18+ and npm
- **Go** (for Subfinder installation)

## Installation

1. **Install Subfinder** (required for subdomain discovery):
```bash
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
```

2. **Install project dependencies**:
```bash
cd subdomain-scanner
npm install
```

## Development

Run the development server:

```bash
cd subdomain-scanner
npm run dev
```

Open [http://localhost:3000](http://localhost:3000) to access the application.

## API Reference

### POST /api/scan
Performs comprehensive domain scanning and security assessment.

**Request Body:**
```json
{
  "domain": "example.com"
}
```

**Response:**
```json
{
  "success": true,
  "data": [
    {
      "domain": "subdomain.example.com",
      "source": "subfinder",
      "ip_address": "1.2.3.4",
      "is_active": true,
      "security_headers": { ... },
      "security_assessment": {
        "domain": "subdomain.example.com",
        "lastChecked": "2024-01-01T00:00:00Z",
        "overallRisk": "medium",
        "passedChecks": 8,
        "totalChecks": 13,
        "checks": [ ... ]
      }
    }
  ]
}
```

## Security Checks Performed

1. **SSL Certificate Validation** - Verifies certificate validity and hostname matching
2. **SSL Certificate Expiration** - Monitors certificate expiration with early warnings
3. **Security Headers** - Analyzes HSTS, CSP, X-Frame-Options, and other security headers
4. **Domain Expiration** - Checks domain registration expiration dates
5. **SSL/TLS Configuration** - Validates TLS versions and cipher suites
6. **DMARC Policy** - Email authentication policy validation
7. **SPF Records** - Sender Policy Framework validation
8. **HTTP to HTTPS Redirect** - Ensures proper security redirects
9. **DNS MX Records** - Mail exchange record configuration
10. **Subdomain Takeover** - Checks for vulnerable CNAME records
11. **SSL Certificate Revocation** - Validates certificate revocation status
12. **Weak TLS Ciphers** - Identifies weak encryption algorithms
13. **SSL/TLS Security Parameters** - Comprehensive TLS security analysis

## Project Structure

```
subdomain-scanner/
├── src/
│   ├── app/
│   │   ├── api/scan/          # API endpoints
│   │   ├── layout.tsx         # Root layout
│   │   └── page.tsx           # Main application
│   ├── components/ui/         # Reusable UI components
│   ├── lib/                   # Utility functions
│   └── types/                 # TypeScript type definitions
├── public/                    # Static assets
└── package.json              # Dependencies and scripts
```

## License

MIT License 