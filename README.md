# Third-Party Risk Management System

A comprehensive security posture assessment platform that helps evaluate and monitor the security stance of organizations. This tool combines multiple security assessment capabilities including domain security analysis, infrastructure scanning, and security controls verification.

## 🛡️ Key Features

### 1. Security Posture Assessment
- 100+ Security Checks across multiple categories:
  - Network Security
  - Application Security
  - DNS Health
  - SSL/TLS Analysis
  - Infrastructure Security
  - Web Security Headers
  - Malware Detection
  - Security Controls
  - Compliance Status

### 2. Domain Security Analysis
- Comprehensive subdomain enumeration using multiple sources:
  - Subfinder
  - crt.sh
  - AlienVault OTX
- DNS health checking
- SSL/TLS certificate analysis
- Security headers verification

### 3. Infrastructure Analysis
- Port scanning and service detection
- Network security assessment
- Vulnerability identification
- Third-party integration scanning
- IP reputation checking

### 4. Security Controls Verification
- Security headers implementation
- Access control measures
- Authentication mechanisms
- Data protection practices
- Network security controls

### 5. Reporting and Analytics
- Detailed security assessment reports
- Risk scoring and prioritization
- Historical trend analysis
- Compliance status tracking
- Actionable recommendations

## 📋 Prerequisites

Before you begin, ensure you have the following installed:
- [Node.js](https://nodejs.org/) (v18.0.0 or higher)
- [npm](https://www.npmjs.com/) (v8.0.0 or higher)
- Modern web browser (Chrome, Firefox, Safari, or Edge)

## 🚀 Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/mitanshubhoot/third-party-risk-management.git
   cd third-party-risk-management
   ```

2. Install dependencies:
   ```bash
   npm install
   ```

## 💻 Usage

1. Start the application:
   ```bash
   cd subdomain-scanner
   npm install
   npm run dev
   ```
   The application will start on http://localhost:3000 by default.

2. Enter the target domain or company identifier
3. Select the type of assessment you want to perform
4. Review the comprehensive security analysis results

## 📊 Assessment Categories

1. **Network Security**
   - Port scanning
   - Service identification
   - Network vulnerability assessment
   - Firewall rule analysis

2. **Application Security**
   - Web application scanning
   - API security testing
   - Security headers analysis
   - Framework vulnerability checking

3. **DNS Health**
   - DNS record analysis
   - Domain configuration verification
   - DNS security extensions
   - Zone transfer testing

4. **Infrastructure Security**
   - Server security assessment
   - Cloud service configuration
   - Infrastructure vulnerability scanning
   - Security control verification

5. **Compliance & Standards**
   - Security control mapping
   - Best practice alignment
   - Regulatory requirement checking
   - Industry standard compliance

## 🔍 Security Checks

The system performs over 100 security checks including:
- SSL/TLS configuration
- Security header implementation
- DNS security measures
- Network security controls
- Application security testing
- Infrastructure vulnerability scanning
- Third-party service integration
- Access control verification
- Authentication mechanisms
- Data protection measures

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📝 License

[Add your license information here]

## 🔒 Security

For security issues, please contact [your contact information]

## 📚 Documentation

For detailed documentation about each component:
- [Security Checks Documentation](./SECURITY_CHECKS_ANALYSIS/README.md)
- [WhatWeb Scanner](./WhatWeb/README.md)
- [Subdomain Scanner](./subdomain-scanner/README.md) 
