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
- Node.js 20.18.1 or higher (Required)
- npm 8.0.0 or higher
- Ruby (for WhatWeb component)
- Modern web browser (Chrome, Firefox, Safari, or Edge)

## 🚀 Detailed Installation Steps

1. **Install Node Version Manager (nvm)**
   ```bash
   curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.7/install.sh | bash
   ```
   After installation, close and reopen your terminal, or run:
   ```bash
   export NVM_DIR="$HOME/.nvm"
   [ -s "$NVM_DIR/nvm.sh" ] && \. "$NVM_DIR/nvm.sh"
   ```

2. **Install the Required Node.js Version**
   ```bash
   nvm install 20
   nvm use 20
   ```

3. **Clone the Repository**
   ```bash
   git clone https://github.com/mitanshubhoot/third-party-risk-management.git
   cd third-party-risk-management
   ```

4. **Install Dependencies**
   ```bash
   # Navigate to the subdomain scanner directory
   cd subdomain-scanner
   
   # Clean npm cache and install dependencies
   npm cache clean --force
   npm install
   ```

5. **Start the Development Server**
   ```bash
   npm run dev
   ```
   The application will be available at http://localhost:3000

### Troubleshooting Common Issues

1. **"Unsupported engine" Warning**
   If you see this warning, it means you're using an incompatible Node.js version. Follow steps 1-2 above to install the correct version.

2. **Port 3000 Already in Use**
   Start the server on a different port:
   ```bash
   npm run dev -- -p 3001
   ```

3. **Dependencies Issues**
   Try cleaning and reinstalling:
   ```bash
   npm cache clean --force
   rm -rf node_modules package-lock.json
   npm install
   ```

## 💻 Usage

1. Enter the target domain or company identifier
2. Select the type of assessment you want to perform
3. Review the comprehensive security analysis results

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