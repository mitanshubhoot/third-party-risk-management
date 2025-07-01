# Subdomain Scanner

A powerful web-based tool for comprehensive domain security analysis and subdomain enumeration. This tool performs 100+ security checks across various categories including Network Security, Application Security, DNS Health, and more.

## Features

- 🔍 Subdomain Enumeration from multiple sources:
  - Subfinder
  - crt.sh
  - AlienVault OTX
- 🛡️ Comprehensive Security Checks:
  - SSL/TLS Analysis
  - DNS Health
  - Network Security
  - Application Security
  - Port Scanning
  - WordPress Security (if applicable)
  - Malicious Activity Detection
- 📊 Detailed Security Reports
- 🌐 Modern Web Interface
- ⚡ Real-time Scanning Updates

## Prerequisites

Before you begin, ensure you have the following installed:
- [Node.js](https://nodejs.org/) (v18.0.0 or higher)
- [npm](https://www.npmjs.com/) (v8.0.0 or higher)
- Modern web browser (Chrome, Firefox, Safari, or Edge)

## Installation

1. Clone the repository:
   ```bash
   git clone <your-repo-url>
   cd subdomain-scanner
   ```

2. Install dependencies:
   ```bash
   npm install
   ```

## Running the Application

1. Start the development server:
   ```bash
   npm run dev
   ```
   By default, the server will try to run on port 3000. If that port is in use, you can specify a different port:
   ```bash
   npm run dev -- -p 3002
   ```

2. Open your browser and navigate to:
   - If using default port: [http://localhost:3000](http://localhost:3000)
   - If using custom port: http://localhost:[PORT]

## Usage

1. Enter a domain name in the input field (e.g., example.com)
2. Click "Scan" to start the security analysis
3. The tool will:
   - Enumerate subdomains
   - Perform security checks
   - Generate a comprehensive report
4. View results in the interactive dashboard

## Building for Production

To create a production build:

```bash
npm run build
npm run start
```

## Environment Variables

Create a `.env.local` file in the root directory with the following variables (if needed):
```env
# Add any required environment variables here
```

## Troubleshooting

Common issues and solutions:

1. **Port Already in Use**
   - Use a different port: `npm run dev -- -p [PORT]`

2. **Dependencies Issues**
   - Clear npm cache: `npm cache clean --force`
   - Delete node_modules: `rm -rf node_modules`
   - Reinstall dependencies: `npm install`

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

[Add your license information here]

## Security

For security issues, please contact [your contact information]
