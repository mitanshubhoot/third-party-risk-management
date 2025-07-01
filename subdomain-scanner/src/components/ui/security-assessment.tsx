// import { Badge } from "./badge";
// import { Card } from "./card";

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

interface SecurityAssessmentProps {
  assessment: SecurityAssessment;
}

export function SecurityAssessment({ assessment }: SecurityAssessmentProps) {
  // Sort checks by status priority: fail > warning > info > pass
  const getStatusPriority = (status: string) => {
    switch (status) {
      case 'fail': return 1;
      case 'warning': return 2;
      case 'info': return 3;
      case 'pass': return 4;
      default: return 5;
    }
  };

  const sortedChecks = [...assessment.checks].sort((a, b) => {
    const priorityA = getStatusPriority(a.status);
    const priorityB = getStatusPriority(b.status);
    
    // If status priority is the same, sort by severity (critical > high > medium > low)
    if (priorityA === priorityB) {
      const severityOrder = { critical: 1, high: 2, medium: 3, low: 4 };
      return (severityOrder[a.severity as keyof typeof severityOrder] || 5) - 
             (severityOrder[b.severity as keyof typeof severityOrder] || 5);
    }
    
    return priorityA - priorityB;
  });

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'pass':
        return 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-300';
      case 'fail':
        return 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-300';
      case 'warning':
        return 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-300';
      default:
        return 'bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-300';
    }
  };

  const getGradeColor = (grade: string) => {
    switch (grade) {
      case 'A':
        return 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-300 border-green-200';
      case 'B':
        return 'bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-300 border-blue-200';
      case 'C':
        return 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-300 border-yellow-200';
      case 'D':
        return 'bg-orange-100 text-orange-800 dark:bg-orange-900 dark:text-orange-300 border-orange-200';
      case 'F':
        return 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-300 border-red-200';
      default:
        return 'bg-gray-100 text-gray-800 dark:bg-gray-800 dark:text-gray-200 border-gray-200';
    }
  };

  return (
    <div className="space-y-8 p-1">
      {/* Modern Risk Score Dashboard */}
      {assessment.riskScore && (
        <div className="relative overflow-hidden rounded-2xl bg-gradient-to-br from-slate-50 via-blue-50 to-indigo-50 dark:from-slate-900 dark:via-blue-950 dark:to-indigo-950 border border-blue-100 dark:border-blue-800">
          {/* Background Pattern */}
          <div className="absolute inset-0 bg-grid-pattern opacity-5"></div>
          
          <div className="relative p-8">
            {/* Header with Score */}
            <div className="flex items-center justify-between mb-8">
              <div className="flex items-center gap-3">
                <div className="p-3 bg-blue-100 dark:bg-blue-900 rounded-full">
                  <svg className="w-6 h-6 text-blue-600 dark:text-blue-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                  </svg>
                </div>
                <div>
                  <h3 className="text-xl font-bold text-gray-900 dark:text-white">Security Risk Score</h3>
                  <p className="text-sm text-gray-600 dark:text-gray-400">Comprehensive security assessment</p>
                </div>
              </div>
              
              {/* Grade and Score Display */}
              <div className="flex items-center gap-4">
                <div className={`relative px-6 py-4 rounded-2xl shadow-lg ${getGradeColor(assessment.riskScore.letterGrade)}`}>
                  <div className="text-center">
                    <div className="text-3xl font-black">{assessment.riskScore.letterGrade}</div>
                    <div className="text-xs font-medium opacity-80">GRADE</div>
                  </div>
                </div>
                <div className="text-right">
                  <div className="text-4xl font-black bg-gradient-to-r from-blue-600 to-indigo-600 bg-clip-text text-transparent dark:from-blue-400 dark:to-indigo-400">
                    {assessment.riskScore.overallScore}
                  </div>
                  <div className="text-sm font-medium text-gray-500 dark:text-gray-400">out of 950</div>
                </div>
              </div>
            </div>
            
            {/* Progress Bar */}
            <div className="mb-8">
              <div className="flex justify-between text-sm font-medium text-gray-600 dark:text-gray-400 mb-2">
                <span>Security Score Progress</span>
                <span>{Math.round((assessment.riskScore.overallScore / 950) * 100)}%</span>
              </div>
              <div className="h-3 bg-gray-200 dark:bg-gray-700 rounded-full overflow-hidden">
                <div 
                  className="h-full bg-gradient-to-r from-blue-500 to-indigo-500 rounded-full transition-all duration-1000 ease-out"
                  style={{ width: `${(assessment.riskScore.overallScore / 950) * 100}%` }}
                ></div>
              </div>
            </div>
            
            {/* Stats Grid */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              <div className="bg-white/60 dark:bg-gray-800/60 backdrop-blur-sm rounded-xl p-4 border border-white/20 dark:border-gray-700/20">
                <div className="flex items-center gap-3">
                  <div className="p-2 bg-green-100 dark:bg-green-900 rounded-lg">
                    <svg className="w-4 h-4 text-green-600 dark:text-green-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                    </svg>
                  </div>
                  <div>
                    <div className="text-2xl font-bold text-green-600 dark:text-green-400">
                      {assessment.riskScore.passedChecks}
                    </div>
                    <div className="text-xs font-medium text-gray-600 dark:text-gray-400">Passed</div>
                  </div>
                </div>
              </div>
              
              <div className="bg-white/60 dark:bg-gray-800/60 backdrop-blur-sm rounded-xl p-4 border border-white/20 dark:border-gray-700/20">
                <div className="flex items-center gap-3">
                  <div className="p-2 bg-red-100 dark:bg-red-900 rounded-lg">
                    <svg className="w-4 h-4 text-red-600 dark:text-red-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                    </svg>
                  </div>
                  <div>
                    <div className="text-2xl font-bold text-red-600 dark:text-red-400">
                      {assessment.riskScore.failedChecks}
                    </div>
                    <div className="text-xs font-medium text-gray-600 dark:text-gray-400">Failed</div>
                  </div>
                </div>
              </div>
              
              <div className="bg-white/60 dark:bg-gray-800/60 backdrop-blur-sm rounded-xl p-4 border border-white/20 dark:border-gray-700/20">
                <div className="flex items-center gap-3">
                  <div className="p-2 bg-yellow-100 dark:bg-yellow-900 rounded-lg">
                    <svg className="w-4 h-4 text-yellow-600 dark:text-yellow-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.732-.833-2.5 0L4.268 15.5c-.77.833.192 2.5 1.732 2.5z" />
                    </svg>
                  </div>
                  <div>
                    <div className="text-2xl font-bold text-yellow-600 dark:text-yellow-400">
                      {assessment.riskScore.warningChecks}
                    </div>
                    <div className="text-xs font-medium text-gray-600 dark:text-gray-400">Warnings</div>
                  </div>
                </div>
              </div>
              
              <div className="bg-white/60 dark:bg-gray-800/60 backdrop-blur-sm rounded-xl p-4 border border-white/20 dark:border-gray-700/20">
                <div className="flex items-center gap-3">
                  <div className={`p-2 rounded-lg ${
                    assessment.riskScore.riskLevel === 'LOW' ? 'bg-green-100 dark:bg-green-900' :
                    assessment.riskScore.riskLevel === 'MEDIUM' ? 'bg-yellow-100 dark:bg-yellow-900' :
                    assessment.riskScore.riskLevel === 'HIGH' ? 'bg-orange-100 dark:bg-orange-900' :
                    'bg-red-100 dark:bg-red-900'
                  }`}>
                    <svg className={`w-4 h-4 ${
                      assessment.riskScore.riskLevel === 'LOW' ? 'text-green-600 dark:text-green-400' :
                      assessment.riskScore.riskLevel === 'MEDIUM' ? 'text-yellow-600 dark:text-yellow-400' :
                      assessment.riskScore.riskLevel === 'HIGH' ? 'text-orange-600 dark:text-orange-400' :
                      'text-red-600 dark:text-red-400'
                    }`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
                    </svg>
                  </div>
                  <div>
                    <div className={`text-lg font-bold ${
                      assessment.riskScore.riskLevel === 'LOW' ? 'text-green-600 dark:text-green-400' :
                      assessment.riskScore.riskLevel === 'MEDIUM' ? 'text-yellow-600 dark:text-yellow-400' :
                      assessment.riskScore.riskLevel === 'HIGH' ? 'text-orange-600 dark:text-orange-400' :
                      'text-red-600 dark:text-red-400'
                    }`}>
                      {assessment.riskScore.riskLevel}
                    </div>
                    <div className="text-xs font-medium text-gray-600 dark:text-gray-400">Risk Level</div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Modern Category Breakdown */}
      {assessment.riskScore && (
        <div className="bg-white dark:bg-gray-900 rounded-2xl border border-gray-200 dark:border-gray-700 overflow-hidden">
          <div className="p-6 bg-gradient-to-r from-gray-50 to-gray-100 dark:from-gray-800 dark:to-gray-900 border-b border-gray-200 dark:border-gray-700">
            <div className="flex items-center gap-3">
              <div className="p-2 bg-indigo-100 dark:bg-indigo-900 rounded-lg">
                <svg className="w-5 h-5 text-indigo-600 dark:text-indigo-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
                </svg>
              </div>
              <div>
                <h3 className="text-lg font-bold text-gray-900 dark:text-white">Risk Category Analysis</h3>
                <p className="text-sm text-gray-600 dark:text-gray-400">Detailed breakdown by security domain</p>
              </div>
            </div>
          </div>
          
          <div className="p-6">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {Object.entries(assessment.riskScore.categoryScores).map(([category, score]) => {
                const categoryData: Record<string, { name: string; icon: string; description: string }> = {
                  websiteSecurity: { 
                    name: 'Website Security', 
                    icon: 'M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9m-9 9a9 9 0 019-9',
                    description: 'HTTPS, HSTS, CSP, Security Headers'
                  },
                  encryption: { 
                    name: 'Encryption', 
                    icon: 'M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z',
                    description: 'SSL/TLS, Certificates, Cipher Strength'
                  },
                  ipReputation: { 
                    name: 'IP/Domain Reputation', 
                    icon: 'M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z',
                    description: 'Malware Detection, Blacklists, Reputation'
                  },
                  vulnerabilityManagement: { 
                    name: 'Vulnerability Management', 
                    icon: 'M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.732-.833-2.5 0L4.268 15.5c-.77.833.192 2.5 1.732 2.5z',
                    description: 'CVE Checks, Patch Management, Updates'
                  },
                  attackSurface: { 
                    name: 'Attack Surface', 
                    icon: 'M19.428 15.428a2 2 0 00-1.022-.547l-2.387-.477a6 6 0 00-3.86.517l-.318.158a6 6 0 01-3.86.517L6.05 15.21a2 2 0 00-1.806.547M8 4h8l-1 1v5.172a2 2 0 00.586 1.414l5 5c1.26 1.26.367 3.414-1.415 3.414H4.828c-1.782 0-2.674-2.154-1.414-3.414l5-5A2 2 0 009 10.172V5L8 4z',
                    description: 'Exposed Services, Cloud Storage, Takeovers'
                  },
                  networkSecurity: { 
                    name: 'Network Security', 
                    icon: 'M8.111 16.404a5.5 5.5 0 017.778 0M12 20h.01m-7.08-7.071c3.904-3.905 10.236-3.905 14.141 0M1.394 9.393c5.857-5.857 15.355-5.857 21.213 0',
                    description: 'Open Ports, Service Detection, Firewalls'
                  },
                  emailSecurity: { 
                    name: 'Email Security', 
                    icon: 'M3 8l7.89 4.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z',
                    description: 'SPF, DMARC, MX Records, Anti-Phishing'
                  },
                  dataLeakage: { 
                    name: 'Data Leakage', 
                    icon: 'M15 12a3 3 0 11-6 0 3 3 0 016 0z M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z',
                    description: 'Data Exposure, Leaks, Breach Detection'
                  },
                  dnsSecurity: { 
                    name: 'DNS Security', 
                    icon: 'M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2',
                    description: 'DNSSEC, CAA Records, DNS Configuration'
                  },
                  brandReputation: { 
                    name: 'Brand & Reputation', 
                    icon: 'M4.318 6.318a4.5 4.5 0 000 6.364L12 20.364l7.682-7.682a4.5 4.5 0 00-6.364-6.364L12 7.636l-1.318-1.318a4.5 4.5 0 00-6.364 0z',
                    description: 'Domain Expiration, Registrar Protection'
                  }
                };
                
                const data = categoryData[category];
                const getScoreColor = (score: number) => {
                  if (score >= 850) return { color: 'text-green-600 dark:text-green-400', bg: 'bg-green-50 dark:bg-green-900/20', border: 'border-green-200 dark:border-green-800' };
                  if (score >= 700) return { color: 'text-blue-600 dark:text-blue-400', bg: 'bg-blue-50 dark:bg-blue-900/20', border: 'border-blue-200 dark:border-blue-800' };
                  if (score >= 500) return { color: 'text-yellow-600 dark:text-yellow-400', bg: 'bg-yellow-50 dark:bg-yellow-900/20', border: 'border-yellow-200 dark:border-yellow-800' };
                  if (score >= 300) return { color: 'text-orange-600 dark:text-orange-400', bg: 'bg-orange-50 dark:bg-orange-900/20', border: 'border-orange-200 dark:border-orange-800' };
                  return { color: 'text-red-600 dark:text-red-400', bg: 'bg-red-50 dark:bg-red-900/20', border: 'border-red-200 dark:border-red-800' };
                };

                const colorScheme = getScoreColor(score);
                const percentage = (score / 950) * 100;

                return (
                  <div key={category} className={`p-4 rounded-xl border-2 ${colorScheme.bg} ${colorScheme.border} card-hover`}>
                    <div className="flex items-center justify-between mb-3">
                      <div className="flex items-center gap-3">
                        <div className={`p-2 rounded-lg ${colorScheme.bg}`}>
                          <svg className={`w-4 h-4 ${colorScheme.color}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d={data.icon} />
                          </svg>
                        </div>
                        <div>
                          <div className="font-semibold text-gray-900 dark:text-white text-sm">{data.name}</div>
                          <div className="text-xs text-gray-500 dark:text-gray-400">{data.description}</div>
                        </div>
                      </div>
                      <div className="text-right">
                        <div className={`text-xl font-bold ${colorScheme.color}`}>{score}</div>
                        <div className="text-xs text-gray-500 dark:text-gray-400">{percentage.toFixed(0)}%</div>
                      </div>
                    </div>
                    
                    {/* Progress bar */}
                    <div className="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-2">
                      <div 
                        className={`h-2 rounded-full transition-all duration-500 ease-out ${
                          score >= 850 ? 'bg-green-500' :
                          score >= 700 ? 'bg-blue-500' :
                          score >= 500 ? 'bg-yellow-500' :
                          score >= 300 ? 'bg-orange-500' : 'bg-red-500'
                        }`}
                        style={{ width: `${percentage}%` }}
                      ></div>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      )}

      {/* Modern Security Checks */}
      <div className="bg-white dark:bg-gray-900 rounded-2xl border border-gray-200 dark:border-gray-700 overflow-hidden">
        <div className="p-6 bg-gradient-to-r from-gray-50 to-gray-100 dark:from-gray-800 dark:to-gray-900 border-b border-gray-200 dark:border-gray-700">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="p-2 bg-purple-100 dark:bg-purple-900 rounded-lg">
                <svg className="w-5 h-5 text-purple-600 dark:text-purple-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
              </div>
              <div>
                <h3 className="text-lg font-bold text-gray-900 dark:text-white">Security Checks</h3>
                <p className="text-sm text-gray-600 dark:text-gray-400">Comprehensive security assessment for {assessment.domain}</p>
              </div>
            </div>
            
            {/* Summary badges */}
            <div className="flex gap-2">
              <div className="px-3 py-1 bg-green-100 dark:bg-green-900 text-green-700 dark:text-green-300 rounded-full text-xs font-medium">
                {sortedChecks.filter(c => c.status === 'pass').length} Passed
              </div>
              <div className="px-3 py-1 bg-red-100 dark:bg-red-900 text-red-700 dark:text-red-300 rounded-full text-xs font-medium">
                {sortedChecks.filter(c => c.status === 'fail').length} Failed
              </div>
              <div className="px-3 py-1 bg-yellow-100 dark:bg-yellow-900 text-yellow-700 dark:text-yellow-300 rounded-full text-xs font-medium">
                {sortedChecks.filter(c => c.status === 'warning').length} Warnings
              </div>
            </div>
          </div>
        </div>
        
        <div className="divide-y divide-gray-200 dark:divide-gray-700">
          {sortedChecks.map((check) => {
            const getCheckIcon = (status: string) => {
              switch (status) {
                case 'pass':
                  return (
                    <div className="p-2 bg-green-100 dark:bg-green-900 rounded-lg">
                      <svg className="w-4 h-4 text-green-600 dark:text-green-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                      </svg>
                    </div>
                  );
                case 'fail':
                  return (
                    <div className="p-2 bg-red-100 dark:bg-red-900 rounded-lg">
                      <svg className="w-4 h-4 text-red-600 dark:text-red-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                      </svg>
                    </div>
                  );
                case 'warning':
                  return (
                    <div className="p-2 bg-yellow-100 dark:bg-yellow-900 rounded-lg">
                      <svg className="w-4 h-4 text-yellow-600 dark:text-yellow-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.732-.833-2.5 0L4.268 15.5c-.77.833.192 2.5 1.732 2.5z" />
                      </svg>
                    </div>
                  );
                default:
                  return (
                    <div className="p-2 bg-blue-100 dark:bg-blue-900 rounded-lg">
                      <svg className="w-4 h-4 text-blue-600 dark:text-blue-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                      </svg>
                    </div>
                  );
              }
            };

            return (
              <div key={check.id} className="p-4 hover:bg-gray-50 dark:hover:bg-gray-800 transition-colors duration-150">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-3 flex-1">
                    {getCheckIcon(check.status)}
                    <div className="flex-1">
                      <div className="font-medium text-gray-900 dark:text-white text-sm">{check.name}</div>
                      <div className="text-xs text-gray-500 dark:text-gray-400 mt-1">{check.description}</div>
                      {check.details && (
                        <div className="text-xs text-gray-600 dark:text-gray-300 mt-2 p-2 bg-gray-50 dark:bg-gray-800 rounded-lg">{check.details}</div>
                      )}
                    </div>
                  </div>
                  <div className="flex items-center gap-3">
                    {check.severity && check.severity !== 'low' && (
                      <span className={`px-2 py-1 rounded-full text-xs font-medium ${
                        check.severity === 'critical' ? 'bg-red-100 dark:bg-red-900 text-red-700 dark:text-red-300' :
                        check.severity === 'high' ? 'bg-orange-100 dark:bg-orange-900 text-orange-700 dark:text-orange-300' :
                        check.severity === 'medium' ? 'bg-yellow-100 dark:bg-yellow-900 text-yellow-700 dark:text-yellow-300' :
                        'bg-blue-100 dark:bg-blue-900 text-blue-700 dark:text-blue-300'
                      }`}>
                        {check.severity.toUpperCase()}
                      </span>
                    )}
                    <span className={`px-3 py-1 rounded-full text-xs font-medium ${getStatusColor(check.status)}`}>
                      {check.status.toUpperCase()}
                    </span>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      <p className="text-xs text-gray-500 dark:text-gray-400">
        Last checked: {new Date(assessment.lastChecked).toLocaleString()}
      </p>
    </div>
  );
} 