'use client';

import { useState } from 'react';
import { useAuth } from '@/app/context/AuthContext';
import { API_ENDPOINTS, createAuthHeaders } from '@/app/lib/api';
import toast from 'react-hot-toast';

// API Response interfaces matching C# backend
interface AuditRule {
  ruleId: string;
  name: string;
  category: string;
  description: string;
}

interface ApiViolation {
  filePath: string;
  lineNumber: number;
  matchedText: string;
  violatedRule: AuditRule;
}

interface ApiScanSummary {
  filesScanned: number;
  violationsFound: number;
  violations: ApiViolation[];
  reportId: string | null;
}

// UI Display interfaces
interface DisplayViolation {
  filePath: string;
  lineNumber: number;
  matchedText: string;
  ruleName: string;
  category: string;
  description: string;
  ruleId: string;
}

export default function ScanPage() {
  const { user } = useAuth();
  const [path, setPath] = useState('');
  const [scanType, setScanType] = useState<'local' | 'git'>('local');
  const [gitUrl, setGitUrl] = useState('');
  const [gitBranch, setGitBranch] = useState('');
  const [gitToken, setGitToken] = useState('');
  const [isScanning, setIsScanning] = useState(false);
  const [scanResult, setScanResult] = useState<ApiScanSummary | null>(null);
  const [violations, setViolations] = useState<DisplayViolation[]>([]);
  const [showResults, setShowResults] = useState(false);

  // Transform API violations to display format
  const transformViolations = (apiViolations: ApiViolation[]): DisplayViolation[] => {
    return apiViolations.map(v => ({
      filePath: v.filePath,
      lineNumber: v.lineNumber,
      matchedText: v.matchedText,
      ruleName: v.violatedRule.name,
      category: v.violatedRule.category,
      description: v.violatedRule.description,
      ruleId: v.violatedRule.ruleId,
    }));
  };

  // Calculate category breakdown
  const getCategoryBreakdown = (apiViolations: ApiViolation[]) => {
    const breakdown: { [key: string]: number } = {};
    apiViolations.forEach(v => {
      const category = v.violatedRule.category;
      breakdown[category] = (breakdown[category] || 0) + 1;
    });
    return breakdown;
  };

  const handleScan = async (e: React.FormEvent) => {
    e.preventDefault();
    
    if (!path.trim()) {
      toast.error('Please enter a path to scan');
      return;
    }

    setIsScanning(true);
    setShowResults(false);
    setScanResult(null);
    setViolations([]);
    
    try {
      console.log('Starting scan for path:', path.trim());
      console.log('API Endpoint:', API_ENDPOINTS.SCAN);
      
      const response = await fetch(API_ENDPOINTS.SCAN, {
        method: 'POST',
        headers: createAuthHeaders(user?.token),
        body: JSON.stringify({ path: path.trim() }),
      });

      console.log('Response status:', response.status);
      console.log('Response ok:', response.ok);

      const data: ApiScanSummary = await response.json();
      console.log('Response data:', data);

      if (response.ok) {
        console.log('Scan successful, setting results...');
        setScanResult(data);
        
        // Transform and set violations from the scan result
        if (data.violations && data.violations.length > 0) {
          console.log('Transforming violations:', data.violations.length);
          const transformedViolations = transformViolations(data.violations);
          setViolations(transformedViolations);
          console.log('Violations set:', transformedViolations.length);
        } else {
          console.log('No violations found');
        }
        
        setShowResults(true);
        toast.success(`Scan completed! Found ${data.violationsFound} violations in ${data.filesScanned} files`);
      } else {
        console.error('Scan failed:', data);
        toast.error((data as any).error || 'Scan failed');
      }
    } catch (error) {
      console.error('Scan error:', error);
      if (error instanceof TypeError && error.message.includes('fetch')) {
        toast.error('Cannot connect to API server. Make sure the backend is running on https://localhost:7120');
      } else {
        toast.error('An error occurred during the scan');
      }
    } finally {
      console.log('Setting isScanning to false');
      setIsScanning(false);
    }
  };

  const handleGitScan = async (e: React.FormEvent) => {
    e.preventDefault();
    
    if (!gitUrl.trim()) {
      toast.error('Please enter a repository URL');
      return;
    }

    setIsScanning(true);
    setShowResults(false);
    setScanResult(null);
    setViolations([]);
    
    try {
      console.log('Starting git scan for:', gitUrl);
      
      const response = await fetch(API_ENDPOINTS.SCAN_GIT, {
        method: 'POST',
        headers: createAuthHeaders(user?.token),
        body: JSON.stringify({ 
          repositoryUrl: gitUrl.trim(),
          branch: gitBranch.trim() || undefined,
          accessToken: gitToken.trim() || undefined
        }),
      });

      const data: ApiScanSummary = await response.json();

      if (response.ok) {
        setScanResult(data);
        
        if (data.violations && data.violations.length > 0) {
          const transformedViolations = transformViolations(data.violations);
          setViolations(transformedViolations);
        }
        
        setShowResults(true);
        toast.success(`Scan completed! Found ${data.violationsFound} violations`);
      } else {
        toast.error((data as any).error || 'Scan failed');
      }
    } catch (error) {
      console.error('Scan error:', error);
      toast.error('An error occurred during the scan');
    } finally {
      setIsScanning(false);
    }
  };

  const getCategoryColor = (category: string) => {
    const colors: { [key: string]: string } = {
      'GDPR': 'bg-blue-500/10 text-blue-400 border-blue-500/20',
      'HIPAA': 'bg-purple-500/10 text-purple-400 border-purple-500/20',
      'Security': 'bg-red-500/10 text-red-400 border-red-500/20',
      'PCI-DSS': 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20',
      'Compliance': 'bg-amber-500/10 text-amber-400 border-amber-500/20',
    };
    return colors[category] || 'bg-slate-700/50 text-slate-300 border-slate-600';
  };

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-lg">
        <h1 className="text-3xl font-bold text-white mb-2">
          🔍 Security Compliance Scanner
        </h1>
        <p className="text-slate-400">
          Scan your codebase for security compliance violations and best practice issues
        </p>
      </div>

      {/* Scan Form */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-8 shadow-lg">
        {/* Tabs */}
        <div className="flex space-x-4 mb-6 border-b border-slate-800">
          <button
            onClick={() => setScanType('local')}
            className={`pb-2 px-4 font-medium transition-colors ${
              scanType === 'local'
                ? 'text-blue-500 border-b-2 border-blue-500'
                : 'text-slate-400 hover:text-white'
            }`}
          >
            Local Scan
          </button>
          <button
            onClick={() => setScanType('git')}
            className={`pb-2 px-4 font-medium transition-colors ${
              scanType === 'git'
                ? 'text-blue-500 border-b-2 border-blue-500'
                : 'text-slate-400 hover:text-white'
            }`}
          >
            Git Repository
          </button>
        </div>

        {scanType === 'local' ? (
          <form onSubmit={handleScan} className="space-y-6">
            <div>
              <label
                htmlFor="path"
                className="block text-sm font-medium text-slate-300 mb-2"
              >
                Directory or File Path
              </label>
              <div className="flex gap-4">
                <input
                  type="text"
                  id="path"
                  value={path}
                  onChange={(e) => setPath(e.target.value)}
                  placeholder="e.g., C:\Projects\MyApp or /home/user/project"
                  className="flex-1 rounded-lg border border-slate-700 bg-slate-800 px-4 py-3 text-white placeholder-slate-500 focus:border-blue-500 focus:ring-2 focus:ring-blue-500 focus:outline-none transition-all"
                  disabled={isScanning}
                />
                <button
                  type="submit"
                  disabled={isScanning}
                  className="px-8 py-3 bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-700 hover:to-indigo-700 disabled:from-slate-700 disabled:to-slate-800 disabled:text-slate-500 text-white font-semibold rounded-lg shadow-lg hover:shadow-blue-500/25 transition-all disabled:cursor-not-allowed flex items-center gap-2"
                >
                  {isScanning ? (
                    <>
                      <div className="animate-spin h-5 w-5 border-2 border-white border-t-transparent rounded-full"></div>
                      Scanning...
                    </>
                  ) : (
                    <>
                      <span>🔍</span>
                      Start Scan
                    </>
                  )}
                </button>
              </div>
              <p className="mt-2 text-sm text-slate-500">
                Enter the full path to the directory or file you want to scan
              </p>
            </div>
          </form>
        ) : (
          <form onSubmit={handleGitScan} className="space-y-6">
            <div className="grid grid-cols-1 gap-6">
              <div>
                <label
                  htmlFor="gitUrl"
                  className="block text-sm font-medium text-slate-300 mb-2"
                >
                  Repository URL
                </label>
                <input
                  type="text"
                  id="gitUrl"
                  value={gitUrl}
                  onChange={(e) => setGitUrl(e.target.value)}
                  placeholder="https://github.com/username/repo.git"
                  className="w-full rounded-lg border border-slate-700 bg-slate-800 px-4 py-3 text-white placeholder-slate-500 focus:border-blue-500 focus:ring-2 focus:ring-blue-500 focus:outline-none transition-all"
                  disabled={isScanning}
                  required
                />
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div>
                  <label
                    htmlFor="gitBranch"
                    className="block text-sm font-medium text-slate-300 mb-2"
                  >
                    Branch (Optional)
                  </label>
                  <input
                    type="text"
                    id="gitBranch"
                    value={gitBranch}
                    onChange={(e) => setGitBranch(e.target.value)}
                    placeholder="main"
                    className="w-full rounded-lg border border-slate-700 bg-slate-800 px-4 py-3 text-white placeholder-slate-500 focus:border-blue-500 focus:ring-2 focus:ring-blue-500 focus:outline-none transition-all"
                    disabled={isScanning}
                  />
                </div>
                <div>
                  <label
                    htmlFor="gitToken"
                    className="block text-sm font-medium text-slate-300 mb-2"
                  >
                    Access Token (Optional)
                  </label>
                  <input
                    type="password"
                    id="gitToken"
                    value={gitToken}
                    onChange={(e) => setGitToken(e.target.value)}
                    placeholder="ghp_..."
                    className="w-full rounded-lg border border-slate-700 bg-slate-800 px-4 py-3 text-white placeholder-slate-500 focus:border-blue-500 focus:ring-2 focus:ring-blue-500 focus:outline-none transition-all"
                    disabled={isScanning}
                  />
                </div>
              </div>

              <div className="flex justify-end">
                <button
                  type="submit"
                  disabled={isScanning}
                  className="px-8 py-3 bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-700 hover:to-indigo-700 disabled:from-slate-700 disabled:to-slate-800 disabled:text-slate-500 text-white font-semibold rounded-lg shadow-lg hover:shadow-blue-500/25 transition-all disabled:cursor-not-allowed flex items-center gap-2"
                >
                  {isScanning ? (
                    <>
                      <div className="animate-spin h-5 w-5 border-2 border-white border-t-transparent rounded-full"></div>
                      Cloning & Scanning...
                    </>
                  ) : (
                    <>
                      <span>🔍</span>
                      Start Git Scan
                    </>
                  )}
                </button>
              </div>
            </div>
          </form>
        )}
      </div>

      {/* Scanning Progress */}
      {isScanning && (
        <div className="bg-blue-900/20 border border-blue-800 rounded-xl p-6">
          <div className="flex items-center gap-4">
            <div className="animate-spin h-8 w-8 border-4 border-blue-500 border-t-transparent rounded-full"></div>
            <div>
              <h3 className="font-semibold text-blue-100">
                Scanning in progress...
              </h3>
              <p className="text-sm text-blue-300">
                Analyzing your codebase for security compliance issues
              </p>
            </div>
          </div>
        </div>
      )}

      {/* Scan Results */}
      {showResults && scanResult && (
        <div className="space-y-6">
          {/* Summary Cards */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-lg border-l-4 border-l-blue-500">
              <div className="text-blue-500 text-3xl mb-2">📁</div>
              <p className="text-slate-400 text-sm">Files Scanned</p>
              <p className="text-3xl font-bold text-white">
                {scanResult.filesScanned}
              </p>
            </div>
            
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-lg border-l-4 border-l-red-500">
              <div className="text-red-500 text-3xl mb-2">⚠️</div>
              <p className="text-slate-400 text-sm">Violations Found</p>
              <p className="text-3xl font-bold text-white">
                {scanResult.violationsFound}
              </p>
            </div>
            
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-lg border-l-4 border-l-purple-500">
              <div className="text-purple-500 text-3xl mb-2">🏷️</div>
              <p className="text-slate-400 text-sm">Categories</p>
              <p className="text-3xl font-bold text-white">
                {Object.keys(getCategoryBreakdown(scanResult.violations)).length}
              </p>
            </div>
          </div>

          {/* Report ID */}
          {scanResult.reportId && (
            <div className="bg-emerald-900/20 border border-emerald-800 rounded-xl p-4">
              <div className="flex items-center gap-3">
                <span className="text-2xl">✅</span>
                <div className="flex-1">
                  <p className="font-semibold text-emerald-100">
                    Report Saved
                  </p>
                  <p className="text-sm text-emerald-300 font-mono">
                    Report ID: {scanResult.reportId}
                  </p>
                </div>
              </div>
            </div>
          )}

          {/* Categories Breakdown */}
          {scanResult.violations.length > 0 && (
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-lg">
              <h2 className="text-xl font-bold text-white mb-4">
                Violations by Category
              </h2>
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                {Object.entries(getCategoryBreakdown(scanResult.violations)).map(([category, count]) => (
                  <div
                    key={category}
                    className="flex items-center justify-between p-4 bg-slate-800 rounded-lg border border-slate-700"
                  >
                    <span className="font-medium text-slate-200">
                      {category}
                    </span>
                    <span className="px-3 py-1 bg-red-500/10 text-red-400 border border-red-500/20 rounded-full text-sm font-semibold">
                      {count as number}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Violations Table */}
          {violations.length > 0 && (
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-lg">
              <h2 className="text-xl font-bold text-white mb-4">
                Detailed Violations ({violations.length})
              </h2>
              <div className="overflow-x-auto">
                <table className="w-full">
                  <thead>
                    <tr className="border-b border-slate-800">
                      <th className="text-left py-3 px-4 text-sm font-semibold text-slate-300">
                        File Path
                      </th>
                      <th className="text-left py-3 px-4 text-sm font-semibold text-slate-300">
                        Line
                      </th>
                      <th className="text-left py-3 px-4 text-sm font-semibold text-slate-300">
                        Rule Name
                      </th>
                      <th className="text-left py-3 px-4 text-sm font-semibold text-slate-300">
                        Category
                      </th>
                      <th className="text-left py-3 px-4 text-sm font-semibold text-slate-300">
                        Matched Text
                      </th>
                      <th className="text-left py-3 px-4 text-sm font-semibold text-slate-300">
                        Description
                      </th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800">
                    {violations.map((violation, index) => (
                      <tr
                        key={index}
                        className="hover:bg-slate-800/50 transition-colors"
                      >
                        <td className="py-3 px-4 text-xs text-slate-300 font-mono">
                          {violation.filePath}
                        </td>
                        <td className="py-3 px-4 text-sm text-slate-400 font-mono">
                          {violation.lineNumber}
                        </td>
                        <td className="py-3 px-4 text-sm text-white font-semibold">
                          {violation.ruleName}
                        </td>
                        <td className="py-3 px-4 text-sm">
                          <span className={`px-2 py-1 rounded border text-xs font-medium ${getCategoryColor(violation.category)}`}>
                            {violation.category}
                          </span>
                        </td>
                        <td className="py-3 px-4 text-xs text-slate-300 font-mono max-w-xs truncate">
                          {violation.matchedText}
                        </td>
                        <td className="py-3 px-4 text-sm text-slate-400 max-w-md">
                          {violation.description}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Empty State */}
      {!showResults && !isScanning && (
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-12 text-center">
          <div className="text-6xl mb-4">🔍</div>
          <h3 className="text-xl font-semibold text-white mb-2">
            Ready to Scan
          </h3>
          <p className="text-slate-400">
            Enter a local path or Git repository URL above to start scanning
          </p>
        </div>
      )}
    </div>
  );
}
