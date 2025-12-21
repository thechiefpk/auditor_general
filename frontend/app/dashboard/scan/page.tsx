'use client';

import { useEffect, useRef, useState } from 'react';
import { useAuth } from '@/app/context/AuthContext';
import { API_ENDPOINTS, createAuthHeaders } from '@/app/lib/api';
import toast from 'react-hot-toast';
import { useRouter } from 'next/navigation';

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
  const router = useRouter();
  const [path, setPath] = useState('');
  const [scanType, setScanType] = useState<'local' | 'git'>('local');
  const [gitUrl, setGitUrl] = useState('');
  const [gitBranch, setGitBranch] = useState('');
  const [gitToken, setGitToken] = useState('');
  const [isAdvanced, setIsAdvanced] = useState(false);
  const [isScanning, setIsScanning] = useState(false);
  const [progress, setProgress] = useState<{ status: string; stage: string; totalFiles: number; processedFiles: number; violationsFound: number; percentage: number; reportId?: string | null; error?: string | null } | null>(null);
  const pollTimer = useRef<NodeJS.Timeout | null>(null);
  const prevStatusRef = useRef<string>('');
  const [scanResult, setScanResult] = useState<ApiScanSummary | null>(null);
  const [violations, setViolations] = useState<DisplayViolation[]>([]);
  const [showResults, setShowResults] = useState(false);

  // Scan Timer
  const [startTime, setStartTime] = useState<number | null>(null);
  const [elapsedTime, setElapsedTime] = useState<string>('00:00');

  useEffect(() => {
    let interval: NodeJS.Timeout;
    if (isScanning && startTime) {
      interval = setInterval(() => {
        const now = Date.now();
        const diff = Math.floor((now - startTime) / 1000);
        const m = Math.floor(diff / 60).toString().padStart(2, '0');
        const s = (diff % 60).toString().padStart(2, '0');
        setElapsedTime(`${m}:${s}`);
      }, 1000);
    }
    return () => clearInterval(interval);
  }, [isScanning, startTime]);
  
  // Docker state
  const [isDockerRunning, setIsDockerRunning] = useState(false);

  // Check and start Docker on mount
  useEffect(() => {
    const checkAndStartDocker = async () => {
        try {
            const res = await fetch(API_ENDPOINTS.SYSTEM_DOCKER_STATUS);
            if (!res.ok) return;
            const data = await res.json();
            
            if (data.isRunning) {
                setIsDockerRunning(true);
            } else {
                setIsDockerRunning(false);
                // Silent start
                
                const startRes = await fetch(API_ENDPOINTS.SYSTEM_START_DOCKER, { method: 'POST' });
                if (startRes.ok) {
                    // Poll for status until running
                    const interval = setInterval(async () => {
                        try {
                            const pollRes = await fetch(API_ENDPOINTS.SYSTEM_DOCKER_STATUS);
                            const pollData = await pollRes.json();
                            if (pollData.isRunning) {
                                setIsDockerRunning(true);
                                clearInterval(interval);
                            }
                        } catch {
                            // ignore poll errors
                        }
                    }, 3000);
                }
            }
        } catch (e) {
            console.error("Failed to check docker status", e);
        }
    };

    checkAndStartDocker();
  }, []);

  // Dynamic storage key based on user
  const getJobStorageKey = () => user?.username ? `scanJobId_${user.username}` : 'currentScanJobId';

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

  const startPolling = (jobId: string) => {
    if (pollTimer.current) clearInterval(pollTimer.current);
    pollTimer.current = setInterval(async () => {
      try {
        const res = await fetch(API_ENDPOINTS.SCAN_PROGRESS(jobId), {
          headers: createAuthHeaders(user?.token),
        });
        
        // Handle unauthorized or not found - stop polling to prevent infinite loops
        if (res.status === 401 || res.status === 403) {
            clearInterval(pollTimer.current!);
            localStorage.removeItem(getJobStorageKey());
            setIsScanning(false);
            setStartTime(null);
            // Don't toast here to avoid spamming on page load if session is stale
            return;
        }
        
        if (res.status === 404) {
            clearInterval(pollTimer.current!);
            localStorage.removeItem(getJobStorageKey());
            setIsScanning(false);
            setStartTime(null);
            return;
        }

        if (!res.ok) return;
        const data = await res.json();
        const normalized = {
          status: data.status ?? data.Status,
          stage: data.stage ?? data.Stage,
          totalFiles: data.totalFiles ?? data.TotalFiles,
          processedFiles: data.processedFiles ?? data.ProcessedFiles,
          violationsFound: data.violationsFound ?? data.ViolationsFound,
          percentage: data.percentage ?? data.Percentage ?? 0,
          reportId: data.reportId ?? data.ReportId ?? null,
          error: data.error ?? data.Error ?? null,
        };
        
        // Check for transition from Cloning to Scanning
        if (prevStatusRef.current === 'Cloning' && normalized.status === 'Scanning') {
            toast.success('Cloning complete. Starting scan...');
        }
        prevStatusRef.current = normalized.status;

        setProgress(normalized);
        setIsScanning(normalized.status !== 'Completed' && normalized.status !== 'Failed' && normalized.status !== 'Cancelled');
        
        if ((normalized.status === 'Completed' || normalized.status === 'Cancelled') && normalized.reportId) {
          clearInterval(pollTimer.current!);
          localStorage.removeItem(getJobStorageKey());
          toast.success(normalized.status === 'Cancelled' ? 'Scan cancelled (partial results saved)' : 'Scan completed');
          setStartTime(null);
          router.push(`/dashboard/reports/${normalized.reportId}`);
        } else if (normalized.status === 'Cancelled') {
             clearInterval(pollTimer.current!);
             localStorage.removeItem(getJobStorageKey());
             toast.success('Scan cancelled');
             setIsScanning(false);
             setStartTime(null);
        }
        
        if (normalized.status === 'Failed') {
          clearInterval(pollTimer.current!);
          localStorage.removeItem(getJobStorageKey());
          toast.error(normalized.error || 'Scan failed');
          setStartTime(null);
        }
      } catch {
      }
    }, 1500);
  };

  useEffect(() => {
    if (!user) return;
    const key = getJobStorageKey();
    const existing = typeof window !== 'undefined' ? localStorage.getItem(key) : null;
    if (existing) {
      setIsScanning(true);
      startPolling(existing);
    }
    return () => {
      if (pollTimer.current) clearInterval(pollTimer.current);
    };
  }, [user]);

  const cancelScan = async () => {
    const jobId = localStorage.getItem(getJobStorageKey());
    if (!jobId) return;

    try {
      const response = await fetch(API_ENDPOINTS.SCAN_CANCEL(jobId), {
        method: 'POST',
        headers: createAuthHeaders(user?.token),
      });
      if (response.ok) {
        toast.success('Cancellation requested. Saving partial results...');
      } else {
        toast.error('Failed to cancel scan');
      }
    } catch {
      toast.error('Failed to cancel scan');
    }
  };

  const handleScan = async (e: React.FormEvent) => {
    e.preventDefault();
    
    if (!path.trim()) {
      toast.error('Please enter a path to scan');
      return;
    }

    if (isAdvanced && !isDockerRunning) {
        toast.error('Docker is not running. Cannot start advanced scan.');
        // trigger start again just in case
        fetch(API_ENDPOINTS.SYSTEM_START_DOCKER, { method: 'POST' });
        return;
    }

    setIsScanning(true);
    setStartTime(Date.now());
    setElapsedTime('00:00');
    setShowResults(false);
    setScanResult(null);
    setViolations([]);
    setProgress(null);
    
    try {
      const response = await fetch(API_ENDPOINTS.SCAN_LOCAL, {
        method: 'POST',
        headers: createAuthHeaders(user?.token),
        body: JSON.stringify({ path: path.trim(), isAdvanced }),
      });

      const data = await response.json();
      if (response.ok) {
        const jobId = data.jobId as string;
        localStorage.setItem(getJobStorageKey(), jobId);
        startPolling(jobId);
      } else {
        toast.error((data as any).error || 'Scan failed');
        setIsScanning(false);
        return;
      }
    } catch (error) {
      if (error instanceof TypeError && error.message.includes('fetch')) {
        toast.error('Cannot connect to API server. Make sure the backend is running on https://localhost:7120');
      } else {
        toast.error('An error occurred during the scan');
      }
      setIsScanning(false);
    } finally {
      // keep isScanning true while polling
    }
  };

  const handleGitScan = async (e: React.FormEvent) => {
    e.preventDefault();
    
    if (!gitUrl.trim()) {
      toast.error('Please enter a repository URL');
      return;
    }

    if (isAdvanced && !isDockerRunning) {
        toast.error('Docker is not running. Cannot start advanced scan.');
        // trigger start again just in case
        fetch(API_ENDPOINTS.SYSTEM_START_DOCKER, { method: 'POST' });
        return;
    }

    setIsScanning(true);
    setStartTime(Date.now());
    setElapsedTime('00:00');
    setShowResults(false);
    setScanResult(null);
    setViolations([]);
    setProgress(null);
    
    try {
      const response = await fetch(API_ENDPOINTS.SCAN_GIT, {
        method: 'POST',
        headers: createAuthHeaders(user?.token),
        body: JSON.stringify({ 
          repositoryUrl: gitUrl.trim(),
          branch: gitBranch.trim() || undefined,
          accessToken: gitToken.trim() || undefined,
          isAdvanced
        }),
      });

      const data = await response.json();
      if (response.ok) {
        const jobId = data.jobId as string;
        localStorage.setItem(getJobStorageKey(), jobId);
        startPolling(jobId);
      } else {
        toast.error((data as any).error || 'Scan failed');
        setIsScanning(false);
        return;
      }
    } catch (error) {
      toast.error('An error occurred during the scan');
      setIsScanning(false);
    } finally {
      // keep isScanning true while polling
    }
  };

  const getCategoryColor = (category: string) => {
    const colors: { [key: string]: string } = {
      'GDPR': 'bg-blue-500/10 text-blue-400 border-blue-500/20',
      'HIPAA': 'bg-cyan-500/10 text-cyan-400 border-cyan-500/20',
      'Security': 'bg-red-500/10 text-red-400 border-red-500/20',
      'PCI-DSS': 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20',
      'Compliance': 'bg-amber-500/10 text-amber-400 border-amber-500/20',
    };
    return colors[category] || 'bg-zinc-800/50 text-zinc-300 border-zinc-700';
  };

  return (
    <div className="space-y-6 animate-in fade-in duration-500">
      {/* Page Header */}
      <div className="bg-zinc-900/40 backdrop-blur-sm border border-zinc-800 rounded-xl p-6 shadow-lg">
        <h1 className="text-3xl font-bold text-white mb-2 flex items-center gap-3">
          <svg className="w-8 h-8 text-zinc-100" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
          </svg>
          Compliance Scanner
        </h1>
        <p className="text-zinc-400">
          Scan your codebase for compliance violations and best practice issues
        </p>
      </div>

      {/* Scan Form */}
      <div className="bg-zinc-900/40 backdrop-blur-sm border border-zinc-800 rounded-xl p-8 shadow-lg">
        {/* Tabs */}
        <div className="flex space-x-4 mb-6 border-b border-zinc-800">
          <button
            onClick={() => !isScanning && setScanType('local')}
            className={`pb-2 px-4 font-medium transition-colors ${
              scanType === 'local'
                ? 'text-white border-b-2 border-white'
                : 'text-zinc-500 hover:text-zinc-300'
            }`}
            disabled={isScanning}
          >
            Local Scan
          </button>
          <button
            onClick={() => !isScanning && setScanType('git')}
            className={`pb-2 px-4 font-medium transition-colors ${
              scanType === 'git'
                ? 'text-white border-b-2 border-white'
                : 'text-zinc-500 hover:text-zinc-300'
            }`}
            disabled={isScanning}
          >
            Git Repository
          </button>
        </div>

        {scanType === 'local' ? (
          <form onSubmit={handleScan} className="space-y-6">
            <div>
              <label
                htmlFor="path"
                className="block text-sm font-medium text-zinc-300 mb-2"
              >
                Directory or File Path
              </label>
              <div className="flex gap-4">
                <input
                  type="text"
                  id="path"
                  value={path}
                  onChange={(e) => setPath(e.target.value)}
                  onKeyDown={(e) => { if (isScanning && e.key === 'Enter') e.preventDefault(); }}
                  placeholder="e.g., C:\Projects\MyApp or /home/user/project"
                  className="flex-1 rounded-lg border border-zinc-800 bg-zinc-900/50 px-4 py-3 text-white placeholder-zinc-600 focus:border-zinc-500 focus:ring-2 focus:ring-zinc-500/20 focus:outline-none transition-all"
                  disabled={isScanning}
                />
                <button
                  type="submit"
                  disabled={isScanning}
                  className="px-8 py-3 bg-zinc-100 hover:bg-zinc-200 disabled:bg-zinc-800 disabled:text-zinc-600 text-black font-semibold rounded-lg shadow-lg hover:shadow-zinc-500/10 transition-all disabled:cursor-not-allowed flex items-center gap-2"
                >
                  {isScanning ? (
                    <>
                      <div className="animate-spin h-5 w-5 border-2 border-black border-t-transparent rounded-full"></div>
                      Scanning...
                    </>
                  ) : (
                    <>
                      <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
                      </svg>
                      Start Scan
                    </>
                  )}
                </button>
              </div>
              <p className="mt-2 text-sm text-zinc-500">
                Enter the full path to the directory or file you want to scan
              </p>
            </div>

            <div className="flex items-center gap-3 bg-zinc-800/30 p-4 rounded-lg border border-zinc-800">
              <input
                type="checkbox"
                id="advancedLocal"
                checked={isAdvanced}
                onChange={(e) => setIsAdvanced(e.target.checked)}
                className="w-5 h-5 rounded border-zinc-600 bg-zinc-700 text-blue-500 focus:ring-blue-500/20 focus:ring-offset-0"
                disabled={isScanning}
              />
              <div>
                <label htmlFor="advancedLocal" className="font-medium text-zinc-200 cursor-pointer">
                  Enable Advanced Deep Scan
                </label>
                <p className="text-xs text-zinc-500">
                  Uses Privado.ai engine to detect data flow and privacy vulnerabilities (slower)
                </p>
              </div>
            </div>
          </form>
        ) : (
          <form onSubmit={handleGitScan} className="space-y-6">
            <div className="grid grid-cols-1 gap-6">
              <div>
                <label
                  htmlFor="gitUrl"
                  className="block text-sm font-medium text-zinc-300 mb-2"
                >
                  Repository URL
                </label>
                <input
                  type="text"
                  id="gitUrl"
                  value={gitUrl}
                  onChange={(e) => setGitUrl(e.target.value)}
                  onKeyDown={(e) => { if (isScanning && e.key === 'Enter') e.preventDefault(); }}
                  placeholder="https://github.com/username/repo.git"
                  className="w-full rounded-lg border border-zinc-800 bg-zinc-900/50 px-4 py-3 text-white placeholder-zinc-600 focus:border-zinc-500 focus:ring-2 focus:ring-zinc-500/20 focus:outline-none transition-all"
                  disabled={isScanning}
                  required
                />
              </div>

              <div className="grid grid-cols-1 gap-6">
                <div>
                  <label
                    htmlFor="gitBranch"
                    className="block text-sm font-medium text-zinc-300 mb-2"
                  >
                    Branch (Optional)
                  </label>
                  <input
                    type="text"
                    id="gitBranch"
                    value={gitBranch}
                    onChange={(e) => setGitBranch(e.target.value)}
                    onKeyDown={(e) => { if (isScanning && e.key === 'Enter') e.preventDefault(); }}
                    placeholder="main"
                    className="w-full rounded-lg border border-zinc-800 bg-zinc-900/50 px-4 py-3 text-white placeholder-zinc-600 focus:border-zinc-500 focus:ring-2 focus:ring-zinc-500/20 focus:outline-none transition-all"
                    disabled={isScanning}
                  />
                </div>
              </div>

              <div className="flex items-center gap-3 bg-zinc-800/30 p-4 rounded-lg border border-zinc-800">
                <input
                  type="checkbox"
                  id="advancedGit"
                  checked={isAdvanced}
                  onChange={(e) => setIsAdvanced(e.target.checked)}
                  className="w-5 h-5 rounded border-zinc-600 bg-zinc-700 text-blue-500 focus:ring-blue-500/20 focus:ring-offset-0"
                  disabled={isScanning}
                />
                <div>
                  <label htmlFor="advancedGit" className="font-medium text-zinc-200 cursor-pointer">
                    Enable Advanced Deep Scan
                  </label>
                  <p className="text-xs text-zinc-500">
                    Uses Privado.ai engine to detect data flow and privacy vulnerabilities (slower)
                  </p>
                </div>
              </div>

              <div className="flex justify-end">
                <button
                  type="submit"
                  disabled={isScanning}
                  className="px-8 py-3 bg-zinc-100 hover:bg-zinc-200 disabled:bg-zinc-800 disabled:text-zinc-600 text-black font-semibold rounded-lg shadow-lg hover:shadow-zinc-500/10 transition-all disabled:cursor-not-allowed flex items-center gap-2"
                >
                  {isScanning ? (
                    <>
                      <div className="animate-spin h-5 w-5 border-2 border-black border-t-transparent rounded-full"></div>
                      {progress?.status === 'Cloning' ? 'Cloning Repository...' : 'Scanning...'}
                    </>
                  ) : (
                    <>
                      <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
                      </svg>
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
        <div className="bg-zinc-900/40 border border-zinc-800 rounded-xl p-6">
          <div className="flex items-center gap-4">
            <div className="animate-spin h-8 w-8 border-4 border-zinc-500 border-t-transparent rounded-full"></div>
            <div>
              <div className="flex justify-between items-center">
                  <h3 className="font-semibold text-white">
                    {progress?.status === 'Cloning' ? 'Cloning Repository...' : (progress?.stage ? `${progress.stage}...` : 'Scanning in progress...')}
                  </h3>
                  {startTime && (
                    <span className="text-sm font-mono text-zinc-400 bg-zinc-800/50 px-2 py-1 rounded">
                        {elapsedTime}
                    </span>
                  )}
              </div>
              <p className="text-sm text-zinc-400 mt-1">
                {progress?.status === 'Cloning' 
                  ? 'Please wait while we clone the repository...' 
                  : (progress ? `Processed ${progress.processedFiles}/${progress.totalFiles} files • Found ${progress.violationsFound} issues` : 'Analyzing your codebase for security compliance issues')}
              </p>
              {progress && progress.status !== 'Cloning' && (
                <div className="mt-3 w-full bg-zinc-800 rounded-full h-2">
                  <div className="bg-zinc-200 h-2 rounded-full transition-all" style={{ width: `${progress.percentage}%` }}></div>
                </div>
              )}
              <div className="mt-4">
                <button
                  type="button"
                  onClick={async () => {
                    const jobId = typeof window !== 'undefined' ? localStorage.getItem(getJobStorageKey()) : null;
                    if (!jobId) return;
                    try {
                      const res = await fetch(API_ENDPOINTS.SCAN_CANCEL(jobId), {
                        method: 'POST',
                        headers: createAuthHeaders(user?.token),
                      });
                      if (res.ok) {
                        toast.success('Cancellation requested');
                      } else {
                        toast.error('Failed to request cancellation');
                      }
                    } catch {
                      toast.error('Failed to request cancellation');
                    }
                  }}
                  className="px-4 py-2 bg-red-600 hover:bg-red-700 text-white rounded-md disabled:bg-red-900 disabled:text-red-300 transition-colors"
                >
                  Stop Scan
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Scan Results */}
      {showResults && scanResult && (
        <div className="space-y-6">
          {/* Summary Cards */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            <div className="bg-zinc-900/40 backdrop-blur-sm border border-zinc-800 rounded-xl p-6 shadow-lg border-l-4 border-l-blue-500">
              <div className="text-blue-500 text-3xl mb-2">
                <svg className="w-8 h-8" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                </svg>
              </div>
              <p className="text-zinc-400 text-sm">Files Scanned</p>
              <p className="text-3xl font-bold text-white">
                {scanResult.filesScanned}
              </p>
            </div>
            
            <div className="bg-zinc-900/40 backdrop-blur-sm border border-zinc-800 rounded-xl p-6 shadow-lg border-l-4 border-l-red-500">
              <div className="text-red-500 text-3xl mb-2">
                <svg className="w-8 h-8" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                </svg>
              </div>
              <p className="text-zinc-400 text-sm">Violations Found</p>
              <p className="text-3xl font-bold text-white">
                {scanResult.violationsFound}
              </p>
            </div>
            
            <div className="bg-zinc-900/40 backdrop-blur-sm border border-zinc-800 rounded-xl p-6 shadow-lg border-l-4 border-l-zinc-500">
              <div className="text-zinc-500 text-3xl mb-2">
                <svg className="w-8 h-8" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M7 7h.01M7 3h5c.512 0 1.024.195 1.414.586l7 7a2 2 0 010 2.828l-7 7a2 2 0 01-2.828 0l-7-7A1.994 1.994 0 013 12V7a4 4 0 014-4z" />
                </svg>
              </div>
              <p className="text-zinc-400 text-sm">Categories</p>
              <p className="text-3xl font-bold text-white">
                {Object.keys(getCategoryBreakdown(scanResult.violations)).length}
              </p>
            </div>
          </div>

          {/* Report ID */}
          {scanResult.reportId && (
            <div className="bg-emerald-900/20 border border-emerald-800 rounded-xl p-4">
              <div className="flex items-center gap-3">
                <span className="text-2xl text-emerald-400">
                  <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                  </svg>
                </span>
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
            <div className="bg-zinc-900/40 backdrop-blur-sm border border-zinc-800 rounded-xl p-6 shadow-lg">
              <h2 className="text-xl font-bold text-white mb-4">
                Violations by Category
              </h2>
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                {Object.entries(getCategoryBreakdown(scanResult.violations)).map(([category, count]) => (
                  <div
                    key={category}
                    className="flex items-center justify-between p-4 bg-zinc-800/30 rounded-lg border border-zinc-800"
                  >
                    <span className="font-medium text-zinc-200">
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
            <div className="bg-zinc-900/40 backdrop-blur-sm border border-zinc-800 rounded-xl p-6 shadow-lg">
              <h2 className="text-xl font-bold text-white mb-4">
                Detailed Violations ({violations.length})
              </h2>
              <div className="overflow-x-auto">
                <table className="w-full">
                  <thead>
                    <tr className="border-b border-zinc-800">
                      <th className="text-left py-3 px-4 text-sm font-semibold text-zinc-300">
                        File Path
                      </th>
                      <th className="text-left py-3 px-4 text-sm font-semibold text-zinc-300">
                        Line
                      </th>
                      <th className="text-left py-3 px-4 text-sm font-semibold text-zinc-300">
                        Rule Name
                      </th>
                      <th className="text-left py-3 px-4 text-sm font-semibold text-zinc-300">
                        Category
                      </th>
                      <th className="text-left py-3 px-4 text-sm font-semibold text-zinc-300">
                        Matched Text
                      </th>
                      <th className="text-left py-3 px-4 text-sm font-semibold text-zinc-300">
                        Description
                      </th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-zinc-800">
                    {violations.map((violation, index) => (
                      <tr
                        key={index}
                        className="hover:bg-zinc-800/30 transition-colors"
                      >
                        <td className="py-3 px-4 text-xs text-zinc-300 font-mono">
                          {violation.filePath}
                        </td>
                        <td className="py-3 px-4 text-sm text-zinc-400 font-mono">
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
                        <td className="py-3 px-4 text-xs text-zinc-300 font-mono max-w-xs truncate">
                          {violation.matchedText}
                        </td>
                        <td className="py-3 px-4 text-sm text-zinc-400 max-w-md">
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
        <div className="bg-zinc-900/40 backdrop-blur-sm border border-zinc-800 rounded-xl p-12 text-center">
          <div className="text-6xl mb-4 flex justify-center">
            <svg className="w-16 h-16 text-zinc-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
            </svg>
          </div>
          <h3 className="text-xl font-semibold text-white mb-2">
            Ready to Scan
          </h3>
          <p className="text-zinc-400">
            Enter a local path or Git repository URL above to start scanning
          </p>
        </div>
      )}
    </div>
  );
}
