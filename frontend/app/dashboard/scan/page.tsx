'use client';

import { useEffect, useRef, useState } from 'react';
import { useAuth } from '@/app/context/AuthContext';
import { API_ENDPOINTS, createAuthHeaders } from '@/app/lib/api';
import toast from 'react-hot-toast';
import { useRouter } from 'next/navigation';
import ConsentModal from '@/app/components/ConsentModal';

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

type ScanType = 'local' | 'git' | 'advanced' | 'sql' | null;

export default function ScanPage() {
  const { user } = useAuth();
  const router = useRouter();
  
  // Selection State
  const [selectedScanType, setSelectedScanType] = useState<ScanType>(null);
  const [isConsentOpen, setIsConsentOpen] = useState(false);
  const [uploadFiles, setUploadFiles] = useState<FileList | null>(null);

  // Form Inputs
  const [path, setPath] = useState('');
  const [gitUrl, setGitUrl] = useState('');
  const [gitBranch, setGitBranch] = useState('');
  const [isValidatingGit, setIsValidatingGit] = useState(false);
  
  // Advanced Scan Specific
  const [advancedTarget, setAdvancedTarget] = useState<'local' | 'git'>('local');

  // Git Validation Function
  const validateGitRepo = async (url: string) => {
    if (!url.trim()) return;
    setIsValidatingGit(true);
    try {
        const res = await fetch(API_ENDPOINTS.SCAN_GIT_VALIDATE, {
            method: 'POST',
            headers: createAuthHeaders(user?.token),
            body: JSON.stringify({ repositoryUrl: url })
        });
        const data = await res.json();
        if (!data.valid) {
            toast.error(data.error || 'Repository is not accessible. Ensure it is public.');
        } else {
            toast.success('Repository validated (Public Access OK)');
        }
    } catch (e) {
        toast.error('Failed to validate repository');
    } finally {
        setIsValidatingGit(false);
    }
  };

  const handleGitUrlBlur = () => {
    if (gitUrl.trim()) {
        validateGitRepo(gitUrl.trim());
    }
  };

  // Execution State
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
      // If we restore a scan, we might not know which type it was, but that's fine, we just show progress.
      // Ideally we'd know, but for now we can just show the progress overlay or stay on the current screen.
      // To keep it simple, if scanning is restored, we just show the tiles but with a global progress indicator?
      // Or we can just let it run in background.
      // Current logic: isScanning is true, so controls are disabled.
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

  const initiateScan = (e: React.FormEvent) => {
    e.preventDefault();
    
    // Validation
    if ((selectedScanType === 'local' || selectedScanType === 'sql' || (selectedScanType === 'advanced' && advancedTarget === 'local'))) {
        if (!path.trim() && !uploadFiles) {
            toast.error('Please enter a path or select files to scan');
            return;
        }
    }
    
    if ((selectedScanType === 'git' || (selectedScanType === 'advanced' && advancedTarget === 'git')) && !gitUrl.trim()) {
      toast.error('Please enter a repository URL');
      return;
    }

    if (selectedScanType === 'advanced' && !isDockerRunning) {
        toast.error('Docker is not running. Cannot start advanced scan.');
        fetch(API_ENDPOINTS.SYSTEM_START_DOCKER, { method: 'POST' });
        return;
    }

    setIsConsentOpen(true);
  };

  const executeScan = async () => {
    setIsConsentOpen(false);
    setIsScanning(true);
    setStartTime(Date.now());
    setElapsedTime('00:00');
    setShowResults(false);
    setScanResult(null);
    setViolations([]);
    setProgress(null);
    
    const isAdvanced = selectedScanType === 'advanced';
    const isGit = selectedScanType === 'git' || (isAdvanced && advancedTarget === 'git');
    const isSql = selectedScanType === 'sql';
    const isLocal = !isGit && !isSql; // 'local' or advanced local

    let url = '';
    let body = {};

    if (isSql) {
      url = API_ENDPOINTS.SCAN_SQL;
      body = { path: path.trim() };
    } else if (isGit) {
      url = API_ENDPOINTS.SCAN_GIT;
      body = { 
        repositoryUrl: gitUrl.trim(),
        branch: gitBranch.trim() || undefined,
        isAdvanced
      };
    } else {
        if (uploadFiles && uploadFiles.length > 0) {
            // Upload Flow
            url = API_ENDPOINTS.SCAN_UPLOAD;
            const formData = new FormData();
            formData.append('isAdvanced', String(isAdvanced));
            
            for (let i = 0; i < uploadFiles.length; i++) {
                formData.append('files', uploadFiles[i]);
            }
            
            try {
                const response = await fetch(url, {
                    method: 'POST',
                    headers: {
                        // Don't set Content-Type, let browser set it with boundary
                        'Authorization': `Bearer ${user?.token}`
                    },
                    body: formData,
                });
                const data = await response.json();
                if (response.ok) {
                    const jobId = data.jobId as string;
                    localStorage.setItem(getJobStorageKey(), jobId);
                    startPolling(jobId);
                } else {
                    toast.error((data as any).error || 'Upload scan failed');
                    setIsScanning(false);
                }
            } catch (error) {
                toast.error('An error occurred during upload');
                setIsScanning(false);
            }
            return;
        } else {
            // Path Flow
            url = API_ENDPOINTS.SCAN_LOCAL;
            body = { path: path.trim(), isAdvanced };
        }
    }

    try {
      const response = await fetch(url, {
        method: 'POST',
        headers: createAuthHeaders(user?.token),
        body: JSON.stringify(body),
      });

      const data = await response.json();
      if (response.ok) {
        const jobId = data.jobId as string;
        localStorage.setItem(getJobStorageKey(), jobId);
        startPolling(jobId);
      } else {
        toast.error((data as any).error || 'Scan failed');
        setIsScanning(false);
      }
    } catch (error) {
      if (error instanceof TypeError && (error as any).message.includes('fetch')) {
        toast.error('Cannot connect to API server.');
      } else {
        toast.error('An error occurred during the scan');
      }
      setIsScanning(false);
    }
  };

  const renderTiles = () => (
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-2 gap-6">
      {/* Local Scan Tile */}
      <button
        onClick={() => setSelectedScanType('local')}
        disabled={isScanning}
        className="flex flex-col items-start p-6 bg-zinc-900/40 backdrop-blur-sm border border-zinc-800 rounded-xl hover:bg-zinc-800/40 hover:border-zinc-700 transition-all text-left group"
      >
        <div className="p-3 bg-blue-500/10 rounded-lg mb-4 group-hover:bg-blue-500/20 transition-colors">
          <svg className="w-8 h-8 text-blue-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M5 19a2 2 0 01-2-2V7a2 2 0 012-2h4l2 2h4a2 2 0 012 2v1M5 19h14a2 2 0 002-2v-5a2 2 0 00-2-2H9a2 2 0 00-2 2v5a2 2 0 01-2 2z" />
          </svg>
        </div>
        <h3 className="text-xl font-semibold text-white mb-2">Local Scan</h3>
        <p className="text-zinc-400 text-sm">Scan a local directory on the server for compliance and security issues.</p>
      </button>

      {/* Git Scan Tile */}
      <button
        onClick={() => setSelectedScanType('git')}
        disabled={isScanning}
        className="flex flex-col items-start p-6 bg-zinc-900/40 backdrop-blur-sm border border-zinc-800 rounded-xl hover:bg-zinc-800/40 hover:border-zinc-700 transition-all text-left group"
      >
        <div className="p-3 bg-purple-500/10 rounded-lg mb-4 group-hover:bg-purple-500/20 transition-colors">
          <svg className="w-8 h-8 text-purple-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4" />
          </svg>
        </div>
        <h3 className="text-xl font-semibold text-white mb-2">Git Repository Scan</h3>
        <p className="text-zinc-400 text-sm">Clone and scan a remote Git repository directly from the source.</p>
      </button>

      {/* Advanced Scan Tile */}
      <button
        onClick={() => setSelectedScanType('advanced')}
        disabled={isScanning}
        className="flex flex-col items-start p-6 bg-zinc-900/40 backdrop-blur-sm border border-amber-500/20 rounded-xl hover:bg-amber-500/10 hover:border-amber-500/40 transition-all text-left group relative overflow-hidden"
      >
        <div className="absolute top-0 right-0 p-2">
            <span className="bg-amber-500/20 text-amber-400 text-xs px-2 py-1 rounded border border-amber-500/20">Deep Scan</span>
        </div>
        <div className="p-3 bg-amber-500/10 rounded-lg mb-4 group-hover:bg-amber-500/20 transition-colors">
          <svg className="w-8 h-8 text-amber-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
          </svg>
        </div>
        <h3 className="text-xl font-semibold text-white mb-2">Advanced Deep Scan</h3>
        <p className="text-zinc-400 text-sm">Uses a 3rd party engine to detect complex data flow and privacy vulnerabilities.</p>
      </button>

      {/* SQL Scan Tile */}
      <button
        onClick={() => setSelectedScanType('sql')}
        disabled={isScanning}
        className="flex flex-col items-start p-6 bg-zinc-900/40 backdrop-blur-sm border border-zinc-800 rounded-xl hover:bg-zinc-800/40 hover:border-zinc-700 transition-all text-left group"
      >
        <div className="p-3 bg-emerald-500/10 rounded-lg mb-4 group-hover:bg-emerald-500/20 transition-colors">
          <svg className="w-8 h-8 text-emerald-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M4 7v10c0 2.21 3.582 4 8 4s8-1.79 8-4V7M4 7c0 2.21 3.582 4 8 4s8-1.79 8-4M4 7c0-2.21 3.582-4 8-4s8 1.79 8 4m0 5c0 2.21-3.582 4-8 4s-8-1.79-8-4" />
          </svg>
        </div>
        <h3 className="text-xl font-semibold text-white mb-2">SQL & Schema Scan</h3>
        <p className="text-zinc-400 text-sm">Analyze SQL files and schemas for security best practices and quality issues.</p>
      </button>
    </div>
  );

  const renderForm = () => {
    const isAdvanced = selectedScanType === 'advanced';
    const isGit = selectedScanType === 'git';
    const isSql = selectedScanType === 'sql';
    const isLocal = selectedScanType === 'local';

    return (
      <div className="bg-zinc-900/40 backdrop-blur-sm border border-zinc-800 rounded-xl p-8 shadow-lg animate-in slide-in-from-right duration-300">
        <div className="flex items-center justify-between mb-6">
            <button 
                onClick={() => setSelectedScanType(null)}
                className="flex items-center text-zinc-400 hover:text-white transition-colors"
                disabled={isScanning}
            >
                <svg className="w-5 h-5 mr-2" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 19l-7-7m0 0l7-7m-7 7h18" />
                </svg>
                Back to Scan Options
            </button>
            <h2 className="text-2xl font-bold text-white">
                {isLocal && 'Local Scan'}
                {isGit && 'Git Repository Scan'}
                {isSql && 'SQL & Schema Scan'}
                {isAdvanced && 'Advanced Deep Scan'}
            </h2>
        </div>

        <form onSubmit={initiateScan} className="space-y-6">
            
            {/* Advanced Scan Type Selector */}
            {isAdvanced && (
                <div className="flex p-1 bg-zinc-800 rounded-lg w-fit mb-6">
                    <button
                        type="button"
                        onClick={() => setAdvancedTarget('local')}
                        className={`px-4 py-2 rounded-md text-sm font-medium transition-all ${advancedTarget === 'local' ? 'bg-zinc-600 text-white shadow' : 'text-zinc-400 hover:text-white'}`}
                        disabled={isScanning}
                    >
                        Local Path
                    </button>
                    <button
                        type="button"
                        onClick={() => setAdvancedTarget('git')}
                        className={`px-4 py-2 rounded-md text-sm font-medium transition-all ${advancedTarget === 'git' ? 'bg-zinc-600 text-white shadow' : 'text-zinc-400 hover:text-white'}`}
                        disabled={isScanning}
                    >
                        Git Repository
                    </button>
                </div>
            )}

            {/* Inputs based on type */}
            {(isLocal || isSql || (isAdvanced && advancedTarget === 'local')) && (
                <div>
                    <label className="block text-sm font-medium text-zinc-300 mb-2">
                        {isSql ? 'Scan SQL Files' : 'Scan Source Code'}
                    </label>
                    
                    {/* Tabs for Path vs Upload */}
                    <div className="space-y-4">
                        <div className="p-4 bg-zinc-900/50 border border-zinc-800 rounded-xl space-y-4">
                             <div className="flex flex-col gap-2">
                                <label className="text-xs font-semibold text-zinc-500 uppercase tracking-wider">Option 1: Enter Path (Server-Side)</label>
                                <input
                                    type="text"
                                    value={path}
                                    onChange={(e) => {
                                        setPath(e.target.value);
                                        setUploadFiles(null); // Clear upload if path is typed
                                    }}
                                    placeholder={isSql ? "e.g., C:\\Projects\\Database\\Scripts" : "e.g., C:\\Projects\\MyApp"}
                                    className="w-full rounded-lg border border-zinc-800 bg-black/20 px-4 py-3 text-white placeholder-zinc-600 focus:border-zinc-500 focus:ring-2 focus:ring-zinc-500/20 focus:outline-none transition-all"
                                    disabled={isScanning || (uploadFiles !== null && uploadFiles.length > 0)}
                                />
                             </div>

                             <div className="relative">
                                <div className="absolute inset-0 flex items-center">
                                    <div className="w-full border-t border-zinc-800"></div>
                                </div>
                                <div className="relative flex justify-center text-xs uppercase">
                                    <span className="bg-zinc-900 px-2 text-zinc-500">Or Select From Computer</span>
                                </div>
                             </div>

                             <div className="flex flex-col gap-2">
                                <label className="text-xs font-semibold text-zinc-500 uppercase tracking-wider">Option 2: Upload Folder/File</label>
                                <div className="flex gap-2">
                                    <div className="relative flex-1">
                                        <input
                                            type="file"
                                            id="folder-upload"
                                            // @ts-ignore - webkitdirectory is standard in modern browsers but missing in some TS definitions
                                            webkitdirectory="" 
                                            directory=""
                                            onChange={(e) => {
                                                if (e.target.files && e.target.files.length > 0) {
                                                    setUploadFiles(e.target.files);
                                                    setPath(''); // Clear path if file selected
                                                }
                                            }}
                                            className="hidden"
                                            disabled={isScanning}
                                        />
                                        <label 
                                            htmlFor="folder-upload"
                                            className={`flex flex-col items-center justify-center w-full h-24 border-2 border-dashed rounded-lg cursor-pointer hover:bg-zinc-800/50 transition-all ${uploadFiles ? 'border-blue-500 bg-blue-500/10' : 'border-zinc-700'}`}
                                        >
                                            <div className="flex flex-col items-center justify-center pt-5 pb-6">
                                                <svg className={`w-8 h-8 mb-2 ${uploadFiles ? 'text-blue-500' : 'text-zinc-400'}`} fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-6l-2-2H5a2 2 0 00-2 2z" />
                                                </svg>
                                                <p className="text-sm text-zinc-400">
                                                    {uploadFiles ? (
                                                        <span className="text-blue-400 font-medium">{uploadFiles.length} files selected</span>
                                                    ) : (
                                                        <span className="text-zinc-500">Click to select a <span className="font-semibold text-zinc-300">Folder</span></span>
                                                    )}
                                                </p>
                                            </div>
                                        </label>
                                    </div>
                                    
                                    {/* Single File Fallback (if they want just one file) */}
                                     <div className="relative w-1/3">
                                        <input
                                            type="file"
                                            id="file-upload"
                                            onChange={(e) => {
                                                if (e.target.files && e.target.files.length > 0) {
                                                    setUploadFiles(e.target.files);
                                                    setPath(''); 
                                                }
                                            }}
                                            className="hidden"
                                            disabled={isScanning}
                                        />
                                        <label 
                                            htmlFor="file-upload"
                                            className="flex flex-col items-center justify-center w-full h-24 border-2 border-dashed border-zinc-700 rounded-lg cursor-pointer hover:bg-zinc-800/50 transition-all"
                                        >
                                            <div className="flex flex-col items-center justify-center pt-5 pb-6">
                                                <svg className="w-8 h-8 mb-2 text-zinc-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                                                </svg>
                                                <p className="text-sm text-zinc-500">Select <span className="font-semibold text-zinc-300">File</span></p>
                                            </div>
                                        </label>
                                    </div>
                                </div>
                             </div>
                        </div>
                    </div>
                </div>
            )}

            {(isGit || (isAdvanced && advancedTarget === 'git')) && (
                <div className="space-y-6">
                    <div className="p-4 bg-blue-500/10 border border-blue-500/20 rounded-lg flex items-start gap-3">
                        <svg className="w-6 h-6 text-blue-500 shrink-0 mt-0.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                        </svg>
                        <div>
                            <p className="text-blue-200 font-medium">Public Repositories Only</p>
                            <p className="text-blue-500/80 text-sm mt-1">
                                We only support scanning of public repositories. Please ensure your repository is publicly accessible. 
                                Private repositories requiring authentication are not supported.
                            </p>
                        </div>
                    </div>

                    <div>
                        <label htmlFor="gitUrl" className="block text-sm font-medium text-zinc-300 mb-2">
                            Repository URL
                        </label>
                        <div className="relative">
                            <input
                                type="text"
                                id="gitUrl"
                                value={gitUrl}
                                onChange={(e) => setGitUrl(e.target.value)}
                                onBlur={handleGitUrlBlur}
                                placeholder="https://github.com/username/repo.git"
                                className="w-full rounded-lg border border-zinc-800 bg-zinc-900/50 px-4 py-3 text-white placeholder-zinc-600 focus:border-zinc-500 focus:ring-2 focus:ring-zinc-500/20 focus:outline-none transition-all"
                                disabled={isScanning || isValidatingGit}
                                required
                            />
                            {isValidatingGit && (
                                <div className="absolute right-3 top-3">
                                    <div className="animate-spin h-5 w-5 border-2 border-zinc-500 border-t-transparent rounded-full"></div>
                                </div>
                            )}
                        </div>
                    </div>
                    <div>
                        <label htmlFor="gitBranch" className="block text-sm font-medium text-zinc-300 mb-2">
                            Branch (Optional)
                        </label>
                        <input
                            type="text"
                            id="gitBranch"
                            value={gitBranch}
                            onChange={(e) => setGitBranch(e.target.value)}
                            placeholder="main"
                            className="w-full rounded-lg border border-zinc-800 bg-zinc-900/50 px-4 py-3 text-white placeholder-zinc-600 focus:border-zinc-500 focus:ring-2 focus:ring-zinc-500/20 focus:outline-none transition-all"
                            disabled={isScanning}
                        />
                    </div>
                </div>
            )}

            {isAdvanced && (
                 <div className="p-4 bg-amber-500/10 border border-amber-500/20 rounded-lg flex items-start gap-3">
                    <svg className="w-6 h-6 text-amber-500 shrink-0 mt-0.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                    </svg>
                    <div>
                        <p className="text-amber-200 font-medium">3rd Party Processing</p>
                        <p className="text-amber-500/80 text-sm mt-1">
                            This scan utilizes a powerful 3rd party analysis engine. Your code will be processed by an external service for deep data flow analysis.
                        </p>
                    </div>
                 </div>
            )}

            <div className="flex justify-end pt-4">
                <button
                    type="submit"
                    disabled={isScanning}
                    className="px-8 py-3 bg-white hover:bg-zinc-200 disabled:bg-zinc-800 disabled:text-zinc-600 text-black font-semibold rounded-lg shadow-lg hover:shadow-zinc-500/10 transition-all disabled:cursor-not-allowed flex items-center gap-2"
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
        </form>
      </div>
    );
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

      {/* Progress Overlay */}
      {isScanning && progress && (
        <div className="bg-zinc-900/40 backdrop-blur-sm border border-zinc-800 rounded-xl p-6 shadow-lg animate-in fade-in">
            <div className="flex items-center justify-between mb-4">
                <div>
                    <h3 className="text-lg font-semibold text-white flex items-center gap-2">
                        <div className="animate-spin h-4 w-4 border-2 border-blue-500 border-t-transparent rounded-full"></div>
                        Scan in Progress
                    </h3>
                    <p className="text-zinc-400 text-sm mt-1">{progress.stage}...</p>
                </div>
                <div className="text-right">
                    <p className="text-2xl font-mono text-white">{elapsedTime}</p>
                    <button 
                        onClick={cancelScan}
                        className="text-red-400 hover:text-red-300 text-xs font-medium mt-1"
                    >
                        Cancel Scan
                    </button>
                </div>
            </div>
            
            <div className="w-full bg-zinc-800 rounded-full h-2 mb-2 overflow-hidden">
                <div 
                    className="bg-blue-500 h-2 rounded-full transition-all duration-500"
                    style={{ width: `${progress.percentage}%` }}
                ></div>
            </div>
            
            <div className="flex justify-between text-xs text-zinc-500">
                <span>Files: {progress.processedFiles} / {progress.totalFiles}</span>
                <span>Violations: {progress.violationsFound}</span>
            </div>
        </div>
      )}

      {/* Main Content */}
      {!isScanning && (
        selectedScanType ? renderForm() : renderTiles()
      )}

      <ConsentModal
        isOpen={isConsentOpen}
        onClose={() => setIsConsentOpen(false)}
        onConfirm={executeScan}
        scanType={selectedScanType || 'local'}
      />

    </div>
  );
}
