'use client';

import { useState, useRef, useEffect } from 'react';
import { useAuth } from '@/app/context/AuthContext';
import { API_ENDPOINTS, createAuthHeaders } from '@/app/lib/api';
import toast from 'react-hot-toast';

export default function CodeQualityPage() {
  const { user } = useAuth();
  
  // Form Inputs
  const [projectPath, setProjectPath] = useState('');
  const [projectKey, setProjectKey] = useState('');
  const [token, setToken] = useState('');
  const [hostUrl, setHostUrl] = useState('http://localhost:9000');
  
  // Execution State
  const [isScanning, setIsScanning] = useState(false);
  const [progress, setProgress] = useState<{ status: string; stage: string; percentage: number; error?: string | null } | null>(null);
  const pollTimer = useRef<NodeJS.Timeout | null>(null);
  const [startTime, setStartTime] = useState<number | null>(null);
  const [elapsedTime, setElapsedTime] = useState<string>('00:00');

  // Timer effect
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

  const startPolling = (jobId: string) => {
    if (pollTimer.current) clearInterval(pollTimer.current);
    pollTimer.current = setInterval(async () => {
      try {
        const res = await fetch(API_ENDPOINTS.SCAN_PROGRESS(jobId), {
          headers: createAuthHeaders(user?.token),
        });
        
        if (res.status === 401 || res.status === 403) {
            clearInterval(pollTimer.current!);
            setIsScanning(false);
            setStartTime(null);
            return;
        }

        if (res.ok) {
          const data = await res.json();
          setProgress(data);

          if (data.status === 'Completed') {
            clearInterval(pollTimer.current!);
            setIsScanning(false);
            setStartTime(null);
            toast.success('SonarQube Analysis Completed!');
          } else if (data.status === 'Failed' || data.status === 'Cancelled') {
            clearInterval(pollTimer.current!);
            setIsScanning(false);
            setStartTime(null);
            toast.error(`Analysis ${data.status}: ${data.error || 'Unknown error'}`);
          }
        }
      } catch (e) {
        console.error('Polling error', e);
      }
    }, 1000);
  };

  const handleScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!projectPath || !projectKey || !token || !hostUrl) {
      toast.error('All fields are required');
      return;
    }

    setIsScanning(true);
    setStartTime(Date.now());
    setProgress(null);

    try {
      const res = await fetch(API_ENDPOINTS.SCAN_SONAR, {
        method: 'POST',
        headers: createAuthHeaders(user?.token),
        body: JSON.stringify({
          projectPath,
          projectKey,
          token,
          hostUrl
        })
      });

      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.error || 'Failed to start scan');
      }

      const data = await res.json();
      startPolling(data.jobId);
      toast.success('Analysis started');
    } catch (e: any) {
      setIsScanning(false);
      setStartTime(null);
      toast.error(e.message);
    }
  };

  const handleCancel = () => {
    // Ideally implement cancel endpoint, for now just stop UI polling
    if (pollTimer.current) clearInterval(pollTimer.current);
    setIsScanning(false);
    setStartTime(null);
    toast('Analysis monitoring stopped (Scan may still run in background)', { icon: '⚠️' });
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold text-white mb-2">Code Quality Analysis</h1>
        <p className="text-zinc-400">Run SonarQube analysis on your .NET projects.</p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Configuration Form */}
        <div className="lg:col-span-2 space-y-6">
          <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-6">
            <h2 className="text-xl font-semibold text-white mb-4 flex items-center gap-2">
              <svg className="w-5 h-5 text-indigo-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" />
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
              </svg>
              Configuration
            </h2>
            
            <form onSubmit={handleScan} className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-zinc-400 mb-1">Project Path (Absolute)</label>
                <input 
                  type="text" 
                  value={projectPath}
                  onChange={(e) => setProjectPath(e.target.value)}
                  placeholder="C:\Users\User\Projects\MyDotNetProject"
                  className="w-full bg-zinc-950 border border-zinc-800 rounded-lg px-4 py-2 text-white focus:outline-none focus:border-indigo-500"
                  disabled={isScanning}
                />
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium text-zinc-400 mb-1">Project Key</label>
                  <input 
                    type="text" 
                    value={projectKey}
                    onChange={(e) => setProjectKey(e.target.value)}
                    placeholder="my-project-key"
                    className="w-full bg-zinc-950 border border-zinc-800 rounded-lg px-4 py-2 text-white focus:outline-none focus:border-indigo-500"
                    disabled={isScanning}
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-zinc-400 mb-1">Host URL</label>
                  <input 
                    type="text" 
                    value={hostUrl}
                    onChange={(e) => setHostUrl(e.target.value)}
                    placeholder="http://localhost:9000"
                    className="w-full bg-zinc-950 border border-zinc-800 rounded-lg px-4 py-2 text-white focus:outline-none focus:border-indigo-500"
                    disabled={isScanning}
                  />
                </div>
              </div>

              <div>
                <label className="block text-sm font-medium text-zinc-400 mb-1">Sonar Token</label>
                <input 
                  type="password" 
                  value={token}
                  onChange={(e) => setToken(e.target.value)}
                  placeholder="squ_..."
                  className="w-full bg-zinc-950 border border-zinc-800 rounded-lg px-4 py-2 text-white focus:outline-none focus:border-indigo-500"
                  disabled={isScanning}
                />
              </div>

              <div className="pt-4 flex justify-end">
                {isScanning ? (
                  <button 
                    type="button" 
                    onClick={handleCancel}
                    className="px-6 py-2 bg-red-600 hover:bg-red-700 text-white rounded-lg font-medium transition-colors"
                  >
                    Stop Monitoring
                  </button>
                ) : (
                  <button 
                    type="submit" 
                    className="px-6 py-2 bg-indigo-600 hover:bg-indigo-700 text-white rounded-lg font-medium transition-colors flex items-center gap-2"
                  >
                    <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M14.752 11.168l-3.197-2.132A1 1 0 0010 9.87v4.263a1 1 0 001.555.832l3.197-2.132a1 1 0 000-1.664z" />
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                    </svg>
                    Start Analysis
                  </button>
                )}
              </div>
            </form>
          </div>
        </div>

        {/* Progress Panel */}
        <div className="space-y-6">
          <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-6 h-full">
             <h2 className="text-xl font-semibold text-white mb-4 flex items-center gap-2">
              <svg className="w-5 h-5 text-emerald-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
              </svg>
              Status
            </h2>

            {isScanning ? (
              <div className="space-y-6">
                 <div className="flex flex-col items-center py-6">
                    <div className="relative h-24 w-24">
                      <div className="absolute inset-0 rounded-full border-4 border-zinc-800"></div>
                      <div className="absolute inset-0 rounded-full border-4 border-indigo-500 border-t-transparent animate-spin"></div>
                      <div className="absolute inset-0 flex items-center justify-center text-white font-mono text-lg">
                        {elapsedTime}
                      </div>
                    </div>
                    <p className="mt-4 text-indigo-400 font-medium animate-pulse">{progress?.stage || 'Initializing...'}</p>
                 </div>

                 <div className="space-y-2">
                    <div className="flex justify-between text-sm text-zinc-400">
                      <span>Progress</span>
                      <span>{progress?.percentage || 0}%</span>
                    </div>
                    <div className="h-2 bg-zinc-800 rounded-full overflow-hidden">
                      <div 
                        className="h-full bg-indigo-500 transition-all duration-500"
                        style={{ width: `${progress?.percentage || 0}%` }}
                      ></div>
                    </div>
                 </div>
              </div>
            ) : (
              <div className="flex flex-col items-center justify-center h-48 text-zinc-500">
                <svg className="w-12 h-12 mb-3 opacity-20" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
                </svg>
                <p>Ready to scan</p>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
