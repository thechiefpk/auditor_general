'use client';

import { useState, useEffect } from 'react';
import { useAuth } from '@/app/context/AuthContext';
import { API_ENDPOINTS, createAuthHeaders } from '@/app/lib/api';
import toast from 'react-hot-toast';
import Link from 'next/link';

interface Schedule {
  id: string;
  frequency: string;
  startDate: string;
  endDate: string;
  scanType: string;
  configJson: string;
  lastRun: string | null;
  nextRun: string;
  isActive: boolean;
  createdAt: string;
}

interface HistoryItem {
    id: string;
    scheduleId: string;
    executedAt: string;
    status: string;
    resultSummary: string | null;
    errorMessage: string | null;
}

export default function AutomationPage() {
  const { user } = useAuth();
  const [schedules, setSchedules] = useState<Schedule[]>([]);
  const [loading, setLoading] = useState(true);
  const [isModalOpen, setIsModalOpen] = useState(false);

  // History State
  const [historyItems, setHistoryItems] = useState<HistoryItem[]>([]);
  const [isHistoryModalOpen, setIsHistoryModalOpen] = useState(false);
  const [loadingHistory, setLoadingHistory] = useState(false);
  const [selectedSchedule, setSelectedSchedule] = useState<Schedule | null>(null);

  // Form State
  const [frequency, setFrequency] = useState('Daily');
  const [startDate, setStartDate] = useState('');
  const [endDate, setEndDate] = useState('');
  const [scanType, setScanType] = useState('local');
  
  // Dynamic Inputs
  const [path, setPath] = useState('');
  const [gitUrl, setGitUrl] = useState('');
  const [gitBranch, setGitBranch] = useState('');
  const [targetIp, setTargetIp] = useState('');
  const [runImmediately, setRunImmediately] = useState(false);

  useEffect(() => {
    fetchSchedules();
  }, [user]);

  const fetchSchedules = async () => {
    if (!user) return;
    try {
      const res = await fetch(API_ENDPOINTS.SCHEDULE_BASE || '/api/schedules', {
        headers: createAuthHeaders(user.token),
      });
      if (res.ok) {
        const data = await res.json();
        setSchedules(data);
      }
    } catch (e) {
      console.error(e);
      toast.error('Failed to load schedules');
    } finally {
      setLoading(false);
    }
  };

  const fetchHistory = async (schedule: Schedule) => {
      setLoadingHistory(true);
      setIsHistoryModalOpen(true);
      setHistoryItems([]);
      setSelectedSchedule(schedule);
      try {
          const res = await fetch(`${API_ENDPOINTS.SCHEDULE_BASE || '/api/schedules'}/${schedule.id}/history`, {
              headers: createAuthHeaders(user?.token),
          });
          if (res.ok) {
              const data = await res.json();
              setHistoryItems(data);
          } else {
              toast.error('Failed to load history');
          }
      } catch {
          toast.error('Failed to load history');
      } finally {
          setLoadingHistory(false);
      }
  };

  const handleExecuteNow = async (scheduleId: string) => {
    try {
        const toastId = toast.loading('Triggering scan...');
        const res = await fetch(`${API_ENDPOINTS.SCHEDULE_BASE || '/api/schedules'}/${scheduleId}/execute`, {
            method: 'POST',
            headers: createAuthHeaders(user?.token),
        });
        
        if (res.ok) {
            toast.success('Scan triggered successfully', { id: toastId });
            // Optionally, we could start polling for status if we wanted, 
            // but for now, the user can just check the history or reports later.
        } else {
            toast.error('Failed to trigger scan', { id: toastId });
        }
    } catch {
        toast.error('Failed to trigger scan');
    }
  };

  const handleDelete = async (id: string) => {
    if (!confirm('Are you sure you want to delete this schedule?')) return;
    try {
      const res = await fetch(`${API_ENDPOINTS.SCHEDULE_BASE || '/api/schedules'}/${id}`, {
        method: 'DELETE',
        headers: createAuthHeaders(user?.token),
      });
      if (res.ok) {
        toast.success('Schedule deleted');
        setSchedules(schedules.filter(s => s.id !== id));
      } else {
        toast.error('Failed to delete schedule');
      }
    } catch {
      toast.error('Failed to delete schedule');
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!startDate || !endDate) {
        toast.error('Please select start and end dates');
        return;
    }

    let config: any = {};
    if (scanType === 'local') {
        if (!path) { toast.error('Path is required'); return; }
        config = { path };
    } else if (scanType === 'git') {
        if (!gitUrl) { toast.error('Repo URL is required'); return; }
        config = { repositoryUrl: gitUrl, branch: gitBranch };
    } else if (scanType === 'network') {
        if (!targetIp) { toast.error('Target IP is required'); return; }
        config = { target: targetIp };
    }

    const payload = {
        frequency,
        startDate: new Date(startDate).toISOString(),
        endDate: new Date(endDate).toISOString(),
        scanType,
        configJson: JSON.stringify(config),
        isActive: true
    };

    try {
        const res = await fetch(API_ENDPOINTS.SCHEDULE_BASE || '/api/schedules', {
            method: 'POST',
            headers: createAuthHeaders(user?.token),
            body: JSON.stringify(payload)
        });
        
        if (res.ok) {
            const createdSchedule = await res.json();
            toast.success('Schedule created successfully');
            
            if (runImmediately && createdSchedule.id) {
                await handleExecuteNow(createdSchedule.id);
            }

            setIsModalOpen(false);
            fetchSchedules();
            resetForm();
        } else {
            toast.error('Failed to create schedule');
        }
    } catch {
        toast.error('Failed to create schedule');
    }
  };

  const resetForm = () => {
    setFrequency('Daily');
    setStartDate('');
    setEndDate('');
    setScanType('local');
    setPath('');
    setGitUrl('');
    setGitBranch('');
    setTargetIp('');
    setRunImmediately(false);
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-white tracking-tight">Automation</h1>
          <p className="text-zinc-400 mt-2">Schedule recurring scans and manage automated security checks.</p>
        </div>
        <button
          onClick={() => setIsModalOpen(true)}
          className="bg-blue-600 hover:bg-blue-500 text-white px-4 py-2 rounded-md font-medium transition-colors flex items-center gap-2"
        >
          <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 6v6m0 0v6m0-6h6m-6 0H6" />
          </svg>
          New Schedule
        </button>
      </div>

      {loading ? (
        <div className="flex justify-center py-12">
            <div className="h-8 w-8 animate-spin rounded-full border-2 border-white border-t-transparent"></div>
        </div>
      ) : schedules.length === 0 ? (
        <div className="bg-zinc-900/50 border border-zinc-800 rounded-xl p-12 text-center">
            <div className="w-16 h-16 bg-zinc-800 rounded-full flex items-center justify-center mx-auto mb-4">
                <svg className="w-8 h-8 text-zinc-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
            </div>
            <h3 className="text-lg font-medium text-white mb-2">No schedules found</h3>
            <p className="text-zinc-400 max-w-sm mx-auto">Create your first scheduled scan to automate your security compliance checks.</p>
        </div>
      ) : (
        <div className="grid gap-4">
            {schedules.map(schedule => (
                <div key={schedule.id} className="bg-zinc-900/50 border border-zinc-800 rounded-xl p-6 flex items-center justify-between group hover:border-zinc-700 transition-all">
                    <Link href={`/dashboard/automation/${schedule.id}`} className="flex items-start gap-4 flex-1 cursor-pointer">
                        <div className={`p-3 rounded-lg ${
                            schedule.scanType === 'local' ? 'bg-blue-500/10 text-blue-500' :
                            schedule.scanType === 'git' ? 'bg-purple-500/10 text-purple-500' :
                            schedule.scanType === 'network' ? 'bg-orange-500/10 text-orange-500' :
                            'bg-pink-500/10 text-pink-500'
                        }`}>
                            <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
                            </svg>
                        </div>
                        <div>
                            <div className="flex items-center gap-3 mb-1">
                                <h3 className="text-lg font-semibold text-white capitalize">{schedule.scanType} Scan</h3>
                                <span className="px-2 py-0.5 rounded-full bg-zinc-800 text-zinc-400 text-xs border border-zinc-700">
                                    {schedule.frequency}
                                </span>
                                {schedule.isActive ? (
                                    <span className="px-2 py-0.5 rounded-full bg-green-500/10 text-green-400 text-xs border border-green-500/20">Active</span>
                                ) : (
                                    <span className="px-2 py-0.5 rounded-full bg-red-500/10 text-red-400 text-xs border border-red-500/20">Inactive</span>
                                )}
                            </div>
                            <div className="text-sm text-zinc-400 space-y-1">
                                <p>Next Run: <span className="text-white">{new Date(schedule.nextRun).toLocaleString()}</span></p>
                                <p>Last Run: {schedule.lastRun ? new Date(schedule.lastRun).toLocaleString() : 'Never'}</p>
                            </div>
                        </div>
                    </Link>
                    <div className="flex items-center gap-4">
                        <button 
                            onClick={() => handleExecuteNow(schedule.id)}
                            className="p-2 text-zinc-500 hover:text-green-400 transition-colors"
                            title="Run Now"
                        >
                            <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M14.752 11.168l-3.197-2.132A1 1 0 0010 9.87v4.263a1 1 0 001.555.832l3.197-2.132a1 1 0 000-1.664z" />
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                            </svg>
                        </button>
                        <button 
                            onClick={() => fetchHistory(schedule)}
                            className="p-2 text-zinc-500 hover:text-blue-400 transition-colors"
                            title="View History"
                        >
                             <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
                            </svg>
                        </button>
                        <button 
                            onClick={() => handleDelete(schedule.id)}
                            className="p-2 text-zinc-500 hover:text-red-400 transition-colors"
                            title="Delete Schedule"
                        >
                            <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                            </svg>
                        </button>
                    </div>
                </div>
            ))}
        </div>
      )}

      {/* History Modal */}
      {isHistoryModalOpen && (
          <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 backdrop-blur-sm p-4">
            <div className="bg-zinc-900 border border-zinc-800 rounded-xl w-full max-w-2xl max-h-[80vh] overflow-y-auto shadow-2xl">
                <div className="p-6 border-b border-zinc-800 flex justify-between items-center">
                    <h2 className="text-xl font-bold text-white">Execution History</h2>
                    <button onClick={() => setIsHistoryModalOpen(false)} className="text-zinc-400 hover:text-white">
                        <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                        </svg>
                    </button>
                </div>
                <div className="p-6">
                    {loadingHistory ? (
                        <div className="flex justify-center py-8">
                            <div className="h-8 w-8 animate-spin rounded-full border-2 border-white border-t-transparent"></div>
                        </div>
                    ) : historyItems.length === 0 ? (
                        <p className="text-center text-zinc-400 py-8">No execution history found.</p>
                    ) : (
                        <div className="space-y-4">
                            {historyItems.map((item) => (
                                <div key={item.id} className="border border-zinc-800 rounded-lg p-4 bg-zinc-900/50">
                                    <div className="flex justify-between items-start mb-2">
                                        <div>
                                            <p className="text-sm text-zinc-400">{new Date(item.executedAt).toLocaleString()}</p>
                                            <div className="flex items-center gap-2 mt-1">
                                                <span className={`px-2 py-0.5 rounded-full text-xs border ${
                                                    item.status === 'Success' 
                                                    ? 'bg-green-500/10 text-green-400 border-green-500/20' 
                                                    : 'bg-red-500/10 text-red-400 border-red-500/20'
                                                }`}>
                                                    {item.status}
                                                </span>
                                            </div>
                                        </div>
                                    </div>
                                    {item.errorMessage && (
                                        <div className="mt-2 text-sm text-red-400 bg-red-500/5 p-2 rounded border border-red-500/10">
                                            {item.errorMessage}
                                        </div>
                                    )}
                                    {item.resultSummary && item.status === 'Success' && (
                                        <div className="mt-2 text-sm text-zinc-400 flex items-center gap-2">
                                            <span>Report ID: <span className="text-zinc-300 font-mono">{item.resultSummary.substring(0, 8)}...</span></span>
                                            <Link 
                                                href={selectedSchedule?.scanType === 'network' 
                                                    ? `/dashboard/reports/network/${item.resultSummary}` 
                                                    : `/dashboard/reports/${item.resultSummary}`
                                                }
                                                className="text-blue-400 hover:text-blue-300 hover:underline ml-2 flex items-center gap-1"
                                            >
                                                View Report
                                                <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14" />
                                                </svg>
                                            </Link>
                                        </div>
                                    )}
                                </div>
                            ))}
                        </div>
                    )}
                </div>
            </div>
          </div>
      )}

      {/* Create Modal */}
      {isModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 backdrop-blur-sm p-4">
            <div className="bg-zinc-900 border border-zinc-800 rounded-xl w-full max-w-2xl max-h-[90vh] overflow-y-auto shadow-2xl">
                <div className="p-6 border-b border-zinc-800 flex justify-between items-center">
                    <h2 className="text-xl font-bold text-white">Schedule New Scan</h2>
                    <button onClick={() => setIsModalOpen(false)} className="text-zinc-400 hover:text-white">
                        <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                        </svg>
                    </button>
                </div>
                
                <form onSubmit={handleSubmit} className="p-6 space-y-6">
                    <div className="grid grid-cols-2 gap-6">
                        <div>
                            <label className="block text-sm font-medium text-zinc-400 mb-2">Frequency</label>
                            <select 
                                value={frequency}
                                onChange={(e) => setFrequency(e.target.value)}
                                className="w-full bg-zinc-800 border border-zinc-700 rounded-lg px-4 py-2.5 text-white focus:outline-none focus:ring-2 focus:ring-blue-500/50"
                            >
                                <option value="Hourly">Hourly</option>
                                <option value="Daily">Daily</option>
                                <option value="Weekly">Weekly</option>
                                <option value="Monthly">Monthly</option>
                            </select>
                        </div>
                        <div>
                            <label className="block text-sm font-medium text-zinc-400 mb-2">Scan Type</label>
                            <select 
                                value={scanType}
                                onChange={(e) => setScanType(e.target.value)}
                                className="w-full bg-zinc-800 border border-zinc-700 rounded-lg px-4 py-2.5 text-white focus:outline-none focus:ring-2 focus:ring-blue-500/50"
                            >
                                <option value="local">Local Scan</option>
                                <option value="git">Git Repository</option>
                                <option value="network">Network Audit</option>
                            </select>
                        </div>
                    </div>

                    <div className="grid grid-cols-2 gap-6">
                        <div>
                            <label className="block text-sm font-medium text-zinc-400 mb-2">Start Date</label>
                            <input 
                                type="datetime-local"
                                value={startDate}
                                onChange={(e) => setStartDate(e.target.value)}
                                className="w-full bg-zinc-800 border border-zinc-700 rounded-lg px-4 py-2.5 text-white focus:outline-none focus:ring-2 focus:ring-blue-500/50"
                                required
                            />
                        </div>
                        <div>
                            <label className="block text-sm font-medium text-zinc-400 mb-2">End Date</label>
                            <input 
                                type="datetime-local"
                                value={endDate}
                                onChange={(e) => setEndDate(e.target.value)}
                                className="w-full bg-zinc-800 border border-zinc-700 rounded-lg px-4 py-2.5 text-white focus:outline-none focus:ring-2 focus:ring-blue-500/50"
                                required
                            />
                        </div>
                    </div>

                    <div className="pt-4 border-t border-zinc-800">
                        <h3 className="text-sm font-medium text-zinc-300 mb-4 uppercase tracking-wider">Configuration</h3>
                        
                        {scanType === 'local' && (
                            <div>
                                <label className="block text-sm font-medium text-zinc-400 mb-2">
                                    Directory Path
                                </label>
                                <input 
                                    type="text"
                                    value={path}
                                    onChange={(e) => setPath(e.target.value)}
                                    placeholder="C:\Projects\MyApp"
                                    className="w-full bg-zinc-800 border border-zinc-700 rounded-lg px-4 py-2.5 text-white focus:outline-none focus:ring-2 focus:ring-blue-500/50"
                                    required
                                />
                            </div>
                        )}

                        {scanType === 'git' && (
                            <div className="space-y-4">
                                <div>
                                    <label className="block text-sm font-medium text-zinc-400 mb-2">Repository URL</label>
                                    <input 
                                        type="text"
                                        value={gitUrl}
                                        onChange={(e) => setGitUrl(e.target.value)}
                                        placeholder="https://github.com/user/repo.git"
                                        className="w-full bg-zinc-800 border border-zinc-700 rounded-lg px-4 py-2.5 text-white focus:outline-none focus:ring-2 focus:ring-blue-500/50"
                                        required
                                    />
                                </div>
                                <div>
                                    <label className="block text-sm font-medium text-zinc-400 mb-2">Branch (Optional)</label>
                                    <input 
                                        type="text"
                                        value={gitBranch}
                                        onChange={(e) => setGitBranch(e.target.value)}
                                        placeholder="main"
                                        className="w-full bg-zinc-800 border border-zinc-700 rounded-lg px-4 py-2.5 text-white focus:outline-none focus:ring-2 focus:ring-blue-500/50"
                                    />
                                </div>
                            </div>
                        )}

                        {scanType === 'network' && (
                            <div>
                                <label className="block text-sm font-medium text-zinc-400 mb-2">Target IP / Range</label>
                                <input 
                                    type="text"
                                    value={targetIp}
                                    onChange={(e) => setTargetIp(e.target.value)}
                                    placeholder="192.168.1.1"
                                    className="w-full bg-zinc-800 border border-zinc-700 rounded-lg px-4 py-2.5 text-white focus:outline-none focus:ring-2 focus:ring-blue-500/50"
                                    required
                                />
                            </div>
                        )}
                    </div>

                    <div className="flex items-center gap-2">
                        <input
                            type="checkbox"
                            id="runImmediately"
                            checked={runImmediately}
                            onChange={(e) => setRunImmediately(e.target.checked)}
                            className="w-4 h-4 rounded border-zinc-700 bg-zinc-800 text-blue-600 focus:ring-blue-500/50 focus:ring-offset-0"
                        />
                        <label htmlFor="runImmediately" className="text-sm text-zinc-400 select-none cursor-pointer">
                            Execute immediately after creation
                        </label>
                    </div>

                    <div className="flex justify-end gap-3 pt-4 border-t border-zinc-800">
                        <button
                            type="button"
                            onClick={() => setIsModalOpen(false)}
                            className="px-4 py-2 rounded-md text-zinc-400 hover:text-white hover:bg-zinc-800 transition-colors"
                        >
                            Cancel
                        </button>
                        <button
                            type="submit"
                            className="px-6 py-2 rounded-md bg-blue-600 text-white font-medium hover:bg-blue-500 transition-colors shadow-lg shadow-blue-900/20"
                        >
                            Create Schedule
                        </button>
                    </div>
                </form>
            </div>
        </div>
      )}
    </div>
  );
}
