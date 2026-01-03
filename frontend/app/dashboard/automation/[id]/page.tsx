'use client';

import { useState, useEffect, use } from 'react';
import { useAuth } from '@/app/context/AuthContext';
import { API_ENDPOINTS, createAuthHeaders } from '@/app/lib/api';
import toast from 'react-hot-toast';
import Link from 'next/link';
import { useRouter } from 'next/navigation';

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

export default function ScheduleDetailPage({ params }: { params: Promise<{ id: string }> }) {
    const { id } = use(params);
    const { user, isLoading: authLoading } = useAuth();
    const router = useRouter();
    const [schedule, setSchedule] = useState<Schedule | null>(null);
    const [history, setHistory] = useState<HistoryItem[]>([]);
    const [loading, setLoading] = useState(true);
    const [saving, setSaving] = useState(false);
    
    // Form State
    const [frequency, setFrequency] = useState('Daily');
    const [startDate, setStartDate] = useState('');
    const [endDate, setEndDate] = useState('');
    const [scanType, setScanType] = useState('local');
    const [isActive, setIsActive] = useState(true);
    
    // Dynamic Inputs
    const [path, setPath] = useState('');
    const [gitUrl, setGitUrl] = useState('');
    const [gitBranch, setGitBranch] = useState('');
    const [targetIp, setTargetIp] = useState('');

    useEffect(() => {
        if (authLoading) return;

        if (!user) {
            router.push('/login');
            return;
        }

        if (id) {
            fetchData();
        }
    }, [user, id, authLoading]);

    const fetchData = async () => {
        setLoading(true);
        try {
            console.log('Fetching schedule:', id);
            // Fetch Schedule
            const res = await fetch(`${API_ENDPOINTS.SCHEDULE_BASE}/${id}`, {
                headers: createAuthHeaders(user?.token),
            });
            
            if (res.ok) {
                const data = await res.json();
                console.log('Schedule data:', data);
                setSchedule(data);
                populateForm(data);
                
                // Fetch History
                try {
                    const historyRes = await fetch(`${API_ENDPOINTS.SCHEDULE_BASE}/${id}/history`, {
                        headers: createAuthHeaders(user?.token),
                    });
                    if (historyRes.ok) {
                        const historyData = await historyRes.json();
                        setHistory(historyData);
                    }
                } catch (histError) {
                    console.error('Error fetching history:', histError);
                    // Don't fail the whole page if history fails
                }
            } else {
                console.error('Failed to load schedule:', res.status, res.statusText);
                toast.error(`Failed to load schedule (${res.status})`);
                // Optional: redirect or stay to show error
                // router.push('/dashboard/automation');
            }
        } catch (error) {
            console.error('Error in fetchData:', error);
            toast.error('Error loading data: ' + (error instanceof Error ? error.message : String(error)));
        } finally {
            setLoading(false);
        }
    };

    const populateForm = (data: Schedule) => {
        if (!data) return;
        setFrequency(data.frequency || 'Daily');
        // Handle DateTime string to input value (yyyy-MM-dd)
        setStartDate(data.startDate ? new Date(data.startDate).toISOString().split('T')[0] : '');
        setEndDate(data.endDate ? new Date(data.endDate).toISOString().split('T')[0] : '');
        setScanType(data.scanType || 'local');
        setIsActive(!!data.isActive);
        
        try {
            if (data.configJson) {
                const config = JSON.parse(data.configJson);
                if (data.scanType === 'local' || data.scanType === 'sql') {
                    setPath(config.path || '');
                } else if (data.scanType === 'git') {
                    setGitUrl(config.repositoryUrl || '');
                    setGitBranch(config.branch || '');
                } else if (data.scanType === 'network') {
                    setTargetIp(config.target || '');
                }
            }
        } catch (e) {
            console.error('Error parsing config', e);
        }
    };

    const handleUpdate = async (e: React.FormEvent) => {
        e.preventDefault();
        if (!startDate || !endDate) {
            toast.error('Please select start and end dates');
            return;
        }

        setSaving(true);
        let config: any = {};
        if (scanType === 'local' || scanType === 'sql') {
            if (!path) { toast.error('Path is required'); setSaving(false); return; }
            config = { path };
        } else if (scanType === 'git') {
            if (!gitUrl) { toast.error('Repo URL is required'); setSaving(false); return; }
            config = { repositoryUrl: gitUrl, branch: gitBranch };
        } else if (scanType === 'network') {
            if (!targetIp) { toast.error('Target IP is required'); setSaving(false); return; }
            config = { target: targetIp };
        }

        const payload = {
            frequency,
            startDate: new Date(startDate).toISOString(),
            endDate: new Date(endDate).toISOString(),
            scanType,
            configJson: JSON.stringify(config),
            isActive
        };

        try {
            const res = await fetch(`${API_ENDPOINTS.SCHEDULE_BASE}/${id}`, {
                method: 'PUT',
                headers: createAuthHeaders(user?.token),
                body: JSON.stringify(payload)
            });
            
            if (res.ok) {
                toast.success('Schedule updated successfully');
                fetchData(); // Reload to confirm
            } else {
                toast.error('Failed to update schedule');
            }
        } catch {
            toast.error('Failed to update schedule');
        } finally {
            setSaving(false);
        }
    };

    const handleExecuteNow = async () => {
        if (!confirm('Are you sure you want to run this schedule now?')) return;
        try {
            const toastId = toast.loading('Triggering scan...');
            const res = await fetch(`${API_ENDPOINTS.SCHEDULE_BASE}/${id}/execute`, {
                method: 'POST',
                headers: createAuthHeaders(user?.token),
            });
            
            if (res.ok) {
                toast.success('Scan triggered successfully', { id: toastId });
                // Refresh history after a delay
                setTimeout(fetchData, 2000);
            } else {
                toast.error('Failed to trigger scan', { id: toastId });
            }
        } catch {
            toast.error('Failed to trigger scan');
        }
    };

    if (loading) {
        return (
            <div className="flex justify-center py-12">
                <div className="h-8 w-8 animate-spin rounded-full border-2 border-white border-t-transparent"></div>
            </div>
        );
    }

    if (!schedule) return null;

    return (
        <div className="space-y-6">
            <div className="flex items-center justify-between">
                <div>
                    <Link href="/dashboard/automation" className="text-zinc-400 hover:text-white flex items-center gap-2 mb-2">
                        <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 19l-7-7m0 0l7-7m-7 7h18" />
                        </svg>
                        Back to Automation
                    </Link>
                    <h1 className="text-3xl font-bold text-white tracking-tight">Schedule Details</h1>
                </div>
                <div className="flex items-center gap-4">
                    <button
                        onClick={handleExecuteNow}
                        className="bg-green-600 hover:bg-green-500 text-white px-4 py-2 rounded-md font-medium transition-colors flex items-center gap-2"
                    >
                        <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M14.752 11.168l-3.197-2.132A1 1 0 0010 9.87v4.263a1 1 0 001.555.832l3.197-2.132a1 1 0 000-1.664z" />
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                        </svg>
                        Execute Now
                    </button>
                </div>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                {/* Edit Form */}
                <div className="bg-zinc-900/50 border border-zinc-800 rounded-xl p-6">
                    <h2 className="text-xl font-bold text-white mb-6">Configuration</h2>
                    <form onSubmit={handleUpdate} className="space-y-6">
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
                                    <option value="sql">SQL Vulnerability Scan</option>
                                    <option value="network">Network Audit</option>
                                </select>
                            </div>
                        </div>

                        <div className="grid grid-cols-2 gap-6">
                            <div>
                                <label className="block text-sm font-medium text-zinc-400 mb-2">Start Date</label>
                                <input 
                                    type="date" 
                                    value={startDate}
                                    onChange={(e) => setStartDate(e.target.value)}
                                    className="w-full bg-zinc-800 border border-zinc-700 rounded-lg px-4 py-2.5 text-white focus:outline-none focus:ring-2 focus:ring-blue-500/50"
                                />
                            </div>
                            <div>
                                <label className="block text-sm font-medium text-zinc-400 mb-2">End Date</label>
                                <input 
                                    type="date" 
                                    value={endDate}
                                    onChange={(e) => setEndDate(e.target.value)}
                                    className="w-full bg-zinc-800 border border-zinc-700 rounded-lg px-4 py-2.5 text-white focus:outline-none focus:ring-2 focus:ring-blue-500/50"
                                />
                            </div>
                        </div>

                        {(scanType === 'local' || scanType === 'sql') && (
                            <div>
                                <label className="block text-sm font-medium text-zinc-400 mb-2">Directory Path</label>
                                <input 
                                    type="text" 
                                    value={path}
                                    onChange={(e) => setPath(e.target.value)}
                                    placeholder="C:\Projects\MyApp"
                                    className="w-full bg-zinc-800 border border-zinc-700 rounded-lg px-4 py-2.5 text-white focus:outline-none focus:ring-2 focus:ring-blue-500/50"
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
                                <label className="block text-sm font-medium text-zinc-400 mb-2">Target IP / Domain</label>
                                <input 
                                    type="text" 
                                    value={targetIp}
                                    onChange={(e) => setTargetIp(e.target.value)}
                                    placeholder="192.168.1.1 or example.com"
                                    className="w-full bg-zinc-800 border border-zinc-700 rounded-lg px-4 py-2.5 text-white focus:outline-none focus:ring-2 focus:ring-blue-500/50"
                                />
                            </div>
                        )}

                        <div className="flex items-center gap-2">
                             <input 
                                type="checkbox"
                                id="isActive"
                                checked={isActive}
                                onChange={(e) => setIsActive(e.target.checked)}
                                className="w-4 h-4 rounded border-zinc-700 bg-zinc-800 text-blue-600 focus:ring-blue-500/50"
                             />
                             <label htmlFor="isActive" className="text-sm font-medium text-zinc-300">Active Schedule</label>
                        </div>

                        <div className="pt-4 flex justify-end">
                            <button
                                type="submit"
                                disabled={saving}
                                className="bg-blue-600 hover:bg-blue-500 text-white px-6 py-2 rounded-md font-medium transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
                            >
                                {saving ? 'Saving...' : 'Save Changes'}
                            </button>
                        </div>
                    </form>
                </div>

                {/* Info & Stats */}
                <div className="space-y-6">
                    <div className="bg-zinc-900/50 border border-zinc-800 rounded-xl p-6">
                         <h2 className="text-xl font-bold text-white mb-4">Status</h2>
                         <div className="space-y-4">
                             <div className="flex justify-between items-center py-2 border-b border-zinc-800">
                                 <span className="text-zinc-400">Next Run</span>
                                 <span className="text-white font-mono">{new Date(schedule.nextRun).toLocaleString()}</span>
                             </div>
                             <div className="flex justify-between items-center py-2 border-b border-zinc-800">
                                 <span className="text-zinc-400">Last Run</span>
                                 <span className="text-white font-mono">{schedule.lastRun ? new Date(schedule.lastRun).toLocaleString() : 'Never'}</span>
                             </div>
                             <div className="flex justify-between items-center py-2 border-b border-zinc-800">
                                 <span className="text-zinc-400">Created At</span>
                                 <span className="text-white font-mono">{new Date(schedule.createdAt).toLocaleString()}</span>
                             </div>
                             <div className="flex justify-between items-center py-2">
                                 <span className="text-zinc-400">Total Executions</span>
                                 <span className="text-white font-mono">{history.length}</span>
                             </div>
                         </div>
                    </div>
                </div>
            </div>

            {/* History Table */}
            <div className="bg-zinc-900/50 border border-zinc-800 rounded-xl p-6">
                <h2 className="text-xl font-bold text-white mb-6">Execution History</h2>
                {history.length === 0 ? (
                    <p className="text-center text-zinc-400 py-8">No execution history found.</p>
                ) : (
                    <div className="overflow-x-auto">
                        <table className="w-full text-left">
                            <thead className="text-xs uppercase text-zinc-500 border-b border-zinc-800">
                                <tr>
                                    <th className="px-4 py-3">Date</th>
                                    <th className="px-4 py-3">Status</th>
                                    <th className="px-4 py-3">Report / Error</th>
                                    <th className="px-4 py-3">Actions</th>
                                </tr>
                            </thead>
                            <tbody className="divide-y divide-zinc-800">
                                {history.map((item) => (
                                    <tr key={item.id} className="hover:bg-zinc-800/30">
                                        <td className="px-4 py-3 text-zinc-300 whitespace-nowrap">
                                            {new Date(item.executedAt).toLocaleString()}
                                        </td>
                                        <td className="px-4 py-3">
                                            <span className={`px-2 py-0.5 rounded-full text-xs border ${
                                                item.status === 'Success' 
                                                ? 'bg-green-500/10 text-green-400 border-green-500/20' 
                                                : 'bg-red-500/10 text-red-400 border-red-500/20'
                                            }`}>
                                                {item.status}
                                            </span>
                                        </td>
                                        <td className="px-4 py-3 text-zinc-400">
                                            {item.status === 'Success' ? (
                                                <span className="font-mono text-zinc-300">{item.resultSummary?.substring(0, 8)}...</span>
                                            ) : (
                                                <span className="text-red-400 truncate max-w-xs block" title={item.errorMessage || ''}>
                                                    {item.errorMessage}
                                                </span>
                                            )}
                                        </td>
                                        <td className="px-4 py-3">
                                            {item.status === 'Success' && item.resultSummary && (
                                                <Link 
                                                    href={schedule.scanType === 'network' 
                                                        ? `/dashboard/reports/network/${item.resultSummary}` 
                                                        : `/dashboard/reports/${item.resultSummary}`
                                                    }
                                                    className="text-blue-400 hover:text-blue-300 hover:underline text-sm flex items-center gap-1"
                                                >
                                                    View Report
                                                </Link>
                                            )}
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                )}
            </div>
        </div>
    );
}