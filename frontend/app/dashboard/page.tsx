'use client';

import Link from 'next/link';
import { useEffect, useState } from 'react';
import { useAuth } from '@/app/context/AuthContext';
import { API_ENDPOINTS, createAuthHeaders, apiRequest } from '@/app/lib/api';

interface AuditRule {
  ruleId: string;
  name: string;
  category: string;
  description: string;
}

interface Violation {
  filePath: string;
  lineNumber: number;
  matchedText: string;
  violatedRule: AuditRule;
}

interface ScanReport {
  reportId: string;
  filesScanned: number;
  violationsFound: number;
  violations: Violation[];
  scanDate?: string;
  scanPath?: string;
}

interface DashboardStats {
  totalScans: number;
  activeScans: number;
  totalViolations: number;
  criticalIssues: number;
  recentReports: ScanReport[];
}

export default function DashboardPage() {
  const { user } = useAuth();
  const [stats, setStats] = useState<DashboardStats>({
    totalScans: 0,
    activeScans: 0,
    totalViolations: 0,
    criticalIssues: 0,
    recentReports: [],
  });
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchDashboardStats();
    fetchActiveCount();
  }, [user]);

  const fetchDashboardStats = async () => {
    if (!user?.token) return;
    
    setLoading(true);
    try {
      const result = await apiRequest<ScanReport[]>(
        API_ENDPOINTS.MY_REPORTS,
        {
          method: 'GET',
          headers: createAuthHeaders(user.token),
        }
      );

      if (result.data) {
        const reports = result.data;
        
        // Calculate stats from reports
        const totalViolations = reports.reduce((sum, r) => sum + r.violationsFound, 0);
        const criticalViolations = reports.reduce((sum, r) => {
          const critical = r.violations.filter(v => 
            v.violatedRule.category === 'Security' || 
            v.violatedRule.category === 'GDPR' ||
            v.violatedRule.category === 'HIPAA'
          ).length;
          return sum + critical;
        }, 0);

        setStats({
          totalScans: reports.length,
          activeScans: 0, // Backend doesn't provide this yet
          totalViolations: totalViolations,
          criticalIssues: criticalViolations,
          recentReports: reports.slice(0, 3), // Get 3 most recent
        });
      }
    } catch (error) {
      console.error('Error fetching dashboard stats:', error);
    } finally {
      setLoading(false);
    }
  };

  const fetchActiveCount = async () => {
    if (!user?.token) return;
    try {
      const result = await apiRequest<{ count: number }>(
        API_ENDPOINTS.SCAN_ACTIVECOUNT,
        {
          method: 'GET',
          headers: createAuthHeaders(user.token),
        }
      );
      if (result.data) {
        setStats((prev) => ({ ...prev, activeScans: result.data!.count }));
      }
    } catch (e) {
      // ignore
    }
  };

  const quickActions = [
    {
      title: 'New Scan',
      description: 'Start a new security compliance scan',
      icon: (
        <svg xmlns="http://www.w3.org/2000/svg" className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
        </svg>
      ),
      href: '/dashboard/scan',
    },
    {
      title: 'View Reports',
      description: 'Browse all scan reports and violations',
      icon: (
        <svg xmlns="http://www.w3.org/2000/svg" className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
        </svg>
      ),
      href: '/dashboard/reports',
    },
    {
      title: 'Statistics',
      description: 'View detailed analytics and trends',
      icon: (
        <svg xmlns="http://www.w3.org/2000/svg" className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
        </svg>
      ),
      href: '/dashboard/statistics',
    },
  ];

  const statCards = [
    {
      title: 'Total Scans',
      value: stats.totalScans,
      change: stats.totalScans > 0 ? `+${stats.totalScans} this week` : 'No scans yet',
      icon: (
        <svg xmlns="http://www.w3.org/2000/svg" className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2" />
        </svg>
      ),
    },
    {
      title: 'Active Scans',
      value: stats.activeScans,
      change: 'System idle',
      icon: (
        <svg xmlns="http://www.w3.org/2000/svg" className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M13 10V3L4 14h7v7l9-11h-7z" />
        </svg>
      ),
    },
    {
      title: 'Total Violations',
      value: stats.totalViolations,
      change: stats.totalViolations > 0 ? 'Requires attention' : 'Clean code',
      icon: (
        <svg xmlns="http://www.w3.org/2000/svg" className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
        </svg>
      ),
    },
    {
      title: 'Critical Issues',
      value: stats.criticalIssues,
      change: stats.criticalIssues > 0 ? 'Immediate action' : 'Secure',
      icon: (
        <svg xmlns="http://www.w3.org/2000/svg" className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
        </svg>
      ),
    },
  ];

  return (
    <div className="space-y-8 animate-in fade-in duration-500">
      {/* Welcome Section */}
      <div className="flex flex-col md:flex-row md:items-end justify-between gap-4 border-b border-zinc-800 pb-6">
        <div>
          {/* <h1 className="text-2xl font-semibold text-white tracking-tight">Overview</h1> */}
          <p className="text-zinc-400 mt-1 text-sm">
            Welcome back, <span className="text-zinc-200 font-medium">{user?.username || 'User'}</span>. Here's what's happening today.
          </p>
        </div>
        <div className="flex items-center gap-3">
          <span className="text-xs font-medium px-3 py-1 rounded-full bg-emerald-900/30 text-emerald-400 border border-emerald-900/50">
            System Operational
          </span>
          <span className="text-xs font-medium px-3 py-1 rounded-full bg-zinc-800 text-zinc-400 border border-zinc-700">
            v2.0.1
          </span>
        </div>
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-5">
        {loading ? (
          // Loading skeletons
          Array.from({ length: 4 }).map((_, index) => (
            <div
              key={index}
              className="bg-zinc-900/50 border border-zinc-800 rounded-lg p-6 shadow-sm animate-pulse h-32"
            ></div>
          ))
        ) : (
          statCards.map((stat, index) => (
            <div
              key={index}
              className="group relative bg-zinc-900/40 backdrop-blur-sm border border-zinc-800 rounded-lg p-5 hover:bg-zinc-800/60 hover:border-zinc-700 transition-all duration-300 overflow-hidden"
            >
              <div className="flex flex-col justify-between h-full relative z-10">
                <div className="flex justify-between items-start mb-2">
                  <h3 className="text-zinc-400 text-sm font-medium tracking-wide">
                    {stat.title}
                  </h3>
                  <div className="text-zinc-500 p-1.5 rounded-md bg-white/5 group-hover:bg-white/10 group-hover:text-white transition-colors">
                    {stat.icon}
                  </div>
                </div>
                
                <div className="mt-2">
                  <p className="text-3xl font-bold text-white tracking-tight group-hover:text-white transition-colors">{stat.value}</p>
                  <div className="flex items-center mt-1">
                    <span className={`text-xs font-medium ${
                      stat.title.includes('Violations') && stats.totalViolations > 0 ? 'text-amber-400' :
                      stat.title.includes('Critical') && stats.criticalIssues > 0 ? 'text-red-400' :
                      'text-emerald-400'
                    }`}>
                      {stat.change}
                    </span>
                  </div>
                </div>
              </div>
            </div>
          ))
        )}
      </div>

      {/* Main Content Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Recent Reports Table */}
        <div className="lg:col-span-2 bg-zinc-900/40 backdrop-blur-sm border border-zinc-800 rounded-lg overflow-hidden">
          <div className="flex items-center justify-between p-6 border-b border-zinc-800">
            <h2 className="text-lg font-semibold text-white tracking-tight">Recent Activity</h2>
            <Link
              href="/dashboard/reports"
              className="text-xs font-medium text-zinc-400 hover:text-white transition-colors uppercase tracking-wider"
            >
              View All
            </Link>
          </div>
          
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="bg-white/[0.02] border-b border-zinc-800">
                  <th className="px-6 py-4 text-xs font-medium text-zinc-500 uppercase tracking-wider">Scan ID</th>
                  <th className="px-6 py-4 text-xs font-medium text-zinc-500 uppercase tracking-wider">Status</th>
                  <th className="px-6 py-4 text-xs font-medium text-zinc-500 uppercase tracking-wider">Date</th>
                  <th className="px-6 py-4 text-xs font-medium text-zinc-500 uppercase tracking-wider text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-zinc-800/50">
                {stats.recentReports.length === 0 ? (
                  <tr>
                    <td colSpan={4} className="px-6 py-12 text-center text-zinc-500 text-sm">
                      No scan reports available yet.
                    </td>
                  </tr>
                ) : (
                  stats.recentReports.map((report) => (
                    <tr key={report.reportId} className="hover:bg-white/[0.02] transition-colors group">
                      <td className="px-6 py-4 text-sm font-medium text-white font-mono">
                        {report.reportId.substring(0, 8)}
                      </td>
                      <td className="px-6 py-4">
                        <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium border ${
                          report.violationsFound > 0 
                            ? 'bg-amber-900/30 text-amber-400 border-amber-900/50' 
                            : 'bg-emerald-900/30 text-emerald-400 border-emerald-900/50'
                        }`}>
                          <span className={`w-1.5 h-1.5 rounded-full ${report.violationsFound > 0 ? 'bg-amber-400' : 'bg-emerald-400'}`}></span>
                          {report.violationsFound} Issues
                        </span>
                      </td>
                      <td className="px-6 py-4 text-sm text-zinc-400">
                        {new Date().toLocaleDateString()}
                      </td>
                      <td className="px-6 py-4 text-right">
                        <Link href={`/dashboard/reports/${report.reportId}`} className="text-zinc-500 hover:text-white transition-colors">
                          <svg xmlns="http://www.w3.org/2000/svg" className="w-5 h-5 ml-auto" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 5l7 7-7 7" />
                          </svg>
                        </Link>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>

        {/* Quick Actions */}
        <div className="bg-zinc-900/40 backdrop-blur-sm border border-zinc-800 rounded-lg p-6 h-fit">
          <h2 className="text-lg font-semibold text-white tracking-tight mb-6">Quick Actions</h2>
          <div className="space-y-3">
            {quickActions.map((action, index) => (
              <Link
                key={index}
                href={action.href}
                className="group flex items-start gap-4 p-4 rounded-lg border border-zinc-800 bg-zinc-900/30 hover:bg-zinc-800 hover:border-zinc-700 transition-all duration-300"
              >
                <div className="p-2 rounded-md bg-zinc-800 text-zinc-400 group-hover:bg-white group-hover:text-black transition-all duration-300">
                  {action.icon}
                </div>
                <div>
                  <h3 className="font-medium text-white group-hover:text-zinc-200 transition-colors text-sm">
                    {action.title}
                  </h3>
                  <p className="text-xs text-zinc-500 mt-0.5 group-hover:text-zinc-400">
                    {action.description}
                  </p>
                </div>
              </Link>
            ))}
          </div>
          
          <div className="mt-8 p-4 rounded-lg bg-zinc-800/30 border border-zinc-700/50">
            <h3 className="text-sm font-semibold text-zinc-300 mb-1">Pro Tip</h3>
            <p className="text-xs text-zinc-500">
              Schedule automated scans to run every night to ensure continuous compliance monitoring.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}
