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

  const quickActions = [
    {
      title: 'New Scan',
      description: 'Start a new security compliance scan',
      icon: '🔍',
      href: '/dashboard/scan',
      color: 'from-blue-500 to-blue-600',
    },
    {
      title: 'View Reports',
      description: 'Browse all scan reports and violations',
      icon: '📄',
      href: '/dashboard/reports',
      color: 'from-emerald-500 to-emerald-600',
    },
    {
      title: 'Statistics',
      description: 'View detailed analytics and trends',
      icon: '📈',
      href: '/dashboard/statistics',
      color: 'from-indigo-500 to-indigo-600',
    },
  ];

  const statCards = [
    {
      title: 'Total Scans',
      value: stats.totalScans,
      icon: '📊',
      change: stats.totalScans > 0 ? `${stats.totalScans} Reports` : 'No scans yet',
      color: 'bg-blue-600',
      textColor: 'text-blue-400',
    },
    {
      title: 'Active Scans',
      value: stats.activeScans,
      icon: '⚡',
      change: 'N/A',
      color: 'bg-emerald-600',
      textColor: 'text-emerald-400',
    },
    {
      title: 'Total Violations',
      value: stats.totalViolations,
      icon: '⚠️',
      change: stats.totalViolations > 0 ? 'Needs attention' : 'All clear',
      color: 'bg-yellow-600',
      textColor: 'text-yellow-400',
    },
    {
      title: 'Critical Issues',
      value: stats.criticalIssues,
      icon: '🔴',
      change: stats.criticalIssues > 0 ? 'High Priority' : 'None',
      color: 'bg-red-600',
      textColor: 'text-red-400',
    },
  ];

  const formatDate = (dateString?: string) => {
    if (!dateString) return 'Recently';
    const date = new Date(dateString);
    const now = new Date();
    const diffMs = now.getTime() - date.getTime();
    const diffMins = Math.floor(diffMs / 60000);
    const diffHours = Math.floor(diffMs / 3600000);
    const diffDays = Math.floor(diffMs / 86400000);

    if (diffMins < 60) return `${diffMins} minutes ago`;
    if (diffHours < 24) return `${diffHours} hours ago`;
    if (diffDays < 7) return `${diffDays} days ago`;
    return date.toLocaleDateString();
  };

  return (
    <div className="space-y-6">
      {/* Welcome Section */}
      <div className="bg-gradient-to-r from-blue-600 to-indigo-600 rounded-2xl p-8 text-white shadow-xl shadow-blue-900/20">
        <h1 className="text-4xl font-bold mb-2">Welcome to SecureAudit</h1>
        <p className="text-blue-100 text-lg">
          Monitor, analyze, and improve your code security compliance
        </p>
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        {loading ? (
          // Loading skeletons
          Array.from({ length: 4 }).map((_, index) => (
            <div
              key={index}
              className="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-lg animate-pulse"
            >
              <div className="flex items-center justify-between mb-4">
                <div className="bg-slate-800 rounded-lg w-12 h-12"></div>
                <div className="bg-slate-800 rounded h-4 w-16"></div>
              </div>
              <div className="bg-slate-800 rounded h-4 w-24 mb-2"></div>
              <div className="bg-slate-800 rounded h-8 w-16"></div>
            </div>
          ))
        ) : (
          statCards.map((stat, index) => (
            <div
              key={index}
              className="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-lg hover:shadow-xl transition-all duration-300 hover:border-slate-700"
            >
              <div className="flex items-center justify-between mb-4">
                <div className={`${stat.color} bg-opacity-20 rounded-lg p-3 text-2xl`}>
                  {stat.icon}
                </div>
                <div className={`text-sm font-medium ${stat.textColor}`}>
                  {stat.change}
                </div>
              </div>
              <h3 className="text-slate-400 text-sm font-medium mb-1">
                {stat.title}
              </h3>
              <p className="text-3xl font-bold text-white">{stat.value}</p>
            </div>
          ))
        )}
      </div>

      {/* Quick Actions & Recent Activity */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Quick Actions */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-lg">
          <h2 className="text-xl font-bold mb-4 text-white">Quick Actions</h2>
          <div className="space-y-4">
            {quickActions.map((action, index) => (
              <Link
                key={index}
                href={action.href}
                className="group flex items-center gap-4 p-4 rounded-xl border border-slate-700 bg-slate-800/50 hover:bg-slate-800 transition-all duration-300 hover:border-slate-600 hover:shadow-md"
              >
                <div className={`bg-gradient-to-br ${action.color} p-3 rounded-lg text-white shadow-lg`}>
                  <span className="text-xl">{action.icon}</span>
                </div>
                <div>
                  <h3 className="font-semibold text-white group-hover:text-blue-400 transition-colors">
                    {action.title}
                  </h3>
                  <p className="text-sm text-slate-400">
                    {action.description}
                  </p>
                </div>
              </Link>
            ))}
          </div>
        </div>

        {/* Recent Reports */}
        <div className="lg:col-span-2 bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-lg">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-xl font-bold text-white">Recent Scan Reports</h2>
            <Link
              href="/dashboard/reports"
              className="text-sm font-medium text-blue-400 hover:text-blue-300 transition-colors"
            >
              View All
            </Link>
          </div>
          
          <div className="overflow-hidden rounded-lg border border-slate-700">
            <table className="min-w-full divide-y divide-slate-700">
              <thead className="bg-slate-800">
                <tr>
                  <th className="px-6 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">
                    Scan ID
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">
                    Violations
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">
                    Date
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">
                    Status
                  </th>
                </tr>
              </thead>
              <tbody className="bg-slate-900 divide-y divide-slate-700">
                {stats.recentReports.length === 0 ? (
                  <tr>
                    <td colSpan={4} className="px-6 py-4 text-center text-slate-400">
                      No scan reports available
                    </td>
                  </tr>
                ) : (
                  stats.recentReports.map((report) => (
                    <tr key={report.reportId} className="hover:bg-slate-800/50 transition-colors">
                      <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-blue-400">
                        {report.reportId.substring(0, 8)}...
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-slate-300">
                        <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${
                          report.violationsFound > 0 
                            ? 'bg-red-900/30 text-red-400' 
                            : 'bg-emerald-900/30 text-emerald-400'
                        }`}>
                          {report.violationsFound} Issues
                        </span>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-slate-400">
                        {formatDate(report.scanDate)}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm">
                        <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-emerald-900/30 text-emerald-400 border border-emerald-900/50">
                          Completed
                        </span>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
}