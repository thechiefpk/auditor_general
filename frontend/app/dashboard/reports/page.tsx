'use client';

import { useState, useEffect, useRef } from 'react';
import { useAuth } from '@/app/context/AuthContext';
import { API_ENDPOINTS, createAuthHeaders, apiRequest } from '@/app/lib/api';
import toast from 'react-hot-toast';
import { useRouter } from 'next/navigation';

// API Response interfaces matching C# backend
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

export default function ReportsPage() {
  const { user } = useAuth();
  const router = useRouter();
  const [reports, setReports] = useState<ScanReport[]>([]);
  const [loading, setLoading] = useState(false);
  const loadedRef = useRef(false);

  useEffect(() => {
    if (user?.token) {
      fetchMyReports();
    }
  }, [user?.token]);

  const fetchMyReports = async () => {
    setLoading(true);
    try {
      console.log('Fetching reports from:', API_ENDPOINTS.MY_REPORTS);
      
      const result = await apiRequest<ScanReport[]>(
        API_ENDPOINTS.MY_REPORTS,
        {
          method: 'GET',
          headers: createAuthHeaders(user?.token),
        }
      );

      if (result.error) {
        console.error('API Error:', result.error);
        toast.error(result.error);
        
        // Show helpful message if backend is not running
        if (result.status === 0) {
          toast.error('⚠️ Make sure backend is running on http://localhost:7120', {
            duration: 5000,
          });
        }
      } else if (result.data) {
        setReports(result.data);
        if (!loadedRef.current) {
            toast.success(`Loaded ${result.data.length} scan reports`);
            loadedRef.current = true;
        }
        console.log('Reports loaded:', result.data);
      }
    } catch (error) {
      console.error('Unexpected error fetching reports:', error);
      toast.error('An unexpected error occurred');
    } finally {
      setLoading(false);
    }
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    toast.success('Report ID copied to clipboard');
  };

  const deleteReport = async (e: React.MouseEvent, reportId: string) => {
    e.stopPropagation(); // Prevent navigation to details page
    if (!confirm('Are you sure you want to delete this report? This action cannot be undone.')) return;

    try {
      const result = await apiRequest(
        API_ENDPOINTS.REPORT_DELETE(reportId),
        {
          method: 'DELETE',
          headers: createAuthHeaders(user?.token),
        }
      );

      if (result.error) {
        toast.error(result.error);
      } else {
        toast.success('Report deleted successfully');
        setReports(reports.filter(r => r.reportId !== reportId));
      }
    } catch (error) {
      toast.error('Failed to delete report');
    }
  };

  const exportCsv = async (e: React.MouseEvent, reportId: string) => {
    e.stopPropagation();
    try {
      const response = await fetch(API_ENDPOINTS.REPORT_CSV(reportId), {
        headers: createAuthHeaders(user?.token),
      });

      if (!response.ok) {
        throw new Error('Export failed');
      }

      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `report_${reportId}.csv`;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);
      toast.success('Report exported successfully');
    } catch (error) {
      toast.error('Failed to export report');
    }
  };

  const getCategoryDotColor = (category: string) => {
    const colors: { [key: string]: string } = {
      'GDPR': 'bg-blue-500',
      'HIPAA': 'bg-cyan-500',
      'Security': 'bg-red-500',
      'PCI-DSS': 'bg-emerald-500',
      'Compliance': 'bg-amber-500',
    };
    return colors[category] || 'bg-zinc-800';
  };

  const getCategoryBreakdown = (violations: Violation[]) => {
    const breakdown: { [key: string]: number } = {};
    violations.forEach(v => {
      const category = v.violatedRule.category;
      breakdown[category] = (breakdown[category] || 0) + 1;
    });
    return breakdown;
  };

  const formatDate = (dateString?: string) => {
    if (!dateString) return 'N/A';
    return new Date(dateString).toLocaleString();
  };

  return (
    <div className="space-y-6 animate-in fade-in duration-500">
      {/* Page Header */}
      <div className="bg-zinc-900/40 backdrop-blur-sm border border-zinc-800 rounded-xl p-6 shadow-lg">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-bold text-white mb-2 flex items-center gap-3">
              <svg className="w-8 h-8 text-zinc-100" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
              </svg>
              My Scan Reports
            </h1>
            <p className="text-zinc-400">
              View all your security compliance scan reports
            </p>
          </div>
          <button
            onClick={fetchMyReports}
            disabled={loading}
            className="px-4 py-2 bg-zinc-100 hover:bg-zinc-200 disabled:bg-zinc-800 disabled:text-zinc-600 text-black font-semibold rounded-lg shadow-lg hover:shadow-zinc-500/10 transition-all focus:outline-none focus:ring-2 focus:ring-zinc-500 focus:ring-offset-2 focus:ring-offset-zinc-900 flex items-center gap-2"
          >
            {loading ? 'Loading...' : (
              <>
                <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
                </svg>
                Refresh
              </>
            )}
          </button>
        </div>
      </div>

      {/* Loading State */}
      {loading && (
        <div className="flex items-center justify-center py-12">
          <div className="animate-spin h-12 w-12 border-4 border-zinc-500 border-t-transparent rounded-full"></div>
        </div>
      )}

      {/* Reports Grid */}
      {!loading && reports.length > 0 && (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {reports.map((report) => {
            const categoryBreakdown = getCategoryBreakdown(report.violations);
            return (
              <div
                key={report.reportId}
                className="bg-zinc-900/40 backdrop-blur-sm border border-zinc-800 rounded-xl shadow-lg hover:shadow-xl hover:border-zinc-600 transition-all duration-300 overflow-hidden group cursor-pointer"
                onClick={() => router.push(`/dashboard/reports/${report.reportId}`)}
              >
                {/* Report Header */}
                <div className="bg-zinc-800/50 p-4 border-b border-zinc-800">
                  <div className="flex items-center justify-between mb-2">
                    <div className="flex items-center gap-2">
                        <span className="text-sm font-mono text-zinc-400" title={report.reportId}>
                          #{report.reportId.substring(0, 8)}...
                        </span>
                        <button
                            onClick={(e) => {
                                e.stopPropagation();
                                copyToClipboard(report.reportId);
                            }}
                            className="p-1 hover:bg-zinc-700 rounded text-zinc-400 hover:text-white transition-colors"
                            title="Copy Full Report ID"
                        >
                            <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
                            </svg>
                        </button>
                    </div>
                    <div className="flex items-center gap-2">
                      <span className="text-xs bg-zinc-700/50 text-zinc-300 px-2 py-1 rounded-full border border-zinc-700">
                        {formatDate(report.scanDate)}
                      </span>
                      <button
                        onClick={(e) => exportCsv(e, report.reportId)}
                        className="p-1 hover:bg-zinc-700 rounded text-zinc-400 hover:text-white transition-colors"
                        title="Export CSV"
                      >
                        <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" />
                        </svg>
                      </button>
                      <button
                        onClick={(e) => {
                            e.stopPropagation();
                            router.push(`/dashboard/statistics?id=${report.reportId}`);
                        }}
                        className="p-1 hover:bg-zinc-700 rounded text-zinc-400 hover:text-white transition-colors"
                        title="View Statistics"
                      >
                        <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
                        </svg>
                      </button>
                      <button
                        onClick={(e) => deleteReport(e, report.reportId)}
                        className="p-1 hover:bg-red-500/20 rounded text-zinc-400 hover:text-red-400 transition-colors"
                        title="Delete Report"
                      >
                        <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                        </svg>
                      </button>
                    </div>
                  </div>
                  <h3 className="text-lg font-bold text-white mb-1 truncate flex items-center gap-2">
                    <svg className="w-5 h-5 text-zinc-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-6l-2-2H5a2 2 0 00-2 2z" />
                    </svg>
                    {report.scanPath || 'Project Scan'}
                  </h3>
                </div>

                {/* Report Content */}
                <div className="p-6">
                  <div className="flex items-center justify-between mb-6">
                    <div className="text-center">
                      <p className="text-sm text-zinc-500 mb-1">Files</p>
                      <p className="text-2xl font-bold text-white">
                        {report.filesScanned}
                      </p>
                    </div>
                    <div className="h-10 w-px bg-zinc-800"></div>
                    <div className="text-center">
                      <p className="text-sm text-zinc-500 mb-1">Violations</p>
                      <p className={`text-2xl font-bold ${
                        report.violationsFound > 0 ? 'text-red-400' : 'text-emerald-400'
                      }`}>
                        {report.violationsFound}
                      </p>
                    </div>
                  </div>

                  {/* Categories */}
                  <div className="space-y-3">
                    <p className="text-sm font-medium text-zinc-500">
                      Top Categories
                    </p>
                    <div className="space-y-2">
                      {Object.entries(categoryBreakdown)
                        .slice(0, 3)
                        .map(([category, count]) => (
                          <div key={category} className="flex items-center justify-between text-sm">
                            <span className="flex items-center gap-2 text-zinc-300">
                              <span className={`w-2 h-2 rounded-full ${getCategoryDotColor(category)}`}></span>
                              {category}
                            </span>
                            <span className="font-semibold text-white">{count}</span>
                          </div>
                        ))}
                    </div>
                  </div>

                  {/* View Details Button */}
                  <div className="mt-6 pt-4 border-t border-zinc-800 flex justify-end">
                    <span className="text-zinc-400 text-sm font-medium group-hover:text-white transition-colors flex items-center gap-1">
                      View Full Report 
                      <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M17 8l4 4m0 0l-4 4m4-4H3" />
                      </svg>
                    </span>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* Empty State */}
      {!loading && reports.length === 0 && (
        <div className="bg-zinc-900/40 backdrop-blur-sm border border-zinc-800 rounded-xl p-12 text-center shadow-lg">
          <div className="text-6xl mb-4 flex justify-center">
            <svg className="w-16 h-16 text-zinc-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
            </svg>
          </div>
          <h2 className="text-2xl font-bold text-white mb-2">
            No Scan Reports Yet
          </h2>
          <p className="text-zinc-400 mb-6 max-w-md mx-auto">
            Run your first security scan to identify vulnerabilities and compliance issues in your codebase.
          </p>
          <a
            href="/dashboard/scan"
            className="inline-flex items-center gap-2 px-6 py-3 bg-zinc-100 hover:bg-zinc-200 text-black font-semibold rounded-lg shadow-lg hover:shadow-zinc-500/10 transition-all"
          >
            <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
            </svg>
            Start New Scan
          </a>
        </div>
      )}
    </div>
  );
}
