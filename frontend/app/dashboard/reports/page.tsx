'use client';

import { useState, useEffect, useRef } from 'react';
import { useAuth } from '@/app/context/AuthContext';
import { API_ENDPOINTS, createAuthHeaders, apiRequest } from '@/app/lib/api';
import toast from 'react-hot-toast';
import { useRouter } from 'next/navigation';
import Link from 'next/link';

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

interface NetworkScanResult {
  id: string;
  url: string;
  statusCode: number;
  statusReason?: string;
  securityScore: number;
  createdAt: string;
  headers?: Record<string, string>;
  missingSecurityHeaders?: string[];
  openPorts?: number[];
  piiFindings?: string[];
}

const PORT_RISKS: Record<number, { risk: string; solution: string }> = {
  21: { risk: 'FTP allows cleartext authentication.', solution: 'Use SFTP or FTPS.' },
  22: { risk: 'SSH exposed to the internet.', solution: 'Use key-based auth and restrict IP access.' },
  23: { risk: 'Telnet transmits data in cleartext.', solution: 'Disable Telnet and use SSH.' },
  80: { risk: 'Unencrypted HTTP traffic.', solution: 'Redirect all traffic to HTTPS (443).' },
  443: { risk: 'HTTPS is standard, but check SSL/TLS config.', solution: 'Ensure TLS 1.2+ and strong ciphers.' },
  3306: { risk: 'Database port exposed.', solution: 'Block external access; use a VPN.' },
  3389: { risk: 'RDP exposed.', solution: 'Require VPN access; enable NLA.' },
  8080: { risk: 'Alternative HTTP port.', solution: 'Ensure this service is intended to be public.' },
};

const HEADER_RISKS: Record<string, { risk: string; solution: string }> = {
  'Strict-Transport-Security': { risk: 'Vulnerable to MITM downgrade attacks.', solution: 'Enable HSTS (max-age=31536000).' },
  'Content-Security-Policy': { risk: 'Vulnerable to XSS and data injection.', solution: 'Implement a strict CSP.' },
  'X-Frame-Options': { risk: 'Vulnerable to Clickjacking.', solution: 'Set to DENY or SAMEORIGIN.' },
  'X-Content-Type-Options': { risk: 'Vulnerable to MIME-type sniffing.', solution: 'Set to "nosniff".' },
  'Referrer-Policy': { risk: 'May leak sensitive URLs to third parties.', solution: 'Set to "strict-origin-when-cross-origin".' },
};

interface ReportsResponse {
  codeScans: ScanReport[];
  networkScans: NetworkScanResult[];
}

export default function ReportsPage() {
  const { user } = useAuth();
  const router = useRouter();
  const [reports, setReports] = useState<ScanReport[]>([]);
  const [networkReports, setNetworkReports] = useState<NetworkScanResult[]>([]);
  const [activeTab, setActiveTab] = useState<'code' | 'network'>('code');
  const [loading, setLoading] = useState(false);
  
  // Expanded Network Report State
  const [expandedReportId, setExpandedReportId] = useState<string | null>(null);
  const [expandedReportDetails, setExpandedReportDetails] = useState<NetworkScanResult | null>(null);
  const [loadingDetails, setLoadingDetails] = useState(false);
  
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
      
      const result = await apiRequest<ReportsResponse>(
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
        setReports(result.data.codeScans || []);
        setNetworkReports(result.data.networkScans || []);
        
        if (!loadedRef.current) {
            const total = (result.data.codeScans?.length || 0) + (result.data.networkScans?.length || 0);
            toast.success(`Loaded ${total} reports`);
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

  const handleExportNetworkPdf = async (e: React.MouseEvent, reportId: string) => {
    e.stopPropagation();
    const toastId = toast.loading('Generating PDF...');
    try {
        const response = await fetch(API_ENDPOINTS.NETWORK_REPORT_PDF(reportId), {
            headers: createAuthHeaders(user?.token),
        });

        if (response.ok) {
            const blob = await response.blob();
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `NetworkScan_Report_${reportId.substring(0,8)}.pdf`;
            document.body.appendChild(a);
            a.click();
            window.URL.revokeObjectURL(url);
            document.body.removeChild(a);
            toast.success('Report downloaded', { id: toastId });
        } else {
            toast.error('Failed to download report', { id: toastId });
        }
    } catch (error) {
        toast.error('Error downloading report', { id: toastId });
    }
  };

  const handleExpandNetworkReport = async (e: React.MouseEvent, reportId: string) => {
      e.stopPropagation();
      
      if (expandedReportId === reportId) {
          setExpandedReportId(null);
          setExpandedReportDetails(null);
          return;
      }

      setExpandedReportId(reportId);
      setLoadingDetails(true);

      try {
        const result = await apiRequest<NetworkScanResult>(
            API_ENDPOINTS.REPORT_NETWORK(reportId),
            {
                method: 'GET',
                headers: createAuthHeaders(user?.token),
            }
        );

        if (result.data) {
            setExpandedReportDetails(result.data);
        } else {
            toast.error('Failed to fetch details');
        }
      } catch (error) {
          console.error(error);
          toast.error('Failed to fetch details');
      } finally {
          setLoadingDetails(false);
      }
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

      {/* Tabs */}
      <div className="flex gap-4 border-b border-zinc-800 pb-4">
        <button
          onClick={() => setActiveTab('code')}
          className={`px-4 py-2 rounded-lg font-medium transition-colors flex items-center gap-2 ${
            activeTab === 'code' 
              ? 'bg-blue-500/10 text-blue-400 border border-blue-500/20' 
              : 'text-zinc-400 hover:text-white hover:bg-zinc-800'
          }`}
        >
          <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4" />
          </svg>
          Code Security ({reports.length})
        </button>
        <button
          onClick={() => setActiveTab('network')}
          className={`px-4 py-2 rounded-lg font-medium transition-colors flex items-center gap-2 ${
            activeTab === 'network' 
              ? 'bg-blue-500/10 text-blue-400 border border-blue-500/20' 
              : 'text-zinc-400 hover:text-white hover:bg-zinc-800'
          }`}
        >
          <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9m-9 9a9 9 0 019-9" />
          </svg>
          Network Audits ({networkReports.length})
        </button>
      </div>

      {/* Loading State */}
      {loading && (
        <div className="flex items-center justify-center py-12">
          <div className="animate-spin h-12 w-12 border-4 border-zinc-500 border-t-transparent rounded-full"></div>
        </div>
      )}

      {/* Reports Grid - Code Security */}
      {!loading && activeTab === 'code' && reports.length > 0 && (
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

      {/* Reports Grid - Network Audit */}
      {!loading && activeTab === 'network' && networkReports.length > 0 && (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {networkReports.map((report) => (
            <div
              key={report.id}
              className={`bg-zinc-900/40 backdrop-blur-sm border border-zinc-800 rounded-xl shadow-lg hover:shadow-xl hover:border-zinc-600 transition-all duration-300 overflow-hidden group cursor-pointer ${expandedReportId === report.id ? 'md:col-span-2 lg:col-span-3 ring-2 ring-blue-500/50' : ''}`}
              onClick={(e) => handleExpandNetworkReport(e, report.id)}
            >
              {/* Report Header */}
              <div className="bg-zinc-800/50 p-4 border-b border-zinc-800">
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center gap-2">
                    <span className="text-xs bg-zinc-700/50 text-zinc-300 px-2 py-1 rounded-full border border-zinc-700">
                      {formatDate(report.createdAt)}
                    </span>
                    {/* Explicitly NO Report ID here as requested */}
                  </div>
                  <div className="flex items-center gap-2">
                      <button
                        onClick={(e) => handleExportNetworkPdf(e, report.id)}
                        className="p-1.5 hover:bg-zinc-700 rounded text-zinc-400 hover:text-white transition-colors"
                        title="Export PDF"
                      >
                         <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" />
                        </svg>
                      </button>
                  </div>
                </div>
                <h3 className="text-lg font-bold text-white mb-1 truncate flex items-center gap-2" title={report.url}>
                  <svg className="w-5 h-5 text-zinc-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9m-9 9a9 9 0 019-9" />
                  </svg>
                  {report.url}
                </h3>
              </div>

              {/* Report Content */}
              <div className="p-6">
                <div className="flex items-center justify-between mb-6">
                  <div className="text-center">
                    <p className="text-sm text-zinc-500 mb-1">Status</p>
                    <p className={`text-2xl font-bold ${
                      report.statusCode >= 200 && report.statusCode < 300 ? 'text-emerald-400' : 'text-red-400'
                    }`}>
                      {report.statusCode}
                    </p>
                  </div>
                  <div className="h-10 w-px bg-zinc-800"></div>
                  <div className="text-center">
                    <p className="text-sm text-zinc-500 mb-1">Score</p>
                    <div className="flex items-center gap-2 justify-center">
                        <span className={`text-2xl font-bold ${
                            report.securityScore >= 80 ? 'text-emerald-400' : 
                            report.securityScore >= 60 ? 'text-amber-400' : 'text-red-400'
                        }`}>
                            {report.securityScore}/100
                        </span>
                    </div>
                  </div>
                </div>

                <div className="space-y-3">
                    <div className="flex items-center justify-between text-sm">
                        <span className="text-zinc-400">Status Reason</span>
                        <span className="text-white font-medium">{report.statusReason || 'OK'}</span>
                    </div>
                </div>

                {/* Expanded Details */}
                {expandedReportId === report.id && (
                    <div className="mt-6 pt-6 border-t border-zinc-800 animate-in fade-in slide-in-from-top-4 duration-300">
                        {loadingDetails ? (
                             <div className="flex justify-center py-4">
                                <div className="animate-spin h-6 w-6 border-2 border-zinc-500 border-t-transparent rounded-full"></div>
                             </div>
                        ) : expandedReportDetails ? (
                            <div className="space-y-6">
                                {/* Audit Details Section as requested */}
                                <div>
                                    <h4 className="text-sm font-medium text-zinc-400 mb-3 uppercase tracking-wider">Audit Details</h4>
                                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4 bg-zinc-950/30 p-4 rounded-lg border border-zinc-800">
                                        <div>
                                            <p className="text-xs text-zinc-500">Status Reason</p>
                                            <p className="text-white">{expandedReportDetails.statusReason || 'N/A'}</p>
                                        </div>
                                        <div>
                                            <p className="text-xs text-zinc-500">Scan Date</p>
                                            <p className="text-white">{formatDate(expandedReportDetails.createdAt)}</p>
                                        </div>
                                    </div>
                                </div>

                                {/* Open Ports */}
                                {expandedReportDetails.openPorts && expandedReportDetails.openPorts.length > 0 && (
                                    <div>
                                        <h4 className="text-sm font-medium text-zinc-400 mb-3 uppercase tracking-wider flex items-center gap-2">
                                            Open Ports <span className="text-xs bg-zinc-800 text-zinc-400 px-2 py-0.5 rounded-full">{expandedReportDetails.openPorts.length}</span>
                                        </h4>
                                        <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                                            {expandedReportDetails.openPorts.map(port => {
                                                const info = PORT_RISKS[port];
                                                return (
                                                    <div key={port} className="bg-zinc-950/30 p-3 rounded border border-zinc-800/50 flex items-center gap-3">
                                                        <span className="font-mono text-orange-400 font-bold">{port}</span>
                                                        {info && <span className="text-xs text-zinc-500 truncate">{info.risk}</span>}
                                                    </div>
                                                );
                                            })}
                                        </div>
                                    </div>
                                )}

                                {/* Missing Headers */}
                                {expandedReportDetails.missingSecurityHeaders && expandedReportDetails.missingSecurityHeaders.length > 0 && (
                                    <div>
                                        <h4 className="text-sm font-medium text-zinc-400 mb-3 uppercase tracking-wider flex items-center gap-2">
                                            Missing Headers <span className="text-xs bg-zinc-800 text-zinc-400 px-2 py-0.5 rounded-full">{expandedReportDetails.missingSecurityHeaders.length}</span>
                                        </h4>
                                        <div className="space-y-2">
                                            {expandedReportDetails.missingSecurityHeaders.map(header => (
                                                <div key={header} className="bg-zinc-950/30 p-2 rounded border border-zinc-800/50 text-sm text-red-300 font-mono">
                                                    {header}
                                                </div>
                                            ))}
                                        </div>
                                    </div>
                                )}
                                
                                <div className="flex justify-end pt-2">
                                    <Link 
                                        href={`/dashboard/reports/network/${report.id}`}
                                        className="text-sm text-blue-400 hover:text-blue-300 hover:underline flex items-center gap-1"
                                        onClick={(e) => e.stopPropagation()}
                                    >
                                        View Full Details Page
                                        <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M14 5l7 7m0 0l-7 7m7-7H3" />
                                        </svg>
                                    </Link>
                                </div>
                            </div>
                        ) : (
                            <p className="text-center text-red-400 text-sm">Failed to load details.</p>
                        )}
                    </div>
                )}

                {/* View Details Button (Only show if NOT expanded) */}
                {!expandedReportId && (
                    <div className="mt-6 pt-4 border-t border-zinc-800 flex justify-end">
                        <span className="text-zinc-400 text-sm font-medium group-hover:text-white transition-colors flex items-center gap-1">
                        Click to Expand Details 
                        <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                        </svg>
                        </span>
                    </div>
                )}

              </div>
            </div>
          ))}
        </div>
      )}

      {/* Empty State */}
      {!loading && ((activeTab === 'code' && reports.length === 0) || (activeTab === 'network' && networkReports.length === 0)) && (
        <div className="bg-zinc-900/40 backdrop-blur-sm border border-zinc-800 rounded-xl p-12 text-center shadow-lg">
          <div className="text-6xl mb-4 flex justify-center">
            <svg className="w-16 h-16 text-zinc-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
            </svg>
          </div>
          <h2 className="text-2xl font-bold text-white mb-2">
            No {activeTab === 'code' ? 'Code Security' : 'Network Audit'} Reports Yet
          </h2>
          <p className="text-zinc-400 mb-6 max-w-md mx-auto">
            {activeTab === 'code' 
              ? 'Run your first security scan to identify vulnerabilities in your codebase.' 
              : 'Run a network audit to check your website headers and security score.'}
          </p>
          <a
            href={activeTab === 'code' ? "/dashboard/scan" : "/dashboard/automation"}
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
