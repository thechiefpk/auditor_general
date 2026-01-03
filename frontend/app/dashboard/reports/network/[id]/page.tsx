'use client';

import { useState, useEffect } from 'react';
import { useAuth } from '@/app/context/AuthContext';
import { API_ENDPOINTS, createAuthHeaders, apiRequest } from '@/app/lib/api';
import toast from 'react-hot-toast';
import Link from 'next/link';
import { useParams, useRouter } from 'next/navigation';
import SecurityMeter from '@/app/components/SecurityMeter';

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

// Risk Knowledge Base
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

export default function NetworkReportDetailsPage() {
  const { user } = useAuth();
  const params = useParams();
  const router = useRouter();
  const [report, setReport] = useState<NetworkScanResult | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (params.id) {
      fetchReport(params.id as string);
    }
  }, [params.id]);

  const fetchReport = async (id: string) => {
    setLoading(true);
    try {
      const result = await apiRequest<NetworkScanResult>(
        API_ENDPOINTS.REPORT_NETWORK(id),
        {
          method: 'GET',
          headers: createAuthHeaders(user?.token),
        }
      );

      if (result.error) {
         // Fallback: Fetch all reports and find the one we need
        console.warn('Failed to fetch single report, trying list...');
        const listResult = await apiRequest<any>(
            API_ENDPOINTS.MY_REPORTS,
            {
                method: 'GET',
                headers: createAuthHeaders(user?.token),
            }
        );
        
        if (listResult.data && listResult.data.networkScans) {
            const found = listResult.data.networkScans.find((r: NetworkScanResult) => r.id === id);
            if (found) {
                setReport(found);
            } else {
                toast.error('Report not found');
                router.push('/dashboard/reports');
            }
        } else {
            toast.error(result.error);
        }
      } else if (result.data) {
        setReport(result.data);
      }
    } catch (error) {
      console.error('Error fetching report:', error);
      toast.error('Failed to load report details');
    } finally {
      setLoading(false);
    }
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    toast.success('Report ID copied to clipboard');
  };

  const handleExportPdf = async () => {
    if (!report || !user) return;
    const toastId = toast.loading('Generating PDF...');
    try {
        const response = await fetch(API_ENDPOINTS.NETWORK_REPORT_PDF(report.id), {
            headers: createAuthHeaders(user.token),
        });

        if (response.ok) {
            const blob = await response.blob();
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `NetworkScan_Report_${report.id.substring(0,8)}.pdf`;
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

  const formatDate = (dateString?: string) => {
    if (!dateString) return 'N/A';
    return new Date(dateString).toLocaleString();
  };

  const getScoreInsights = (score: number) => {
    if (score >= 90) return ['Excellent security posture', 'Strong configuration', 'No critical issues'];
    if (score >= 80) return ['Good security', 'Minor configuration tweaks needed', 'Review optional headers'];
    if (score >= 60) return ['Fair security', 'Missing some key headers', 'Check SSL settings'];
    if (score >= 40) return ['Poor security', 'Multiple missing headers', 'Potential port exposure'];
    return ['Critical vulnerabilities', 'Missing essential headers', 'Immediate action required'];
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-[60vh]">
        <div className="animate-spin h-12 w-12 border-4 border-zinc-500 border-t-transparent rounded-full"></div>
      </div>
    );
  }

  if (!report) {
    return (
      <div className="text-center py-12">
        <h2 className="text-2xl font-bold text-white mb-4">Report Not Found</h2>
        <Link href="/dashboard/reports" className="text-zinc-400 hover:text-white underline">
          Back to Reports
        </Link>
      </div>
    );
  }

  return (
    <div className="space-y-6 animate-in fade-in duration-500 pb-10">
      {/* Breadcrumb */}
      <div className="flex flex-col gap-4">
        <Link 
          href="/dashboard/reports"
          className="inline-flex items-center gap-2 text-zinc-400 hover:text-white transition-colors w-fit"
        >
          <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 19l-7-7m0 0l7-7m-7 7h18" />
          </svg>
          Back to Reports
        </Link>
        
        {/* Main Header Card */}
        <div className="bg-zinc-900/40 backdrop-blur-sm border border-zinc-800 rounded-xl p-6 shadow-lg">
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
                <div>
                    <h1 className="text-2xl font-bold text-white flex items-center gap-3">
                        Network Audit Report
                    </h1>
                    <p className="text-zinc-400 mt-1 flex items-center gap-2">
                        <span className="font-medium text-zinc-300">{report.url}</span>
                        <span>•</span>
                        <span>{formatDate(report.createdAt)}</span>
                    </p>
                </div>
                
                <div className="flex items-center gap-6 text-sm">
                    <div className="text-center px-4 py-2 bg-zinc-800/50 rounded-lg border border-zinc-800">
                        <p className="text-zinc-500 text-xs uppercase tracking-wider mb-1">Status</p>
                        <p className={`text-xl font-bold ${
                            report.statusCode >= 200 && report.statusCode < 300 ? 'text-emerald-400' : 'text-red-400'
                        }`}>
                            {report.statusCode}
                        </p>
                    </div>
                    <div className="text-center px-4 py-2 bg-zinc-800/50 rounded-lg border border-zinc-800">
                        <p className="text-zinc-500 text-xs uppercase tracking-wider mb-1">Score</p>
                        <p className={`text-xl font-bold ${
                            report.securityScore >= 80 ? 'text-emerald-400' : 
                            report.securityScore >= 60 ? 'text-amber-400' : 'text-red-400'
                        }`}>
                            {report.securityScore}/100
                        </p>
                    </div>
                </div>
            </div>
        </div>
      </div>

      {/* Detailed Content Grid */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6 animate-in fade-in slide-in-from-bottom-4 duration-500">
          
          {/* Left Column: Score & Export */}
          <div className="md:col-span-1 space-y-6">
              {/* Score Meter */}
              <SecurityMeter score={report.securityScore} />
              
              {/* Insights */}
              <div className="bg-zinc-900/50 border border-zinc-800 rounded-xl p-6">
                  <h3 className="text-sm font-medium text-zinc-400 mb-3 uppercase tracking-wider">Analysis Insights</h3>
                  <ul className="space-y-2">
                      {getScoreInsights(report.securityScore).map((insight, i) => (
                          <li key={i} className="flex items-center gap-2 text-zinc-300 text-sm">
                              <div className="w-1.5 h-1.5 rounded-full bg-blue-500"></div>
                              {insight}
                          </li>
                      ))}
                  </ul>
              </div>

              {/* Actions */}
              <button 
                onClick={handleExportPdf}
                className="w-full py-3 bg-zinc-800 hover:bg-zinc-700 text-white rounded-xl border border-zinc-700 transition-colors flex items-center justify-center gap-2 font-medium"
              >
                  <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" />
                  </svg>
                  Export PDF Report
              </button>
          </div>

          {/* Right Column: Details */}
          <div className="md:col-span-2 space-y-6">
            
            {/* Server Status */}
            <div className="bg-zinc-900/50 border border-zinc-800 rounded-xl p-6 shadow-lg">
              <h3 className="text-lg font-medium text-white mb-4 flex items-center gap-2">
                <svg className="w-5 h-5 text-zinc-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 12h14M12 5l7 7-7 7" />
                </svg>
                Audit Details
              </h3>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                  <div className="p-4 bg-zinc-950/50 rounded-lg border border-zinc-800/50 flex flex-col gap-1">
                    <span className="text-sm text-zinc-500">Status Reason</span>
                    <span className="text-white font-medium">{report.statusReason || 'N/A'}</span>
                  </div>
                  <div className="p-4 bg-zinc-950/50 rounded-lg border border-zinc-800/50 flex flex-col gap-1">
                    <span className="text-sm text-zinc-500">Scan Date</span>
                    <span className="text-white font-medium">{formatDate(report.createdAt)}</span>
                  </div>
              </div>
            </div>

            {/* Open Ports */}
            <div className="bg-zinc-900/50 border border-zinc-800 rounded-xl p-6 shadow-lg">
              <h3 className="text-lg font-medium text-white mb-4 flex items-center gap-2">
                <svg className="w-5 h-5 text-orange-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 9l3 3-3 3m5 0h3M5 20h14a2 2 0 002-2V6a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z" />
                </svg>
                Open Ports
              </h3>
              {report.openPorts && report.openPorts.length > 0 ? (
                <div className="grid gap-3">
                  {report.openPorts.map((port) => {
                      const info = PORT_RISKS[port] || { risk: 'Unknown service port.', solution: 'Verify necessity.' };
                      return (
                        <div key={port} className="flex items-start gap-4 p-4 bg-zinc-950/30 border border-zinc-800 rounded-lg">
                            <div className="w-10 h-10 rounded-lg bg-orange-500/10 border border-orange-500/20 flex items-center justify-center text-orange-400 font-mono font-bold">
                                {port}
                            </div>
                            <div>
                                <div className="flex items-center gap-2 mb-1">
                                    <div className="w-2 h-2 rounded-full bg-red-500"></div>
                                    <span className="text-red-200 text-sm font-medium">{info.risk}</span>
                                </div>
                                <div className="flex items-center gap-2">
                                    <div className="w-2 h-2 rounded-full bg-emerald-500"></div>
                                    <span className="text-emerald-200 text-sm">{info.solution}</span>
                                </div>
                            </div>
                        </div>
                      );
                  })}
                </div>
              ) : (
                 <div className="text-zinc-500 text-sm p-4 bg-zinc-950/30 rounded-lg">No common ports detected (or firewall is blocking).</div>
              )}
            </div>

            {/* Missing Headers */}
            <div className="bg-zinc-900/50 border border-zinc-800 rounded-xl p-6 shadow-lg">
              <h3 className="text-lg font-medium text-white mb-4 flex items-center gap-2">
                <svg className="w-5 h-5 text-red-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                </svg>
                Missing Security Headers
              </h3>
              {report.missingSecurityHeaders && report.missingSecurityHeaders.length > 0 ? (
                <div className="grid gap-3">
                  {report.missingSecurityHeaders.map((header) => {
                      const info = HEADER_RISKS[header] || { risk: 'Missing security header.', solution: 'Enable this header.' };
                      return (
                        <div key={header} className="p-4 bg-zinc-950/30 border border-zinc-800 rounded-lg">
                            <div className="text-red-300 font-mono mb-2">{header}</div>
                            <div className="flex flex-col gap-1 text-sm">
                                <span className="text-zinc-400"><span className="text-red-400">• Risk:</span> {info.risk}</span>
                                <span className="text-zinc-400"><span className="text-emerald-400">• Fix:</span> {info.solution}</span>
                            </div>
                        </div>
                      );
                  })}
                </div>
              ) : (
                <div className="text-emerald-400 text-sm p-4 bg-zinc-950/30 rounded-lg flex items-center gap-2">
                    <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                    </svg>
                    All critical security headers are present.
                </div>
              )}
            </div>
          </div>
      </div>
    </div>
  );
}
