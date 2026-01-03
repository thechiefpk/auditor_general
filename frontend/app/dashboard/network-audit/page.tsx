'use client';

import { useState, useEffect } from 'react';
import { API_ENDPOINTS, apiRequest, createAuthHeaders } from '@/app/lib/api';
import { useAuth } from '@/app/context/AuthContext';
import toast from 'react-hot-toast';
import SecurityMeter from '@/app/components/SecurityMeter';

interface NetworkScanResult {
  id: string;
  createdAt: string;
  url: string;
  statusCode: number;
  statusReason: string;
  headers: Record<string, string>;
  missingSecurityHeaders: string[];
  securityScore: number;
  openPorts: number[];
  piiFindings: string[];
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

export default function NetworkAuditPage() {
  const { user } = useAuth();
  const [url, setUrl] = useState('');
  const [isScanning, setIsScanning] = useState(false);
  const [result, setResult] = useState<NetworkScanResult | null>(null);
  const [history, setHistory] = useState<NetworkScanResult[]>([]);

  useEffect(() => {
    fetchHistory();
  }, [user]);

  const fetchHistory = async () => {
    if (!user) return;
    try {
      const response = await apiRequest<NetworkScanResult[]>('/api/network/history', {
        headers: createAuthHeaders(user.token),
      });
      if (response.data) {
        setHistory(response.data);
      }
    } catch (error) {
      console.error('Failed to fetch history', error);
    }
  };

  const handleScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!url) {
      toast.error('Please enter a URL');
      return;
    }

    setIsScanning(true);
    setResult(null);

    try {
      const response = await apiRequest<NetworkScanResult>(API_ENDPOINTS.NETWORK_SCAN, {
        method: 'POST',
        headers: createAuthHeaders(user?.token),
        body: JSON.stringify({ url }),
      });

      if (response.error) {
        toast.error(response.error);
      } else if (response.data) {
        setResult(response.data);
        toast.success('Scan completed successfully');
        fetchHistory(); // Refresh history
      }
    } catch (error) {
      toast.error('An unexpected error occurred');
      console.error(error);
    } finally {
      setIsScanning(false);
    }
  };

  const handleDownloadPdf = async (scanId: string) => {
    if (!user) return;
    const toastId = toast.loading('Generating PDF...');
    try {
        const response = await fetch(API_ENDPOINTS.NETWORK_REPORT_PDF(scanId), {
            headers: createAuthHeaders(user.token),
        });

        if (response.ok) {
            const blob = await response.blob();
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `NetworkScan_Report_${scanId.substring(0,8)}.pdf`;
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

  const getScoreInsights = (score: number) => {
    if (score >= 90) return ['Excellent security posture', 'Strong configuration', 'No critical issues'];
    if (score >= 80) return ['Good security', 'Minor configuration tweaks needed', 'Review optional headers'];
    if (score >= 60) return ['Fair security', 'Missing some key headers', 'Check SSL settings'];
    if (score >= 40) return ['Poor security', 'Multiple missing headers', 'Potential port exposure'];
    return ['Critical vulnerabilities', 'Missing essential headers', 'Immediate action required'];
  };

  const getScoreColor = (score: number) => {
    if (score >= 90) return 'text-emerald-400';
    if (score >= 60) return 'text-amber-400';
    return 'text-red-400';
  };

  return (
    <div className="space-y-8 animate-in fade-in duration-500">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-white mb-2">Network Audit</h1>
        <p className="text-zinc-400">
          Deep-dive analysis of public-facing infrastructure, SSL, and data leakage.
        </p>
      </div>

      {/* Input Section */}
      <div className="bg-zinc-900/50 border border-zinc-800 rounded-xl p-6 shadow-xl backdrop-blur-sm">
        <form onSubmit={handleScan} className="flex flex-col md:flex-row gap-4">
          <input
            type="text"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="example.com"
            className="flex-1 bg-zinc-950 border border-zinc-800 rounded-lg px-4 py-3 text-white placeholder-zinc-600 focus:outline-none focus:ring-2 focus:ring-blue-500/50 focus:border-blue-500 transition-all"
            disabled={isScanning}
          />
          <button
            type="submit"
            disabled={isScanning}
            className={`px-8 py-3 rounded-lg font-semibold text-white shadow-lg transition-all flex items-center justify-center gap-2 ${
              isScanning
                ? 'bg-zinc-700 cursor-not-allowed'
                : 'bg-blue-600 hover:bg-blue-500 hover:shadow-blue-500/20 active:scale-95'
            }`}
          >
            {isScanning ? (
              <>
                <div className="w-5 h-5 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                Scanning...
              </>
            ) : (
              <>
                <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
                Scan Target
              </>
            )}
          </button>
        </form>
      </div>

      {/* Results Section */}
      {result && (
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 animate-in fade-in slide-in-from-bottom-4 duration-500">
          
          {/* Left Column: Score & Connection */}
          <div className="md:col-span-1 space-y-6">
              {/* Score Meter */}
              <SecurityMeter score={result.securityScore} />
              
              {/* Insights */}
              <div className="bg-zinc-900/50 border border-zinc-800 rounded-xl p-6">
                  <h3 className="text-sm font-medium text-zinc-400 mb-3 uppercase tracking-wider">Analysis Insights</h3>
                  <ul className="space-y-2">
                      {getScoreInsights(result.securityScore).map((insight, i) => (
                          <li key={i} className="flex items-center gap-2 text-zinc-300 text-sm">
                              <div className="w-1.5 h-1.5 rounded-full bg-blue-500"></div>
                              {insight}
                          </li>
                      ))}
                  </ul>
              </div>

              {/* Actions */}
              <button 
                onClick={() => handleDownloadPdf(result.id)}
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
                Connection Details
              </h3>
              <div className="p-4 bg-zinc-950/50 rounded-lg border border-zinc-800/50 flex flex-col gap-2">
                  <div className="flex justify-between items-center">
                    <span className="text-sm text-zinc-500">Target</span>
                    <span className="text-sm text-zinc-300 font-mono">{result.url}</span>
                  </div>
                  <div className="flex justify-between items-center">
                    <span className="text-sm text-zinc-500">Status</span>
                    <span className={`text-sm font-mono font-bold ${result.statusCode >= 200 && result.statusCode < 300 ? 'text-emerald-400' : 'text-red-400'}`}>
                        {result.statusCode} {result.statusReason}
                    </span>
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
              {result.openPorts.length > 0 ? (
                <div className="grid gap-3">
                  {result.openPorts.map((port) => {
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
              {result.missingSecurityHeaders.length > 0 ? (
                <div className="grid gap-3">
                  {result.missingSecurityHeaders.map((header) => {
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
                <div className="flex items-center gap-2 text-emerald-400 bg-emerald-500/5 p-4 rounded-lg border border-emerald-500/10">
                  <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                  </svg>
                  All critical headers are present.
                </div>
              )}
            </div>

            {/* PII Findings */}
            {result.piiFindings.length > 0 && (
                <div className="bg-zinc-900/50 border border-zinc-800 rounded-xl p-6 shadow-lg">
                <h3 className="text-lg font-medium text-white mb-4 flex items-center gap-2">
                    <svg className="w-5 h-5 text-pink-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
                    </svg>
                    PII / Data Leakage
                </h3>
                <div className="space-y-2">
                    {result.piiFindings.map((finding, idx) => (
                    <div key={idx} className="flex items-start gap-3 p-3 bg-pink-500/5 border border-pink-500/10 rounded-lg">
                        <div className="w-2 h-2 mt-1.5 rounded-full bg-pink-500 shrink-0" />
                        <span className="text-sm text-pink-200 font-mono break-all">{finding}</span>
                    </div>
                    ))}
                </div>
                </div>
            )}

          </div>
        </div>
      )}

      {/* History Section */}
      {history.length > 0 && (
          <div className="mt-12">
              <h2 className="text-xl font-bold text-white mb-6">Recent Scans</h2>
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                  {history.map(scan => (
                      <div key={scan.id} className="bg-zinc-900/30 border border-zinc-800 hover:border-zinc-700 p-4 rounded-lg transition-colors group">
                          <div className="flex justify-between items-start mb-3">
                              <span className="font-mono text-sm text-zinc-300 truncate w-2/3" title={scan.url}>{scan.url}</span>
                              <span className={`text-xs px-2 py-0.5 rounded ${scan.securityScore >= 80 ? 'bg-emerald-500/20 text-emerald-400' : 'bg-red-500/20 text-red-400'}`}>
                                  Score {scan.securityScore}
                              </span>
                          </div>
                          <div className="text-xs text-zinc-500 mb-4">
                              {new Date(scan.createdAt).toLocaleString()}
                          </div>
                          <div className="flex gap-2">
                              <button 
                                onClick={() => setResult(scan)}
                                className="flex-1 px-3 py-1.5 bg-zinc-800 hover:bg-zinc-700 text-xs text-white rounded transition-colors"
                              >
                                  View Details
                              </button>
                              <button 
                                onClick={() => handleDownloadPdf(scan.id)}
                                className="px-3 py-1.5 bg-zinc-800 hover:bg-zinc-700 text-xs text-white rounded transition-colors"
                                title="Download PDF"
                              >
                                  <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" />
                                  </svg>
                              </button>
                          </div>
                      </div>
                  ))}
              </div>
          </div>
      )}
    </div>
  );
}
