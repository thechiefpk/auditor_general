'use client';

import { useState, useEffect } from 'react';
import { useSearchParams } from 'next/navigation';
import { useAuth } from '@/app/context/AuthContext';
import { API_ENDPOINTS, createAuthHeaders } from '@/app/lib/api';
import toast from 'react-hot-toast';

interface TopViolation {
  ruleId: string;
  ruleName: string;
  category: string;
  count: number;
  suggestiveSolution: string;
  referenceUrl: string;
}

interface Statistics {
  violationsFound: number;
  violationsByCategory: { [key: string]: number };
  violationsBySeverity: { [key: string]: number };
  violationsByFileType: { [key: string]: number };
  filesScanned: number;
  scanDuration: number;
  topViolations: TopViolation[];
}

export default function StatisticsPage() {
  const { user } = useAuth();
  const searchParams = useSearchParams();
  const [scanId, setScanId] = useState('');
  const [stats, setStats] = useState<Statistics | null>(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    const idParam = searchParams.get('id');
    if (idParam) {
      setScanId(idParam);
      if (user?.token) {
        fetchStatistics(idParam);
      }
    }
  }, [searchParams, user?.token]);

  const fetchStatistics = async (idOverride?: string) => {
    const idToUse = idOverride || scanId;

    if (!idToUse.trim()) {
      toast.error('Please enter a scan ID');
      return;
    }

    setLoading(true);
    try {
      const response = await fetch(
        API_ENDPOINTS.STATS(idToUse),
        {
          headers: createAuthHeaders(user?.token),
        }
      );

      if (response.ok) {
        const data = await response.json();
        setStats(data);
        toast.success('Statistics loaded successfully');
      } else {
        const error = await response.json();
        toast.error(error.error || 'Failed to load statistics');
      }
    } catch (error) {
      console.error('Error fetching statistics:', error);
      toast.error('An error occurred while fetching statistics');
    } finally {
      setLoading(false);
    }
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    fetchStatistics();
  };

  const getSeverityColor = (severity: string) => {
    const colors: { [key: string]: string } = {
      critical: 'from-red-500 to-red-600',
      high: 'from-orange-500 to-orange-600',
      medium: 'from-amber-500 to-amber-600',
      low: 'from-blue-500 to-blue-600',
      info: 'from-zinc-500 to-zinc-600',
    };
    return colors[severity.toLowerCase()] || colors.info;
  };

  const getCategoryColor = (index: number) => {
    // Classic premium colors - avoiding purple/pink
    const colors = [
      'from-zinc-500 to-zinc-600',
      'from-slate-500 to-slate-600',
      'from-neutral-500 to-neutral-600',
      'from-stone-500 to-stone-600',
      'from-gray-500 to-gray-600',
    ];
    return colors[index % colors.length];
  };

  const calculatePercentage = (value: number, total: number) => {
    if (total === 0) return '0.00';
    const percentage = (value / total) * 100;
    // If it's very small but not zero (e.g. 0.001%), show < 0.01 or something?
    // User asked for "accurate %... even in double format". toFixed(2) is standard.
    return percentage.toFixed(2);
  };

  const exportCsv = async () => {
    if (!scanId) return;
    try {
      const response = await fetch(API_ENDPOINTS.REPORT_CSV(scanId), {
        headers: createAuthHeaders(user?.token),
      });

      if (!response.ok) throw new Error('Export failed');

      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `report_${scanId}.csv`;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);
      toast.success('Report exported successfully');
    } catch (error) {
      toast.error('Failed to export CSV');
    }
  };

  const exportPdf = async () => {
    if (!scanId) return;
    try {
        const response = await fetch(API_ENDPOINTS.REPORT_PDF(scanId), {
            headers: createAuthHeaders(user?.token),
        });

        if (!response.ok) {
            const errorData = await response.json().catch(() => ({}));
            throw new Error(errorData.error || 'Export failed');
        }

        const blob = await response.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `ComplianceReport_${scanId}.pdf`;
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
        document.body.removeChild(a);
        toast.success('PDF Report downloaded successfully');
    } catch (error) {
        toast.error(error instanceof Error ? error.message : 'Failed to download PDF report');
        console.error(error);
    }
  };

  // Helper for Conic Gradient
  const getPieGradient = (data: { [key: string]: number }) => {
    const total = Object.values(data).reduce((a, b) => a + b, 0);
    if (total === 0) return 'conic-gradient(#3f3f46 0% 100%)';

    let current = 0;
    const parts = Object.entries(data).map(([key, value], index) => {
        const pct = (value / total) * 100;
        const start = current;
        current += pct;
        // Simple color mapping
        const colors = ['#3b82f6', '#10b981', '#ef4444', '#f59e0b', '#8b5cf6', '#ec4899', '#6366f1'];
        const color = colors[index % colors.length];
        return `${color} ${start}% ${current}%`;
    });
    return `conic-gradient(${parts.join(', ')})`;
  };

  return (
    <div className="space-y-6 animate-in fade-in duration-500 print:space-y-4">
      <style jsx global>{`
        @media print {
            @page { margin: 2cm; }
            .no-print { display: none !important; }
            body { background: white; color: black; font-family: sans-serif; }
            .print-black { color: black !important; }
            /* Hide sidebar/nav if possible - usually handled by layout but we can try */
            nav, aside, header { display: none !important; }
            
            /* Force background graphics */
            * {
                -webkit-print-color-adjust: exact !important;
                print-color-adjust: exact !important;
            }

            /* Break pages properly */
            .break-before { page-break-before: always; }
            .avoid-break { page-break-inside: avoid; }
        }
      `}</style>
      {/* Page Header */}
      <div className="bg-zinc-900/40 backdrop-blur-sm border border-zinc-800 rounded-xl p-6 shadow-lg flex justify-between items-center print:border-none print:shadow-none print:p-0 print:mb-8">
        <div>
            <div className="hidden print:block text-sm text-gray-500 mb-2">SecureSoft Audit Report</div>
            <h1 className="text-3xl font-bold text-white mb-2 flex items-center gap-3 print:text-black">
            <svg className="w-8 h-8 text-zinc-100 print:text-black" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
            </svg>
            Scan Statistics & Analysis
            </h1>
            <p className="text-zinc-400 print:text-gray-600">
            Detailed compliance and security analysis generated on {new Date().toLocaleDateString()}
            </p>
        </div>
        {stats && (
            <div className="flex gap-2 no-print">
                <button onClick={exportCsv} className="px-4 py-2 bg-zinc-800 hover:bg-zinc-700 text-white rounded-lg flex items-center gap-2">
                    <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" /></svg>
                    Export CSV
                </button>
                <button onClick={exportPdf} className="px-4 py-2 bg-zinc-100 hover:bg-white text-black rounded-lg flex items-center gap-2">
                    <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M17 17h2a2 2 0 002-2v-4a2 2 0 00-2-2H5a2 2 0 00-2 2v4a2 2 0 002 2h2m2 4h6a2 2 0 002-2v-4a2 2 0 00-2-2H9a2 2 0 00-2 2v4a2 2 0 002 2zm8-12V5a2 2 0 00-2-2H9a2 2 0 00-2 2v4h10z" /></svg>
                    Download PDF
                </button>
            </div>
        )}
      </div>

      {/* Search Form */}
      <div className="bg-zinc-900/40 backdrop-blur-sm border border-zinc-800 rounded-xl p-6 shadow-lg no-print">
        <form onSubmit={handleSubmit} className="flex gap-4">
          <input
            type="text"
            value={scanId}
            onChange={(e) => setScanId(e.target.value)}
            placeholder="Enter scan ID (GUID)"
            className="flex-1 rounded-lg border border-zinc-800 bg-zinc-900/50 px-4 py-2 text-white placeholder-zinc-500 focus:border-zinc-500 focus:ring-2 focus:ring-zinc-500/20 focus:outline-none transition-all"
          />
          <button
            type="submit"
            disabled={loading}
            className="px-6 py-2 bg-zinc-100 hover:bg-zinc-200 disabled:bg-zinc-800 disabled:text-zinc-600 text-black font-semibold rounded-lg shadow-lg hover:shadow-zinc-500/10 transition-all disabled:cursor-not-allowed flex items-center gap-2"
          >
            {loading ? (
              <>
                <svg className="animate-spin h-5 w-5 text-black" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                </svg>
                Loading...
              </>
            ) : (
              <>
                <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
                </svg>
                Get Statistics
              </>
            )}
          </button>
        </form>
      </div>

      {/* Statistics Display */}
      {stats && (
        <div className="space-y-6">
          {/* Overview Cards */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
            <div className="bg-zinc-900/40 backdrop-blur-sm border border-zinc-800 rounded-xl p-6 shadow-lg border-l-4 border-l-blue-500">
              <div className="text-blue-500 mb-2">
                <svg className="w-8 h-8" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
                </svg>
              </div>
              <p className="text-zinc-400 text-sm mb-1">Total Violations</p>
              <p className="text-4xl font-bold text-white">{stats.violationsFound}</p>
            </div>

            <div className="bg-zinc-900/40 backdrop-blur-sm border border-zinc-800 rounded-xl p-6 shadow-lg border-l-4 border-l-emerald-500">
              <div className="text-emerald-500 mb-2">
                <svg className="w-8 h-8" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                </svg>
              </div>
              <p className="text-zinc-400 text-sm mb-1">Files Scanned</p>
              <p className="text-4xl font-bold text-white">{stats.filesScanned}</p>
            </div>

            <div className="bg-zinc-900/40 backdrop-blur-sm border border-zinc-800 rounded-xl p-6 shadow-lg border-l-4 border-l-zinc-500">
              <div className="text-zinc-500 mb-2">
                <svg className="w-8 h-8" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
              </div>
              <p className="text-zinc-400 text-sm mb-1">Scan Duration</p>
              <p className="text-4xl font-bold text-white">{stats.scanDuration ? stats.scanDuration.toFixed(2) : 0}s</p>
            </div>

            <div className="bg-zinc-900/40 backdrop-blur-sm border border-zinc-800 rounded-xl p-6 shadow-lg border-l-4 border-l-amber-500">
              <div className="text-amber-500 mb-2">
                <svg className="w-8 h-8" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M7 7h.01M7 3h5c.512 0 1.024.195 1.414.586l7 7a2 2 0 010 2.828l-7 7a2 2 0 01-2.828 0l-7-7A1.994 1.994 0 013 12V7a4 4 0 014-4z" />
                </svg>
              </div>
              <p className="text-zinc-400 text-sm mb-1">Categories</p>
              <p className="text-4xl font-bold text-white">
                {Object.keys(stats.violationsByCategory || {}).length}
              </p>
            </div>
          </div>

          {/* Violations by File Type (Histogram) */}
          {stats.violationsByFileType && (
            <div className="bg-zinc-900/40 backdrop-blur-sm border border-zinc-800 rounded-xl p-6 shadow-lg print:border-none print:shadow-none">
              <h2 className="text-2xl font-bold text-white mb-6 print:text-black">
                Violations by File Type (Histogram)
              </h2>
              <div className="space-y-4">
                {Object.entries(stats.violationsByFileType)
                  .sort(([, a], [, b]) => (b as number) - (a as number))
                  .map(([ext, count]) => {
                    const maxCount = Math.max(...Object.values(stats.violationsByFileType));
                    const percentageOfMax = maxCount > 0 ? (count / maxCount) * 100 : 0;
                    
                    return (
                      <div key={ext}>
                        <div className="flex items-center justify-between mb-2">
                          <span className="text-sm font-semibold text-zinc-300 capitalize print:text-black">
                            {ext}
                          </span>
                          <span className="text-sm font-bold text-white print:text-black">
                             {count} violations
                          </span>
                        </div>
                        <div className="h-4 bg-zinc-800 rounded-full overflow-hidden border border-zinc-700 print:border-gray-300 print:bg-gray-100">
                          <div
                            className="h-full bg-blue-500 rounded-full transition-all duration-500 print:bg-none print:bg-black"
                            style={{ width: `${percentageOfMax}%` }}
                          />
                        </div>
                      </div>
                    );
                  })}
              </div>
            </div>
          )}

          {/* Violations by Category */}
          {stats.violationsByCategory && (
            <div className="bg-zinc-900/40 backdrop-blur-sm border border-zinc-800 rounded-xl p-6 shadow-lg print:border-none print:shadow-none print:break-before-page">
              <h2 className="text-2xl font-bold text-white mb-6 print:text-black">
                Violations by Category (Pie Chart)
              </h2>
              <div className="flex flex-col md:flex-row gap-8 items-center justify-center">
                  {/* Pie Chart */}
                  <div className="w-64 h-64 flex-shrink-0 rounded-full relative shadow-xl" 
                       style={{ background: getPieGradient(stats.violationsByCategory) }}>
                      {/* Donut hole */}
                      <div className="absolute inset-8 bg-zinc-900 rounded-full print:bg-white flex items-center justify-center">
                          <div className="text-center">
                              <p className="text-zinc-400 text-sm">Total</p>
                              <p className="text-3xl font-bold text-white print:text-black">{stats.violationsFound}</p>
                          </div>
                      </div>
                  </div>

                  {/* Legend / Grid */}
                  <div className="flex-1 w-full grid grid-cols-1 sm:grid-cols-2 gap-4">
                    {Object.entries(stats.violationsByCategory)
                    .sort(([, a], [, b]) => (b as number) - (a as number))
                    .map(([category, count], index) => {
                        const percentage = calculatePercentage(
                        count as number,
                        stats.violationsFound
                        );
                        const colors = ['#3b82f6', '#10b981', '#ef4444', '#f59e0b', '#8b5cf6', '#ec4899', '#6366f1'];
                        const color = colors[index % colors.length];
                        
                        return (
                        <div
                            key={category}
                            className="bg-zinc-900/30 border border-zinc-800 rounded-lg p-4 print:border-gray-200 print:bg-white"
                        >
                            <div className="flex items-center gap-3 mb-2">
                                <div className="w-3 h-3 rounded-full" style={{ backgroundColor: color }}></div>
                                <h3 className="font-semibold text-white print:text-black truncate">
                                    {category}
                                </h3>
                            </div>
                            <div className="flex justify-between items-end">
                                <span className="text-2xl font-bold text-white print:text-black">
                                    {count}
                                </span>
                                <span className="text-sm text-zinc-400 print:text-gray-600">
                                    {percentage}%
                                </span>
                            </div>
                        </div>
                        );
                    })}
                  </div>
              </div>
            </div>
          )}

          {/* Summary Table */}
          <div className="bg-zinc-900/40 backdrop-blur-sm border border-zinc-800 rounded-xl p-6 shadow-lg avoid-break">
            <h2 className="text-2xl font-bold text-white mb-6 print:text-black">
              Scan Summary
            </h2>
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead className="border-b border-zinc-800 print:border-gray-200">
                  <tr>
                    <th className="text-left py-3 px-4 text-sm font-semibold text-zinc-300 print:text-gray-700">
                      Metric
                    </th>
                    <th className="text-right py-3 px-4 text-sm font-semibold text-zinc-300 print:text-gray-700">
                      Value
                    </th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-zinc-800 print:divide-gray-200">
                  <tr>
                    <td className="py-3 px-4 text-sm text-white print:text-black">
                      Total Violations
                    </td>
                    <td className="py-3 px-4 text-sm text-right font-semibold text-white print:text-black">
                      {stats.violationsFound}
                    </td>
                  </tr>
                  <tr>
                    <td className="py-3 px-4 text-sm text-white print:text-black">
                      Files Scanned
                    </td>
                    <td className="py-3 px-4 text-sm text-right font-semibold text-white print:text-black">
                      {stats.filesScanned}
                    </td>
                  </tr>
                  <tr>
                    <td className="py-3 px-4 text-sm text-white print:text-black">
                      Average Violations per File
                    </td>
                    <td className="py-3 px-4 text-sm text-right font-semibold text-white print:text-black">
                      {stats.filesScanned > 0
                        ? (stats.violationsFound / stats.filesScanned).toFixed(2)
                        : '0'}
                    </td>
                  </tr>
                  <tr>
                    <td className="py-3 px-4 text-sm text-white print:text-black">
                      Scan Duration
                    </td>
                    <td className="py-3 px-4 text-sm text-right font-semibold text-white print:text-black">
                      {stats.scanDuration ? stats.scanDuration.toFixed(2) : 0}s
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>

          {/* Top Violations & Recommendations (Print Focused) */}
          {stats.topViolations && stats.topViolations.length > 0 && (
            <div className="bg-zinc-900/40 backdrop-blur-sm border border-zinc-800 rounded-xl p-6 shadow-lg break-before">
                <h2 className="text-2xl font-bold text-white mb-6 print:text-black flex items-center gap-2">
                    <svg className="w-6 h-6 text-emerald-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                    </svg>
                    Top Findings & Recommendations
                </h2>
                <div className="space-y-6">
                    {stats.topViolations.map((violation, idx) => (
                        <div key={idx} className="bg-zinc-900/50 border border-zinc-700 rounded-lg p-6 print:bg-white print:border-gray-200 avoid-break">
                            <div className="flex justify-between items-start mb-4">
                                <div>
                                    <div className="flex items-center gap-2 mb-1">
                                        <span className={`px-2 py-0.5 rounded text-xs font-bold uppercase ${
                                            violation.category === 'HIPAA' || violation.category === 'Financial' ? 'bg-red-500/20 text-red-400 print:text-red-700 print:bg-red-50' :
                                            violation.category === 'Security' || violation.category === 'GDPR' ? 'bg-orange-500/20 text-orange-400 print:text-orange-700 print:bg-orange-50' :
                                            'bg-blue-500/20 text-blue-400 print:text-blue-700 print:bg-blue-50'
                                        }`}>
                                            {violation.category}
                                        </span>
                                        <h3 className="text-lg font-bold text-white print:text-black">
                                            {violation.ruleName}
                                        </h3>
                                    </div>
                                    <p className="text-sm text-zinc-400 print:text-gray-600 font-mono">
                                        ID: {violation.ruleId}
                                    </p>
                                </div>
                                <div className="text-right">
                                    <span className="block text-2xl font-bold text-white print:text-black">
                                        {violation.count}
                                    </span>
                                    <span className="text-xs text-zinc-500 uppercase">Occurrences</span>
                                </div>
                            </div>
                            
                            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-4 pt-4 border-t border-zinc-700 print:border-gray-200">
                                <div>
                                    <h4 className="text-sm font-semibold text-zinc-300 mb-1 print:text-gray-800">Suggestive Solution:</h4>
                                    <p className="text-sm text-zinc-400 print:text-gray-600 leading-relaxed">
                                        {violation.suggestiveSolution}
                                    </p>
                                </div>
                                <div>
                                    <h4 className="text-sm font-semibold text-zinc-300 mb-1 print:text-gray-800">Reference:</h4>
                                    <a href={violation.referenceUrl} target="_blank" rel="noopener noreferrer" className="text-sm text-blue-400 hover:text-blue-300 print:text-blue-700 underline break-all">
                                        {violation.referenceUrl}
                                    </a>
                                </div>
                            </div>
                        </div>
                    ))}
                </div>
            </div>
          )}
        </div>
      )}

      {/* Empty State */}
      {!loading && !stats && (
        <div className="bg-zinc-900/40 backdrop-blur-sm border border-zinc-800 rounded-xl p-12 text-center shadow-lg">
          <div className="text-6xl mb-4 flex justify-center">
            <svg className="w-16 h-16 text-zinc-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
            </svg>
          </div>
          <h3 className="text-xl font-semibold text-white mb-2">
            No Statistics Available
          </h3>
          <p className="text-zinc-400 max-w-md mx-auto">
            Enter a scan ID above to view detailed statistics and analytics
          </p>
        </div>
      )}
    </div>
  );
}
