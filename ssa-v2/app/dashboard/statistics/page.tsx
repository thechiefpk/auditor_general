'use client';

import { useState, useEffect } from 'react';
import { useAuth } from '@/app/context/AuthContext';
import { API_ENDPOINTS, createAuthHeaders } from '@/app/lib/api';
import toast from 'react-hot-toast';

interface Statistics {
  totalViolations: number;
  violationsByCategory: { [key: string]: number };
  violationsBySeverity: { [key: string]: number };
  filesScanned: number;
  scanDuration: number;
}

export default function StatisticsPage() {
  const { user } = useAuth();
  const [scanId, setScanId] = useState('');
  const [stats, setStats] = useState<Statistics | null>(null);
  const [loading, setLoading] = useState(false);

  const fetchStatistics = async () => {
    if (!scanId.trim()) {
      toast.error('Please enter a scan ID');
      return;
    }

    setLoading(true);
    try {
      const response = await fetch(
        API_ENDPOINTS.STATS(scanId),
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
    return total > 0 ? Math.round((value / total) * 100) : 0;
  };

  return (
    <div className="space-y-6 animate-in fade-in duration-500">
      {/* Page Header */}
      <div className="bg-zinc-900/40 backdrop-blur-sm border border-zinc-800 rounded-xl p-6 shadow-lg">
        <h1 className="text-3xl font-bold text-white mb-2 flex items-center gap-3">
          <svg className="w-8 h-8 text-zinc-100" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
          </svg>
          Scan Statistics
        </h1>
        <p className="text-zinc-400">
          View detailed statistics and analytics from your security scans
        </p>
      </div>

      {/* Search Form */}
      <div className="bg-zinc-900/40 backdrop-blur-sm border border-zinc-800 rounded-xl p-6 shadow-lg">
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
              <p className="text-4xl font-bold text-white">{stats.totalViolations}</p>
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
              <p className="text-4xl font-bold text-white">{stats.scanDuration}s</p>
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

          {/* Violations by Severity */}
          {stats.violationsBySeverity && (
            <div className="bg-zinc-900/40 backdrop-blur-sm border border-zinc-800 rounded-xl p-6 shadow-lg">
              <h2 className="text-2xl font-bold text-white mb-6">
                Violations by Severity
              </h2>
              <div className="space-y-4">
                {Object.entries(stats.violationsBySeverity)
                  .sort(([, a], [, b]) => (b as number) - (a as number))
                  .map(([severity, count]) => {
                    const percentage = calculatePercentage(
                      count as number,
                      stats.totalViolations
                    );
                    return (
                      <div key={severity}>
                        <div className="flex items-center justify-between mb-2">
                          <span className="text-sm font-semibold text-zinc-300 capitalize">
                            {severity}
                          </span>
                          <div className="flex items-center gap-3">
                            <span className="text-sm text-zinc-400">
                              {count} violations
                            </span>
                            <span className="text-sm font-bold text-white">
                              {percentage}%
                            </span>
                          </div>
                        </div>
                        <div className="h-4 bg-zinc-800 rounded-full overflow-hidden border border-zinc-700">
                          <div
                            className={`h-full bg-gradient-to-r ${getSeverityColor(
                              severity
                            )} rounded-full transition-all duration-500`}
                            style={{ width: `${percentage}%` }}
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
            <div className="bg-zinc-900/40 backdrop-blur-sm border border-zinc-800 rounded-xl p-6 shadow-lg">
              <h2 className="text-2xl font-bold text-white mb-6">
                Violations by Category
              </h2>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                {Object.entries(stats.violationsByCategory)
                  .sort(([, a], [, b]) => (b as number) - (a as number))
                  .map(([category, count], index) => {
                    const percentage = calculatePercentage(
                      count as number,
                      stats.totalViolations
                    );
                    return (
                      <div
                        key={category}
                        className="bg-zinc-900/30 border border-zinc-800 rounded-lg p-4"
                      >
                        <div className="flex items-center justify-between mb-3">
                          <h3 className="font-semibold text-white">
                            {category}
                          </h3>
                          <span className="text-2xl font-bold text-white">
                            {count}
                          </span>
                        </div>
                        <div className="h-3 bg-zinc-800 rounded-full overflow-hidden">
                          <div
                            className={`h-full bg-gradient-to-r ${getCategoryColor(
                              index
                            )} rounded-full transition-all duration-500`}
                            style={{ width: `${percentage}%` }}
                          />
                        </div>
                        <p className="text-xs text-zinc-400 mt-2">
                          {percentage}% of total violations
                        </p>
                      </div>
                    );
                  })}
              </div>
            </div>
          )}

          {/* Summary Table */}
          <div className="bg-zinc-900/40 backdrop-blur-sm border border-zinc-800 rounded-xl p-6 shadow-lg">
            <h2 className="text-2xl font-bold text-white mb-6">
              Scan Summary
            </h2>
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead className="border-b border-zinc-800">
                  <tr>
                    <th className="text-left py-3 px-4 text-sm font-semibold text-zinc-300">
                      Metric
                    </th>
                    <th className="text-right py-3 px-4 text-sm font-semibold text-zinc-300">
                      Value
                    </th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-zinc-800">
                  <tr>
                    <td className="py-3 px-4 text-sm text-white">
                      Total Violations
                    </td>
                    <td className="py-3 px-4 text-sm text-right font-semibold text-white">
                      {stats.totalViolations}
                    </td>
                  </tr>
                  <tr>
                    <td className="py-3 px-4 text-sm text-white">
                      Files Scanned
                    </td>
                    <td className="py-3 px-4 text-sm text-right font-semibold text-white">
                      {stats.filesScanned}
                    </td>
                  </tr>
                  <tr>
                    <td className="py-3 px-4 text-sm text-white">
                      Average Violations per File
                    </td>
                    <td className="py-3 px-4 text-sm text-right font-semibold text-white">
                      {stats.filesScanned > 0
                        ? (stats.totalViolations / stats.filesScanned).toFixed(2)
                        : '0'}
                    </td>
                  </tr>
                  <tr>
                    <td className="py-3 px-4 text-sm text-white">
                      Scan Duration
                    </td>
                    <td className="py-3 px-4 text-sm text-right font-semibold text-white">
                      {stats.scanDuration}s
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>
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
