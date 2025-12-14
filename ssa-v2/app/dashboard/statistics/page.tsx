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
      medium: 'from-yellow-500 to-yellow-600',
      low: 'from-blue-500 to-blue-600',
      info: 'from-slate-500 to-slate-600',
    };
    return colors[severity.toLowerCase()] || colors.info;
  };

  const getCategoryColor = (index: number) => {
    const colors = [
      'from-purple-500 to-purple-600',
      'from-pink-500 to-pink-600',
      'from-indigo-500 to-indigo-600',
      'from-teal-500 to-teal-600',
      'from-emerald-500 to-emerald-600',
    ];
    return colors[index % colors.length];
  };

  const calculatePercentage = (value: number, total: number) => {
    return total > 0 ? Math.round((value / total) * 100) : 0;
  };

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-lg">
        <h1 className="text-3xl font-bold text-white mb-2">
          📈 Scan Statistics
        </h1>
        <p className="text-slate-400">
          View detailed statistics and analytics from your security scans
        </p>
      </div>

      {/* Search Form */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-lg">
        <form onSubmit={handleSubmit} className="flex gap-4">
          <input
            type="text"
            value={scanId}
            onChange={(e) => setScanId(e.target.value)}
            placeholder="Enter scan ID (GUID)"
            className="flex-1 rounded-lg border border-slate-700 bg-slate-800 px-4 py-2 text-white placeholder-slate-500 focus:border-blue-500 focus:ring-2 focus:ring-blue-500 focus:outline-none transition-all"
          />
          <button
            type="submit"
            disabled={loading}
            className="px-6 py-2 bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-700 hover:to-indigo-700 disabled:from-slate-700 disabled:to-slate-800 disabled:text-slate-500 text-white font-semibold rounded-lg shadow-lg hover:shadow-blue-500/25 transition-all disabled:cursor-not-allowed"
          >
            {loading ? 'Loading...' : 'Get Statistics'}
          </button>
        </form>
      </div>

      {/* Statistics Display */}
      {stats && (
        <div className="space-y-6">
          {/* Overview Cards */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-lg border-l-4 border-l-blue-500">
              <div className="text-blue-500 text-3xl mb-2">📊</div>
              <p className="text-slate-400 text-sm mb-1">Total Violations</p>
              <p className="text-4xl font-bold text-white">{stats.totalViolations}</p>
            </div>

            <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-lg border-l-4 border-l-emerald-500">
              <div className="text-emerald-500 text-3xl mb-2">📁</div>
              <p className="text-slate-400 text-sm mb-1">Files Scanned</p>
              <p className="text-4xl font-bold text-white">{stats.filesScanned}</p>
            </div>

            <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-lg border-l-4 border-l-purple-500">
              <div className="text-purple-500 text-3xl mb-2">⏱️</div>
              <p className="text-slate-400 text-sm mb-1">Scan Duration</p>
              <p className="text-4xl font-bold text-white">{stats.scanDuration}s</p>
            </div>

            <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-lg border-l-4 border-l-orange-500">
              <div className="text-orange-500 text-3xl mb-2">🏷️</div>
              <p className="text-slate-400 text-sm mb-1">Categories</p>
              <p className="text-4xl font-bold text-white">
                {Object.keys(stats.violationsByCategory || {}).length}
              </p>
            </div>
          </div>

          {/* Violations by Severity */}
          {stats.violationsBySeverity && (
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-lg">
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
                          <span className="text-sm font-semibold text-slate-300 capitalize">
                            {severity}
                          </span>
                          <div className="flex items-center gap-3">
                            <span className="text-sm text-slate-400">
                              {count} violations
                            </span>
                            <span className="text-sm font-bold text-white">
                              {percentage}%
                            </span>
                          </div>
                        </div>
                        <div className="h-4 bg-slate-800 rounded-full overflow-hidden border border-slate-700">
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
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-lg">
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
                        className="bg-slate-800/50 border border-slate-700 rounded-lg p-4"
                      >
                        <div className="flex items-center justify-between mb-3">
                          <h3 className="font-semibold text-white">
                            {category}
                          </h3>
                          <span className="text-2xl font-bold text-white">
                            {count}
                          </span>
                        </div>
                        <div className="h-3 bg-slate-700 rounded-full overflow-hidden">
                          <div
                            className={`h-full bg-gradient-to-r ${getCategoryColor(
                              index
                            )} rounded-full transition-all duration-500`}
                            style={{ width: `${percentage}%` }}
                          />
                        </div>
                        <p className="text-xs text-slate-400 mt-2">
                          {percentage}% of total violations
                        </p>
                      </div>
                    );
                  })}
              </div>
            </div>
          )}

          {/* Summary Table */}
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-lg">
            <h2 className="text-2xl font-bold text-white mb-6">
              Scan Summary
            </h2>
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead className="border-b border-slate-800">
                  <tr>
                    <th className="text-left py-3 px-4 text-sm font-semibold text-slate-300">
                      Metric
                    </th>
                    <th className="text-right py-3 px-4 text-sm font-semibold text-slate-300">
                      Value
                    </th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800">
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
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-12 text-center">
          <div className="text-6xl mb-4">📈</div>
          <h3 className="text-xl font-semibold text-white mb-2">
            No Statistics Available
          </h3>
          <p className="text-slate-400">
            Enter a scan ID above to view detailed statistics and analytics
          </p>
        </div>
      )}
    </div>
  );
}
