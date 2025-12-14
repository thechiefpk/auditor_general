'use client';

import { useState, useEffect } from 'react';
import { useAuth } from '@/app/context/AuthContext';
import { API_ENDPOINTS, createAuthHeaders, apiRequest } from '@/app/lib/api';
import toast from 'react-hot-toast';

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
  const [reports, setReports] = useState<ScanReport[]>([]);
  const [loading, setLoading] = useState(false);
  const [selectedReport, setSelectedReport] = useState<ScanReport | null>(null);
  const [showViolationsModal, setShowViolationsModal] = useState(false);
  const [selectedViolation, setSelectedViolation] = useState<Violation | null>(null);
  
  // Pagination for violations in modal
  const [currentPage, setCurrentPage] = useState(1);
  const [violationsPerPage] = useState(50);
  const [searchTerm, setSearchTerm] = useState('');
  const [categoryFilter, setCategoryFilter] = useState('');

  useEffect(() => {
    fetchMyReports();
  }, []);

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
        toast.success(`Loaded ${result.data.length} scan reports`);
        console.log('Reports loaded:', result.data);
      }
    } catch (error) {
      console.error('Unexpected error fetching reports:', error);
      toast.error('An unexpected error occurred');
    } finally {
      setLoading(false);
    }
  };

  const openViolationsModal = (report: ScanReport) => {
    setSelectedReport(report);
    setShowViolationsModal(true);
    setCurrentPage(1);
    setSearchTerm('');
    setCategoryFilter('');
  };

  const closeViolationsModal = () => {
    setShowViolationsModal(false);
    setSelectedReport(null);
    setSelectedViolation(null);
  };

  const getCategoryColor = (category: string) => {
    const colors: { [key: string]: string } = {
      'GDPR': 'bg-blue-500',
      'HIPAA': 'bg-purple-500',
      'Security': 'bg-red-500',
      'PCI-DSS': 'bg-emerald-500',
      'Compliance': 'bg-yellow-500',
    };
    return colors[category] || 'bg-slate-500';
  };

  const getCategoryBreakdown = (violations: Violation[]) => {
    const breakdown: { [key: string]: number } = {};
    violations.forEach(v => {
      const category = v.violatedRule.category;
      breakdown[category] = (breakdown[category] || 0) + 1;
    });
    return breakdown;
  };

  // Filter and paginate violations
  const getFilteredViolations = () => {
    if (!selectedReport) return [];

    let filtered = selectedReport.violations;

    // Apply search filter
    if (searchTerm) {
      filtered = filtered.filter(v =>
        v.filePath.toLowerCase().includes(searchTerm.toLowerCase()) ||
        v.violatedRule.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
        v.matchedText.toLowerCase().includes(searchTerm.toLowerCase())
      );
    }

    // Apply category filter
    if (categoryFilter) {
      filtered = filtered.filter(v => v.violatedRule.category === categoryFilter);
    }

    return filtered;
  };

  const getPaginatedViolations = () => {
    const filtered = getFilteredViolations();
    const startIndex = (currentPage - 1) * violationsPerPage;
    const endIndex = startIndex + violationsPerPage;
    return filtered.slice(startIndex, endIndex);
  };

  const totalFilteredViolations = getFilteredViolations().length;
  const totalPages = Math.ceil(totalFilteredViolations / violationsPerPage);

  const formatDate = (dateString?: string) => {
    if (!dateString) return 'N/A';
    return new Date(dateString).toLocaleString();
  };

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-lg">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-bold text-white mb-2">
              📄 My Scan Reports
            </h1>
            <p className="text-slate-400">
              View all your security compliance scan reports
            </p>
          </div>
          <button
            onClick={fetchMyReports}
            disabled={loading}
            className="px-4 py-2 bg-blue-600 hover:bg-blue-500 disabled:bg-slate-700 text-white font-semibold rounded-lg shadow-lg shadow-blue-500/25 transition-all focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 focus:ring-offset-slate-900"
          >
            {loading ? 'Loading...' : '🔄 Refresh'}
          </button>
        </div>
      </div>

      {/* Loading State */}
      {loading && (
        <div className="flex items-center justify-center py-12">
          <div className="animate-spin h-12 w-12 border-4 border-blue-500 border-t-transparent rounded-full"></div>
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
                className="bg-slate-900 border border-slate-800 rounded-xl shadow-lg hover:shadow-xl hover:border-slate-700 transition-all duration-300 overflow-hidden group cursor-pointer"
                onClick={() => openViolationsModal(report)}
              >
                {/* Report Header */}
                <div className="bg-gradient-to-r from-blue-600 to-indigo-600 p-4 text-white">
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-sm font-medium opacity-90">
                      #{report.reportId.substring(0, 8)}
                    </span>
                    <span className="text-xs bg-white/20 px-2 py-1 rounded-full">
                      {formatDate(report.scanDate)}
                    </span>
                  </div>
                  <h3 className="text-xl font-bold mb-1 truncate">
                    {report.scanPath || 'Project Scan'}
                  </h3>
                </div>

                {/* Report Content */}
                <div className="p-6">
                  <div className="flex items-center justify-between mb-6">
                    <div className="text-center">
                      <p className="text-sm text-slate-400 mb-1">Files</p>
                      <p className="text-2xl font-bold text-white">
                        {report.filesScanned}
                      </p>
                    </div>
                    <div className="h-10 w-px bg-slate-700"></div>
                    <div className="text-center">
                      <p className="text-sm text-slate-400 mb-1">Violations</p>
                      <p className={`text-2xl font-bold ${
                        report.violationsFound > 0 ? 'text-red-400' : 'text-emerald-400'
                      }`}>
                        {report.violationsFound}
                      </p>
                    </div>
                  </div>

                  {/* Categories */}
                  <div className="space-y-3">
                    <p className="text-sm font-medium text-slate-400">
                      Top Categories
                    </p>
                    <div className="space-y-2">
                      {Object.entries(categoryBreakdown)
                        .slice(0, 3)
                        .map(([category, count]) => (
                          <div key={category} className="flex items-center justify-between text-sm">
                            <span className="flex items-center gap-2 text-slate-300">
                              <span className={`w-2 h-2 rounded-full ${getCategoryColor(category)}`}></span>
                              {category}
                            </span>
                            <span className="font-semibold text-white">{count}</span>
                          </div>
                        ))}
                    </div>
                  </div>

                  {/* View Details Button */}
                  <div className="mt-6 pt-4 border-t border-slate-700 flex justify-end">
                    <span className="text-blue-400 text-sm font-medium group-hover:text-blue-300 transition-colors flex items-center gap-1">
                      View Full Report →
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
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-12 text-center shadow-lg">
          <div className="text-6xl mb-4">🔍</div>
          <h2 className="text-2xl font-bold text-white mb-2">
            No Scan Reports Yet
          </h2>
          <p className="text-slate-400 mb-6 max-w-md mx-auto">
            Run your first security scan to identify vulnerabilities and compliance issues in your codebase.
          </p>
          <a
            href="/dashboard/scan"
            className="inline-flex items-center gap-2 px-6 py-3 bg-blue-600 hover:bg-blue-500 text-white font-semibold rounded-lg shadow-lg shadow-blue-500/25 transition-all"
          >
            Start New Scan
          </a>
        </div>
      )}

      {/* Violations Modal */}
      {showViolationsModal && selectedReport && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl shadow-2xl w-full max-w-6xl max-h-[90vh] flex flex-col">
            {/* Modal Header */}
            <div className="flex items-center justify-between p-6 border-b border-slate-800">
              <div>
                <h2 className="text-2xl font-bold text-white flex items-center gap-3">
                  Report Details
                  <span className="text-sm font-normal text-slate-400 bg-slate-800 px-3 py-1 rounded-full">
                    #{selectedReport.reportId.substring(0, 8)}
                  </span>
                </h2>
                <p className="text-slate-400 mt-1">
                  {selectedReport.scanPath || 'Project Scan'} • {formatDate(selectedReport.scanDate)}
                </p>
              </div>
              <button
                onClick={closeViolationsModal}
                className="text-slate-400 hover:text-white transition-colors text-2xl"
              >
                ×
              </button>
            </div>

            {/* Filters & Controls */}
            <div className="p-6 border-b border-slate-800 bg-slate-800/30">
              <div className="flex flex-col md:flex-row gap-4 justify-between">
                <div className="flex flex-col md:flex-row gap-4 flex-1">
                  {/* Search */}
                  <div className="relative flex-1 max-w-md">
                    <span className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-400">
                      🔍
                    </span>
                    <input
                      type="text"
                      placeholder="Search violations..."
                      value={searchTerm}
                      onChange={(e) => {
                        setSearchTerm(e.target.value);
                        setCurrentPage(1);
                      }}
                      className="w-full pl-10 pr-4 py-2 bg-slate-800 border border-slate-700 rounded-lg text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-all"
                    />
                  </div>

                  {/* Category Filter */}
                  <select
                    value={categoryFilter}
                    onChange={(e) => {
                      setCategoryFilter(e.target.value);
                      setCurrentPage(1);
                    }}
                    className="px-4 py-2 bg-slate-800 border border-slate-700 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-blue-500 transition-all"
                  >
                    <option value="">All Categories</option>
                    {Array.from(new Set(selectedReport.violations.map(v => v.violatedRule.category))).map(cat => (
                      <option key={cat} value={cat}>{cat}</option>
                    ))}
                  </select>
                </div>

                {/* Stats Summary */}
                <div className="flex items-center gap-4 text-sm text-slate-400">
                  <span>
                    Total: <strong className="text-white">{selectedReport.violationsFound}</strong>
                  </span>
                  <span>•</span>
                  <span>
                    Showing: <strong className="text-white">{totalFilteredViolations}</strong>
                  </span>
                </div>
              </div>
            </div>

            {/* Violations List */}
            <div className="flex-1 overflow-auto p-6">
              {getPaginatedViolations().length > 0 ? (
                <div className="space-y-4">
                  {getPaginatedViolations().map((violation, idx) => (
                    <div
                      key={idx}
                      className="bg-slate-800/50 border border-slate-700 rounded-xl p-4 hover:border-slate-600 transition-colors"
                    >
                      <div className="flex items-start justify-between gap-4 mb-2">
                        <div className="flex items-center gap-3">
                          <span className={`px-3 py-1 rounded-full text-xs font-semibold text-white ${getCategoryColor(violation.violatedRule.category)}`}>
                            {violation.violatedRule.category}
                          </span>
                          <h3 className="font-semibold text-white">
                            {violation.violatedRule.name}
                          </h3>
                        </div>
                        <span className="text-sm font-mono text-slate-400 bg-slate-900 px-2 py-1 rounded border border-slate-800">
                          Line {violation.lineNumber}
                        </span>
                      </div>
                      
                      <p className="text-slate-300 text-sm mb-3">
                        {violation.violatedRule.description}
                      </p>

                      <div className="bg-slate-950 rounded-lg p-3 border border-slate-800 overflow-x-auto">
                        <div className="flex items-center gap-2 mb-2 text-xs text-slate-500 border-b border-slate-800 pb-2">
                          <span className="font-mono">{violation.filePath}</span>
                        </div>
                        <code className="text-sm font-mono text-red-300 block whitespace-pre-wrap">
                          {violation.matchedText}
                        </code>
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="flex flex-col items-center justify-center h-full text-slate-500">
                  <span className="text-4xl mb-2">🔍</span>
                  <p>No violations found matching your filters</p>
                </div>
              )}
            </div>

            {/* Pagination Footer */}
            {totalPages > 1 && (
              <div className="p-4 border-t border-slate-800 bg-slate-800/30 flex justify-center gap-2">
                <button
                  onClick={() => setCurrentPage(p => Math.max(1, p - 1))}
                  disabled={currentPage === 1}
                  className="px-3 py-1 rounded-lg border border-slate-700 text-slate-300 disabled:opacity-50 hover:bg-slate-700 transition-colors"
                >
                  Previous
                </button>
                <span className="px-3 py-1 text-slate-400">
                  Page {currentPage} of {totalPages}
                </span>
                <button
                  onClick={() => setCurrentPage(p => Math.min(totalPages, p + 1))}
                  disabled={currentPage === totalPages}
                  className="px-3 py-1 rounded-lg border border-slate-700 text-slate-300 disabled:opacity-50 hover:bg-slate-700 transition-colors"
                >
                  Next
                </button>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
