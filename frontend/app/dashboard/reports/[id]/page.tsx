'use client';

import { useState, useEffect } from 'react';
import { useAuth } from '@/app/context/AuthContext';
import { API_ENDPOINTS, createAuthHeaders, apiRequest } from '@/app/lib/api';
import toast from 'react-hot-toast';
import Link from 'next/link';
import { useParams, useRouter } from 'next/navigation';

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
  engine?: string;
}

interface ScanReport {
  reportId: string;
  filesScanned: number;
  violationsFound: number;
  violations: Violation[];
  scanDate?: string;
  scanPath?: string;
}

export default function ReportDetailsPage() {
  const { user } = useAuth();
  const params = useParams();
  const router = useRouter();
  const [report, setReport] = useState<ScanReport | null>(null);
  const [loading, setLoading] = useState(true);
  
  // Pagination
  const [currentPage, setCurrentPage] = useState(1);
  const [violationsPerPage] = useState(50);
  const [searchTerm, setSearchTerm] = useState('');
  const [categoryFilter, setCategoryFilter] = useState('');

  useEffect(() => {
    if (params.id) {
      fetchReport(params.id as string);
    }
  }, [params.id]);

  const fetchReport = async (id: string) => {
    setLoading(true);
    try {
      // First try to fetch single report if endpoint exists
      // If not, we might need to fetch all and find it (fallback)
      // Based on api.ts, REPORT(id) exists
      const result = await apiRequest<ScanReport>(
        API_ENDPOINTS.REPORT(id),
        {
          method: 'GET',
          headers: createAuthHeaders(user?.token),
        }
      );

      if (result.error) {
        // Fallback: Fetch all reports and find the one we need
        // This is useful if the single report endpoint isn't working or returns different structure
        console.warn('Failed to fetch single report, trying list...');
        const listResult = await apiRequest<ScanReport[]>(
            API_ENDPOINTS.MY_REPORTS,
            {
                method: 'GET',
                headers: createAuthHeaders(user?.token),
            }
        );
        
        if (listResult.data) {
            const found = listResult.data.find(r => r.reportId === id);
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

  const handleExport = async (format: 'csv' | 'pdf') => {
    if (!report) return;
    
    const url = format === 'csv' 
        ? API_ENDPOINTS.REPORT_CSV(report.reportId)
        : API_ENDPOINTS.REPORT_PDF(report.reportId);
        
    const toastId = toast.loading(`Generating ${format.toUpperCase()} report...`);
    
    try {
        const response = await fetch(url, {
            headers: createAuthHeaders(user?.token),
        });
        
        if (!response.ok) throw new Error('Export failed');
        
        const blob = await response.blob();
        const downloadUrl = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = downloadUrl;
        a.download = `report-${report.reportId.substring(0, 8)}.${format}`;
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(downloadUrl);
        document.body.removeChild(a);
        
        toast.success(`${format.toUpperCase()} report exported`, { id: toastId });
    } catch (error) {
        toast.error('Failed to export report', { id: toastId });
    }
  };

  const getCategoryBadgeStyle = (category: string) => {
    const styles: { [key: string]: string } = {
      'GDPR': 'bg-blue-500/10 text-blue-400 border-blue-500/20 border',
      'HIPAA': 'bg-cyan-500/10 text-cyan-400 border-cyan-500/20 border',
      'Security': 'bg-red-500/10 text-red-400 border-red-500/20 border',
      'PCI-DSS': 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20 border',
      'Compliance': 'bg-amber-500/10 text-amber-400 border-amber-500/20 border',
    };
    return styles[category] || 'bg-zinc-800/50 text-zinc-300 border-zinc-700 border';
  };

  // Filter and paginate violations
  const getFilteredViolations = () => {
    if (!report || !report.violations) return [];

    let filtered = report.violations;

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

  const filteredViolations = getFilteredViolations();
  const totalFilteredViolations = filteredViolations.length;
  const totalPages = Math.ceil(totalFilteredViolations / violationsPerPage);
  
  const getPaginatedViolations = () => {
    const startIndex = (currentPage - 1) * violationsPerPage;
    const endIndex = startIndex + violationsPerPage;
    return filteredViolations.slice(startIndex, endIndex);
  };

  const currentViolations = getPaginatedViolations();

  const formatDate = (dateString?: string) => {
    if (!dateString) return 'N/A';
    return new Date(dateString).toLocaleString();
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
      {/* Breadcrumb & Header */}
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
        
        <div className="bg-zinc-900/40 backdrop-blur-sm border border-zinc-800 rounded-xl p-6 shadow-lg">
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
                <div>
                    <h1 className="text-2xl font-bold text-white flex items-center gap-3">
                        Report Details
                        <div className="flex items-center gap-2 text-sm font-normal text-zinc-400 bg-zinc-800 px-3 py-1 rounded-full border border-zinc-700">
                            <span title={report.reportId}>
                                #{report.reportId?.substring(0, 8) || 'N/A'}...
                            </span>
                            <button
                                onClick={() => copyToClipboard(report.reportId)}
                                className="hover:text-white transition-colors"
                                title="Copy Full Report ID"
                            >
                                <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
                                </svg>
                            </button>
                        </div>
                    </h1>
                    <p className="text-zinc-400 mt-1 flex items-center gap-2">
                        <span className="font-medium text-zinc-300">{report.scanPath || 'Project Scan'}</span>
                        <span>•</span>
                        <span>{formatDate(report.scanDate)}</span>
                    </p>
                </div>
                
                <div className="flex items-center gap-6 text-sm">
                    <div className="flex gap-2 mr-4">
                        <button 
                            onClick={() => handleExport('csv')}
                            className="p-2 text-zinc-400 hover:text-white bg-zinc-800 hover:bg-zinc-700 rounded-lg border border-zinc-700 transition-all"
                            title="Export CSV"
                        >
                            <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 17v-2m3 2v-4m3 4v-6m2 10H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                            </svg>
                        </button>
                        <button 
                            onClick={() => handleExport('pdf')}
                            className="p-2 text-zinc-400 hover:text-white bg-zinc-800 hover:bg-zinc-700 rounded-lg border border-zinc-700 transition-all"
                            title="Export PDF"
                        >
                            <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M7 21h10a2 2 0 002-2V9.414a1 1 0 00-.293-.707l-5.414-5.414A1 1 0 0012.586 3H7a2 2 0 00-2 2v14a2 2 0 002 2z" />
                            </svg>
                        </button>
                    </div>

                    <div className="text-center px-4 py-2 bg-zinc-800/50 rounded-lg border border-zinc-800">
                        <p className="text-zinc-500 text-xs uppercase tracking-wider mb-1">Files Scanned</p>
                        <p className="text-xl font-bold text-white">{report.filesScanned}</p>
                    </div>
                    <div className="text-center px-4 py-2 bg-zinc-800/50 rounded-lg border border-zinc-800">
                        <p className="text-zinc-500 text-xs uppercase tracking-wider mb-1">Violations</p>
                        <p className={`text-xl font-bold ${report.violationsFound > 0 ? 'text-red-400' : 'text-emerald-400'}`}>
                            {report.violationsFound}
                        </p>
                    </div>
                </div>
            </div>
        </div>
      </div>

      {/* Filters & Controls */}
      <div className="bg-zinc-900/40 backdrop-blur-sm border border-zinc-800 rounded-xl p-6 shadow-lg">
        <div className="flex flex-col md:flex-row gap-4 justify-between">
            <div className="flex flex-col md:flex-row gap-4 flex-1">
                {/* Search */}
                <div className="relative flex-1 max-w-md">
                <span className="absolute left-3 top-1/2 -translate-y-1/2 text-zinc-400">
                    <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
                    </svg>
                </span>
                <input
                    type="text"
                    placeholder="Search violations..."
                    value={searchTerm}
                    onChange={(e) => {
                    setSearchTerm(e.target.value);
                    setCurrentPage(1);
                    }}
                    className="w-full pl-10 pr-4 py-2 bg-zinc-800 border border-zinc-700 rounded-lg text-white placeholder-zinc-500 focus:outline-none focus:ring-2 focus:ring-zinc-500 focus:border-transparent transition-all"
                />
                </div>

                {/* Category Filter */}
                <select
                value={categoryFilter}
                onChange={(e) => {
                    setCategoryFilter(e.target.value);
                    setCurrentPage(1);
                }}
                className="px-4 py-2 bg-zinc-800 border border-zinc-700 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-zinc-500 transition-all"
                >
                <option value="">All Categories</option>
                {Array.from(new Set((report.violations || []).map(v => v.violatedRule.category))).map(cat => (
                    <option key={cat} value={cat}>{cat}</option>
                ))}
                </select>
            </div>

            {/* Stats Summary */}
            <div className="flex items-center gap-4 text-sm text-zinc-400 bg-zinc-800/50 px-4 py-2 rounded-lg border border-zinc-800">
                <span>
                Total: <strong className="text-white">{totalFilteredViolations}</strong>
                </span>
                <span>•</span>
                <span>
                Showing: <strong className="text-white">{currentViolations.length}</strong>
                </span>
            </div>
        </div>
      </div>

      {/* Violations List */}
      <div className="space-y-4">
        {currentViolations.length > 0 ? (
            currentViolations.map((violation, idx) => (
            <div
                key={idx}
                className="bg-zinc-900/40 backdrop-blur-sm border border-zinc-800 rounded-xl p-6 hover:border-zinc-600 transition-all shadow-md"
            >
                <div className="flex items-start justify-between gap-4 mb-4">
                <div className="flex items-center gap-3">
                    <span className={`px-3 py-1 rounded-full text-xs font-semibold ${getCategoryBadgeStyle(violation.violatedRule.category)}`}>
                    {violation.violatedRule.category}
                    </span>
                    <h3 className="font-semibold text-lg text-white">
                    {violation.violatedRule.name}
                    </h3>
                </div>
                <div className="flex items-center gap-2">
                    {violation.engine && (
                      <span className="text-xs font-medium text-emerald-300 bg-emerald-900/40 px-2 py-1 rounded-full border border-emerald-700">
                        {violation.engine}
                      </span>
                    )}
                    <span className="text-sm font-mono text-zinc-400 bg-black px-2 py-1 rounded border border-zinc-800">
                      Line {violation.lineNumber}
                    </span>
                </div>
                </div>
                
                <p className="text-zinc-300 text-sm mb-4">
                {violation.violatedRule.description}
                </p>

                <div className="bg-black rounded-lg p-4 border border-zinc-800 overflow-x-auto group">
                <div className="flex items-center gap-2 mb-2 text-xs text-zinc-500 border-b border-zinc-800 pb-2">
                    <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                    </svg>
                    <span className="font-mono">{violation.filePath}</span>
                </div>
                <code className="text-sm font-mono text-red-300 block whitespace-pre-wrap">
                    {violation.matchedText}
                </code>
                </div>
            </div>
            ))
        ) : (
            <div className="flex flex-col items-center justify-center py-20 bg-zinc-900/20 rounded-xl border border-zinc-800 border-dashed">
            <div className="text-4xl mb-4">
                <svg className="w-16 h-16 text-zinc-700" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                </svg>
            </div>
            <h3 className="text-xl font-semibold text-zinc-300 mb-2">No violations found</h3>
            <p className="text-zinc-500">Try adjusting your search or filters</p>
            </div>
        )}
      </div>

      {/* Pagination Footer */}
      {totalPages > 1 && (
        <div className="flex justify-center gap-2 mt-8">
            <button
                onClick={() => setCurrentPage(p => Math.max(1, p - 1))}
                disabled={currentPage === 1}
                className="px-4 py-2 rounded-lg border border-zinc-800 bg-zinc-900 text-zinc-300 disabled:opacity-50 hover:bg-zinc-800 hover:text-white transition-all shadow-sm"
            >
                Previous
            </button>
            <div className="flex items-center px-4 text-zinc-400 bg-zinc-900 border border-zinc-800 rounded-lg">
                Page <span className="text-white font-medium mx-1">{currentPage}</span> of <span className="text-white font-medium mx-1">{totalPages}</span>
            </div>
            <button
                onClick={() => setCurrentPage(p => Math.min(totalPages, p + 1))}
                disabled={currentPage === totalPages}
                className="px-4 py-2 rounded-lg border border-zinc-800 bg-zinc-900 text-zinc-300 disabled:opacity-50 hover:bg-zinc-800 hover:text-white transition-all shadow-sm"
            >
                Next
            </button>
        </div>
      )}
    </div>
  );
}
