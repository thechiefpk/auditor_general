import React, { useEffect, useMemo, useState } from 'react';
import { useLocation, Link } from 'react-router-dom';
import Card from '../components/ui/Card';
import { Button, Input } from '../components/ui';
import Badge from '../components/ui/Badge';
import Modal from '../components/ui/Modal';
import { useToast } from '../components/ToastProvider';

export default function ResultsPage() {
    const location = useLocation();
    const toast = useToast();
    const [summary, setSummary] = useState(location.state?.summary || window.history.state?.summary || null);
    const [filter, setFilter] = useState('all');
    const [query, setQuery] = useState('');
    const [sort, setSort] = useState({ key: 'filePath', dir: 'asc' });
    const [modalOpen, setModalOpen] = useState(false);
    const [modalContent, setModalContent] = useState('');
    const [page, setPage] = useState(1);
    const [pageSize, setPageSize] = useState(10);

    useEffect(() => {
        if (!summary) {
            const s = sessionStorage.getItem('lastSummary');
            if (s) setSummary(JSON.parse(s));
        }
    }, [])

    useEffect(() => { if (summary) { sessionStorage.setItem('lastSummary', JSON.stringify(summary)); } }, [summary]);

    // keyboard shortcut: press '/' to focus search input (if not typing in an input)
    useEffect(() => {
        const onKey = (e) => {
            if (e.key === '/' && (document.activeElement?.tagName || '').toLowerCase() !== 'input' && (document.activeElement?.tagName || '').toLowerCase() !== 'textarea') {
                e.preventDefault();
                const el = document.getElementById('results-search');
                if (el) el.focus();
            }
        };
        window.addEventListener('keydown', onKey);
        return () => window.removeEventListener('keydown', onKey);
    }, []);

    if (!summary) return <div>No results available. Run a scan first.</div>

    const violations = summary.violations || [];

    const filtered = useMemo(() => {
        let list = violations.slice();
        if (filter !== 'all') {
            list = list.filter(v => (v.category || v.ruleCategory || '').toLowerCase() === filter.toLowerCase());
        }
        if (query) {
            const q = query.toLowerCase();
            list = list.filter(v => (v.filePath || '').toLowerCase().includes(q) || (v.ruleName || v.violatedRule?.name || '').toLowerCase().includes(q) || (v.lineContent || v.matchedText || '').toLowerCase().includes(q));
        }
        list.sort((a, b) => {
            const va = (a[sort.key] ?? '').toString();
            const vb = (b[sort.key] ?? '').toString();
            if (va < vb) return sort.dir === 'asc' ? -1 : 1;
            if (va > vb) return sort.dir === 'asc' ? 1 : -1;
            return 0;
        });
        return list;
    }, [violations, filter, query, sort]);

    useEffect(() => { setPage(1); }, [filter, query, sort, pageSize]);

    const total = filtered.length;
    const pages = Math.max(1, Math.ceil(total / pageSize));
    const paginated = filtered.slice((page - 1) * pageSize, page * pageSize);

    const exportCsv = () => {
        try {
            const csv = ['File,Line,Rule,Matched', ...(violations || []).map(v => `"${v.filePath}","${v.lineNumber}","${(v.ruleName || v.violatedRule?.name || '')}","${(v.lineContent || v.matchedText || '').replace(/"/g, '""')}"`)].join('\n');
            const blob = new Blob([csv], { type: 'text/csv' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url; a.download = 'scan-results.csv'; a.click(); URL.revokeObjectURL(url);
            toast.push('CSV exported', 'success');
        } catch (e) { console.error(e); toast.push('Export failed', 'error'); }
    }

    const exportJson = () => {
        try {
            const blob = new Blob([JSON.stringify({ summary, exportedAt: new Date().toISOString() }, null, 2)], { type: 'application/json' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url; a.download = 'scan-results.json'; a.click(); URL.revokeObjectURL(url);
            toast.push('JSON exported', 'success');
        } catch (e) { console.error(e); toast.push('Export failed', 'error'); }
    }

    const openSnippet = (text) => {
        setModalContent(text);
        setModalOpen(true);
    }

    const copySnippet = async (text) => {
        try {
            await navigator.clipboard.writeText(text || '');
            toast.push('Snippet copied to clipboard', 'success');
        } catch (e) {
            toast.push('Failed to copy', 'error');
        }
    }

    const toggleSort = (key) => {
        setSort(s => ({ key, dir: s.key === key ? (s.dir === 'asc' ? 'desc' : 'asc') : 'asc' }));
    }

    const categories = Array.from(new Set((violations || []).map(v => (v.category || v.ruleCategory || '').toLowerCase()).filter(Boolean)));

    return (
        <div>
            <h2 className="text-2xl font-bold mb-4">Scan Results</h2>
            <div className="grid grid-cols-3 gap-4 mb-4">
                <Card><div>Files scanned<br /><div className="text-2xl font-semibold">{summary.filesScanned}</div></div></Card>
                <Card><div>Violations<br /><div className="text-2xl font-semibold">{summary.violationsFound}</div></div></Card>
                <Card><div>Report ID<br /><div className="text-2xl font-semibold">{summary.reportId || 'n/a'}</div></div></Card>
            </div>

            <div className="flex items-center gap-2 mb-4">
                <label className="text-sm mr-2">Filter:</label>
                <select value={filter} onChange={e => setFilter(e.target.value)} className="border p-2 rounded" aria-label="Filter violations by category">
                    <option value="all">All</option>
                    {categories.map(c => <option key={c} value={c}>{c}</option>)}
                </select>

                <div className="ml-4 w-1/3">
                    <Input id="results-search" placeholder="Search file, rule or snippet..." value={query} onChange={e => setQuery(e.target.value)} aria-label="Search violations" />
                </div>

                <div className="ml-2 flex gap-2">
                    <Button variant="secondary" onClick={exportCsv}>Export CSV</Button>
                    <Button variant="secondary" onClick={exportJson}>Export JSON</Button>
                </div>
            </div>

            <div className="flex items-center justify-between mb-2">
                <div className="text-sm text-gray-600">Showing {Math.min(total, (page - 1) * pageSize + 1)} - {Math.min(page * pageSize, total)} of {total}</div>
                <div className="flex items-center gap-2">
                    <label className="text-sm">Per page</label>
                    <select value={pageSize} onChange={e => setPageSize(Number(e.target.value))} className="border p-1 rounded" aria-label="Results per page">
                        <option value={5}>5</option>
                        <option value={10}>10</option>
                        <option value={25}>25</option>
                    </select>
                </div>
            </div>

            <Card>
                <h3 className="font-semibold mb-2">Violations</h3>
                <div className="overflow-auto">
                    <table className="w-full table-auto border-collapse" role="table" aria-label="Violations table">
                        <thead>
                            <tr className="text-left">
                                <th scope="col" onClick={() => toggleSort('filePath')} className="cursor-pointer" role="columnheader" aria-sort={sort.key === 'filePath' ? (sort.dir === 'asc' ? 'ascending' : 'descending') : 'none'}>File</th>
                                <th scope="col" onClick={() => toggleSort('lineNumber')} className="cursor-pointer" role="columnheader" aria-sort={sort.key === 'lineNumber' ? (sort.dir === 'asc' ? 'ascending' : 'descending') : 'none'}>Line</th>
                                <th scope="col" onClick={() => toggleSort('ruleName')} className="cursor-pointer" role="columnheader" aria-sort={sort.key === 'ruleName' ? (sort.dir === 'asc' ? 'ascending' : 'descending') : 'none'}>Rule</th>
                                <th scope="col">Matched</th>
                                <th scope="col" aria-hidden="true"></th>
                            </tr>
                        </thead>
                        <tbody>
                            {paginated.length === 0 && (
                                <tr role="row"><td colSpan={5} className="p-4 text-center text-gray-600">No matching violations.</td></tr>
                            )}
                            {paginated.map((v, i) => (
                                <tr key={i} className="border-t align-top" role="row">
                                    <td className="align-top break-all" role="cell">{v.filePath}</td>
                                    <td className="align-top" role="cell">{v.lineNumber}</td>
                                    <td className="align-top" role="cell">{v.ruleName || (v.violatedRule && v.violatedRule.name)}</td>
                                    <td className="align-top" role="cell"><pre className="whitespace-pre-wrap">{v.lineContent || v.matchedText}</pre></td>
                                    <td className="align-top text-right" role="cell">
                                        <div className="flex items-center gap-2">
                                            <button onClick={() => openSnippet(v.matchedText || v.lineContent)} className="text-indigo-600">View</button>
                                            <button onClick={() => copySnippet(v.matchedText || v.lineContent)} className="text-gray-600">Copy</button>
                                        </div>
                                    </td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
            </Card>

            <div className="flex items-center justify-between mt-3">
                <div>
                    <Button variant="ghost" onClick={() => setPage(p => Math.max(1, p - 1))} disabled={page <= 1}>Previous</Button>
                    <Button variant="ghost" onClick={() => setPage(p => Math.min(pages, p + 1))} disabled={page >= pages}>Next</Button>
                </div>
                <div className="text-sm text-gray-600">Page {page} of {pages}</div>
            </div>

            <Modal open={modalOpen} onClose={() => setModalOpen(false)} title="Snippet">
                <div className="mb-2 flex justify-end">
                    <button onClick={() => copySnippet(modalContent)} className="text-sm text-indigo-600">Copy</button>
                </div>
                <pre className="whitespace-pre-wrap">{modalContent}</pre>
            </Modal>
        </div>
    )
}
