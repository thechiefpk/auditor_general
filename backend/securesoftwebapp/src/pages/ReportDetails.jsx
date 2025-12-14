import React, { useEffect, useState } from 'react';
import { useParams } from 'react-router-dom';
import api from '../services/api';
import Modal from '../components/ui/Modal';
import Card from '../components/ui/Card';
import { useToast } from '../components/ToastProvider';

export default function ReportDetails() {
    const { id } = useParams();
    const toast = useToast();
    const [report, setReport] = useState(null);
    const [loadingReport, setLoadingReport] = useState(true);
    const [errorReport, setErrorReport] = useState(null);

    // paginated violations
    const [violationsPaged, setViolationsPaged] = useState({ total: 0, items: [] });
    const [page, setPage] = useState(1);
    const [pageSize, setPageSize] = useState(25);
    const [loadingPage, setLoadingPage] = useState(false);
    const [errorPage, setErrorPage] = useState(null);

    const [modalOpen, setModalOpen] = useState(false);
    const [modalContent, setModalContent] = useState('');

    useEffect(() => {
        if (!id) { setErrorReport('Missing id'); setLoadingReport(false); return; }
        setLoadingReport(true);
        api.getReport(id).then(r => { setReport(r); setLoadingReport(false); }).catch(e => { setErrorReport(e.message || String(e)); setLoadingReport(false); toast.push(e.message || 'Failed to load report', 'error'); });
    }, [id]);

    useEffect(() => {
        if (!id) return;
        setLoadingPage(true);
        setErrorPage(null);
        api.getReportViolations(id, page, pageSize).then(p => { setViolationsPaged(p); setLoadingPage(false); }).catch(e => { setErrorPage(e.message || String(e)); setLoadingPage(false); toast.push(e.message || 'Failed to load violations', 'error'); });
    }, [id, page, pageSize]);

    if (loadingReport) return <div>Loading report...</div>;
    if (errorReport) return <div className="text-red-600">{errorReport}</div>;
    if (!report) return <div>No report found.</div>;

    const openSnippet = (text) => {
        setModalContent(text);
        setModalOpen(true);
    }

    const copySnippet = async (text) => {
        try { await navigator.clipboard.writeText(text || ''); toast.push('Snippet copied', 'success'); } catch { toast.push('Failed to copy', 'error'); }
    }

    const total = violationsPaged?.total || 0;
    const pages = Math.max(1, Math.ceil(total / pageSize));

    return (
        <div className="max-w-4xl mx-auto">
            <h2 className="text-2xl font-bold mb-4">Report Details</h2>
            <Card className="mb-4" ariaLabel="Report summary">
                <div className="grid grid-cols-3 gap-4">
                    <div>
                        <div className="text-sm text-gray-500">Files scanned</div>
                        <div className="font-semibold">{report.filesScanned}</div>
                    </div>
                    <div>
                        <div className="text-sm text-gray-500">Violations</div>
                        <div className="font-semibold">{report.violationsFound}</div>
                    </div>
                    <div>
                        <div className="text-sm text-gray-500">Report ID</div>
                        <div className="font-semibold break-all">{id}</div>
                    </div>
                </div>
            </Card>

            <Card>
                <h3 className="font-semibold mb-2">Violations</h3>
                {loadingPage ? (
                    <div className="p-4">Loading violations...</div>
                ) : errorPage ? (
                    <div className="p-4 text-red-600">{errorPage}</div>
                ) : (
                    <>
                        <div className="overflow-auto">
                            <table className="w-full table-auto">
                                <thead><tr className="text-left"><th>File</th><th>Line</th><th>Rule</th><th>Matched</th><th></th></tr></thead>
                                <tbody>
                                    {violationsPaged.items.map((v, i) => (
                                        <tr key={i} className="border-t"><td className="break-all">{v.filePath}</td><td>{v.lineNumber}</td><td>{v.violatedRule?.name || v.ruleName}</td><td><pre className="whitespace-pre-wrap">{v.matchedText || v.lineContent}</pre></td><td className="text-right"><button onClick={() => openSnippet(v.matchedText || v.lineContent)} className="text-indigo-600">View</button></td></tr>
                                    ))}
                                </tbody>
                            </table>
                        </div>

                        <div className="flex items-center justify-between mt-3">
                            <div className="flex items-center gap-2">
                                <label className="text-sm">Per page</label>
                                <select value={pageSize} onChange={e => { setPageSize(Number(e.target.value)); setPage(1); }} className="border p-1 rounded">
                                    <option value={10}>10</option>
                                    <option value={25}>25</option>
                                    <option value={50}>50</option>
                                </select>
                            </div>
                            <div className="flex items-center gap-2">
                                <button onClick={() => setPage(p => Math.max(1, p - 1))} disabled={page <= 1} className="py-1 px-2 rounded border">Previous</button>
                                <div className="text-sm text-gray-600">Page {page} of {pages}</div>
                                <button onClick={() => setPage(p => Math.min(pages, p + 1))} disabled={page >= pages} className="py-1 px-2 rounded border">Next</button>
                            </div>
                        </div>
                    </>
                )}
            </Card>

            <Modal open={modalOpen} onClose={() => setModalOpen(false)} title="File Snippet">
                <div className="mb-2 flex justify-end">
                    <button onClick={() => copySnippet(modalContent)} className="text-sm text-indigo-600">Copy</button>
                </div>
                <pre className="whitespace-pre-wrap">{modalContent}</pre>
            </Modal>
        </div>
    )
}
