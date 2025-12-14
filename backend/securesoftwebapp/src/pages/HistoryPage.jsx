import React, { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { Card, Table } from '../components/ui';

export default function HistoryPage() {
    const [saved, setSaved] = useState([]);

    useEffect(() => {
        try {
            const s = JSON.parse(localStorage.getItem('savedReports') || '[]');
            setSaved(s);
        } catch { }
    }, []);

    if (!saved || saved.length === 0) return <div>No saved reports in this browser.</div>;

    return (
        <div className="max-w-4xl mx-auto">
            <h2 className="text-2xl font-bold mb-4">Saved Reports</h2>
            <Card>
                <Table>
                    <thead><tr className="text-left"><th>When</th><th>Path</th><th>Files</th><th>Violations</th><th></th></tr></thead>
                    <tbody>
                        {saved.map((r, i) => (
                            <tr key={i} className="border-t"><td>{new Date(r.timestamp).toLocaleString()}</td><td className="break-all">{r.path}</td><td>{r.filesScanned}</td><td>{r.violationsFound}</td><td><Link to={`/report/${r.reportId}`} className="text-indigo-600">View</Link></td></tr>
                        ))}
                    </tbody>
                </Table>
            </Card>
        </div>
    )
}
