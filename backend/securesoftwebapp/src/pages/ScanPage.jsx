import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import api from '../services/api';
import { Button } from '../components/ui';
import Input from '../components/ui/Input';
import { useToast } from '../components/ToastProvider';

export default function ScanPage() {
    const [path, setPath] = useState('');
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState(null);
    const navigate = useNavigate();
    const toast = useToast();

    useEffect(() => {
        const last = localStorage.getItem('lastPath');
        if (last) setPath(last);
    }, []);

    const startScan = async () => {
        setError(null);
        setLoading(true);
        try {
            const body = typeof path === 'string' ? { path } : path;
            const res = await api.scanJson(body);
            localStorage.setItem('lastPath', body.path || path);
            if (res?.reportId) {
                try {
                    const stored = JSON.parse(localStorage.getItem('savedReports') || '[]');
                    stored.unshift({ reportId: res.reportId, path: body.path, filesScanned: res.filesScanned, violationsFound: res.violationsFound, timestamp: new Date().toISOString() });
                    localStorage.setItem('savedReports', JSON.stringify(stored.slice(0, 50)));
                } catch { }
            }
            navigate('/results', { state: { summary: res } });
            toast.push('Scan completed', 'success');
        } catch (e) {
            setError(e.message || 'Scan failed');
            toast.push(e.message || 'Scan failed', 'error');
        } finally { setLoading(false); }
    }

    return (
        <div className="max-w-3xl mx-auto">
            <h2 className="text-2xl font-bold mb-4">Start a Scan</h2>
            <div className="mb-4">
                <label className="block mb-1">Repository / Path</label>
                <Input value={path} onChange={e => setPath(e.target.value)} placeholder="C:\\Users\\... or /home/user/project" />
                <p className="text-xs text-gray-500 mt-1">Path is normalized on the server. Ensure the API has access to the filesystem path.</p>
            </div>
            <div className="flex items-center gap-2">
                <Button variant="primary" onClick={startScan} disabled={loading}>{loading ? 'Scanning...' : 'Start Scan'}</Button>
                {error && <div className="text-red-600">{error}</div>}
            </div>
        </div>
    )
}
