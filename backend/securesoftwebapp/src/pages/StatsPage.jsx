import React, { useEffect, useState } from 'react';
import { useParams } from 'react-router-dom';
import api from '../services/api';
import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer, Legend, BarChart, Bar, XAxis, YAxis, CartesianGrid } from 'recharts';
import useFetch from '../hooks/useFetch';
import Card from '../components/ui/Card';
import { Button } from '../components/ui';
import { useToast } from '../components/ToastProvider';

const COLORS = ['#4F46E5', '#06B6D4', '#F97316', '#EF4444', '#10B981', '#8B5CF6'];

export default function StatsPage() {
    const { id } = useParams();
    const toast = useToast();
    const { data: stats, loading, error, reload } = useFetch(() => api.getStats(id), [id]);
    const [topFiles, setTopFiles] = useState([]);
    const [loadingTop, setLoadingTop] = useState(false);
    const [errorTop, setErrorTop] = useState(null);

    useEffect(() => {
        if (!id) return;
        setLoadingTop(true);
        setErrorTop(null);
        api.getTopFiles(id, 10).then(data => { setTopFiles(data || []); setLoadingTop(false); }).catch(err => { setErrorTop(err.message || String(err)); setLoadingTop(false); toast.push(err.message || 'Failed to load top files', 'error'); });
    }, [id]);

    if (!id) return <div className="text-red-600">Missing report id</div>;

    if (loading) return (
        <div className="max-w-4xl mx-auto">
            <h2 className="text-2xl font-bold mb-4">Report Statistics</h2>
            <div className="grid grid-cols-2 gap-4">
                <Card className="h-64 flex items-center justify-center">Loading charts...</Card>
                <Card className="h-64 flex items-center justify-center">Loading charts...</Card>
            </div>
        </div>
    );

    if (error) {
        toast.push(error.message || String(error), 'error');
        return (
            <div className="max-w-4xl mx-auto">
                <h2 className="text-2xl font-bold mb-4">Report Statistics</h2>
                <div className="bg-white rounded shadow p-4 mb-4">
                    <div className="grid grid-cols-3 gap-4">
                        <div>
                            <div className="text-sm text-gray-500">Report ID</div>
                            <div className="font-semibold break-all">{id}</div>
                        </div>
                        <div>
                            <div className="text-sm text-gray-500">Files scanned</div>
                            <div className="font-semibold">-</div>
                        </div>
                        <div>
                            <div className="text-sm text-gray-500">Violations found</div>
                            <div className="font-semibold">-</div>
                        </div>
                    </div>
                </div>
                <div className="flex gap-2">
                    <Button variant="primary" onClick={reload}>Retry</Button>
                </div>
            </div>
        );
    }

    if (!stats) return <div>No statistics available.</div>;

    const pieData = Object.entries(stats.violationsByCategory || {}).map(([key, value]) => ({ name: key, value }));
    const barData = pieData.map(d => ({ name: d.name, value: d.value }));

    // files vs violations: aggregate violations per file (stats.filesByFile expected or compute from stats.violations)
    let filesViolations = [];
    if (stats.files && Array.isArray(stats.files)) {
        // if server provided files list with violation counts
        filesViolations = stats.files.map(f => ({ name: f.filePath || f.name, violations: f.violations || 0 }));
    } else if (stats.violations && Array.isArray(stats.violations)) {
        const map = {};
        stats.violations.forEach(v => { const key = v.filePath || 'unknown'; map[key] = (map[key] || 0) + 1; });
        filesViolations = Object.entries(map).map(([k, v]) => ({ name: k, violations: v }));
    } else {
        // fallback empty
        filesViolations = [];
    }

    // compliance gauge: percent of files without violations
    const totalFiles = stats.filesScanned || (filesViolations.length || 0);
    const filesWithViolations = filesViolations.filter(f => f.violations > 0).length;
    const filesClean = Math.max(0, totalFiles - filesWithViolations);
    const compliancePercent = totalFiles > 0 ? Math.round((filesClean / totalFiles) * 100) : 0;
    const gaugeData = [
        { name: 'compliant', value: compliancePercent },
        { name: 'rest', value: 100 - compliancePercent }
    ];

    return (
        <div className="max-w-4xl mx-auto">
            <h2 className="text-2xl font-bold mb-4">Report Statistics</h2>
            <div className="bg-white rounded shadow p-4 mb-4">
                <div className="grid grid-cols-3 gap-4">
                    <div>
                        <div className="text-sm text-gray-500">Report ID</div>
                        <div className="font-semibold break-all">{stats.reportId || id}</div>
                    </div>
                    <div>
                        <div className="text-sm text-gray-500">Files scanned</div>
                        <div className="font-semibold">{stats.filesScanned ?? '-'}</div>
                    </div>
                    <div>
                        <div className="text-sm text-gray-500">Violations found</div>
                        <div className="font-semibold">{stats.violationsFound ?? '-'}</div>
                    </div>
                </div>
            </div>

            <div className="flex justify-end mb-4">
                <Button variant="secondary" onClick={reload}>Reload</Button>
            </div>

            <div className="grid grid-cols-2 gap-4">
                <Card>
                    <h3 className="font-semibold mb-2">Violations by Category</h3>
                    {pieData.length === 0 ? <div>No violations recorded.</div> : (
                        <ResponsiveContainer width="100%" height={300}>
                            <PieChart>
                                <Pie data={pieData} dataKey="value" nameKey="name" cx="50%" cy="50%" outerRadius={100} label>
                                    {pieData.map((entry, index) => (
                                        <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                                    ))}
                                </Pie>
                                <Tooltip />
                                <Legend />
                            </PieChart>
                        </ResponsiveContainer>
                    )}
                </Card>

                <Card>
                    <h3 className="font-semibold mb-2">Violations (bar)</h3>
                    {barData.length === 0 ? <div>No violations recorded.</div> : (
                        <ResponsiveContainer width="100%" height={300}>
                            <BarChart data={barData} margin={{ top: 5, right: 20, left: 0, bottom: 5 }}>
                                <CartesianGrid strokeDasharray="33" />
                                <XAxis dataKey="name" />
                                <YAxis />
                                <Tooltip />
                                <Bar dataKey="value" fill="#4F46E5" />
                            </BarChart>
                        </ResponsiveContainer>
                    )}
                </Card>
            </div>

            <div className="grid grid-cols-2 gap-4 mt-4">
                <Card>
                    <h3 className="font-semibold mb-2">Files vs Violations</h3>
                    {filesViolations.length === 0 ? <div>No file-level data available.</div> : (
                        <ResponsiveContainer width="100%" height={300}>
                            <BarChart data={filesViolations} margin={{ top: 5, right: 20, left: 0, bottom: 5 }}>
                                <CartesianGrid strokeDasharray="33" />
                                <XAxis dataKey="name" hide={filesViolations.length > 12} />
                                <YAxis />
                                <Tooltip />
                                <Bar dataKey="violations" fill="#EF4444" />
                            </BarChart>
                        </ResponsiveContainer>
                    )}
                </Card>

                <Card>
                    <h3 className="font-semibold mb-2">Compliance Gauge</h3>
                    <div className="flex items-center justify-center" style={{ height: 300 }}>
                        {totalFiles === 0 ? <div>No files scanned.</div> : (
                            <ResponsiveContainer width="50%" height={200}>
                                <PieChart>
                                    <Pie data={gaugeData} dataKey="value" startAngle={180} endAngle={0} innerRadius={60} outerRadius={100} paddingAngle={0}>
                                        <Cell key="cell-0" fill="#10B981" />
                                        <Cell key="cell-1" fill="#e6e6e6" />
                                    </Pie>
                                </PieChart>
                            </ResponsiveContainer>
                        )}
                    </div>
                    <div className="text-center mt-2">
                        <div className="text-3xl font-semibold">{compliancePercent}%</div>
                        <div className="text-sm text-gray-500">Files without violations</div>
                    </div>
                </Card>
            </div>

            <div className="mt-4">
                <Card>
                    <h3 className="font-semibold mb-2">Top files by violations</h3>
                    {loadingTop ? <div>Loading top files...</div> : errorTop ? <div className="text-red-600">{errorTop}</div> : (
                        <div>
                            {topFiles.length === 0 ? <div>No data</div> : (
                                <ol className="list-decimal list-inside">
                                    {topFiles.map((f, i) => (
                                        <li key={i} className="mb-1"><div className="flex justify-between"><span className="break-all">{f.filePath}</span><span className="font-semibold">{f.violations}</span></div></li>
                                    ))}
                                </ol>
                            )}
                        </div>
                    )}
                </Card>
            </div>
        </div>
    )
}
