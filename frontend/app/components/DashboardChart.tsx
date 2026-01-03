'use client';

import { useEffect, useState } from 'react';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend, Label } from 'recharts';
import { API_ENDPOINTS, createAuthHeaders } from '@/app/lib/api';
import { useAuth } from '@/app/context/AuthContext';

export interface DailyStat {
    date: string;
    scanCount: number;
    violationCount: number;
    dollarsSaved: number;
}

interface DashboardChartProps {
    onDataPointClick?: (data: DailyStat) => void;
}

export default function DashboardChart({ onDataPointClick }: DashboardChartProps) {
    const { user } = useAuth();
    const [data, setData] = useState<DailyStat[]>([]);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        if (!user) return;
        const fetchData = async () => {
            try {
                const res = await fetch(API_ENDPOINTS.STATS_DAILY, {
                    headers: createAuthHeaders(user.token),
                });
                if (res.ok) {
                    const json: DailyStat[] = await res.json();
                    
                    if (json.length > 0) {
                        // Fill in missing dates from first scan to today
                        const sorted = [...json].sort((a, b) => new Date(a.date).getTime() - new Date(b.date).getTime());
                        const start = new Date(sorted[0].date);
                        const end = new Date();
                        const filled: DailyStat[] = [];
                        
                        // Normalize dates to YYYY-MM-DD for comparison
                        const formatDate = (d: Date) => d.toISOString().split('T')[0];
                        
                        for (let d = new Date(start); d <= end; d.setDate(d.getDate() + 1)) {
                            const dateStr = formatDate(d);
                            // Check if date exists in sorted data (handling potential time component mismatch)
                            const existing = sorted.find(s => s.date.startsWith(dateStr));
                            if (existing) {
                                filled.push(existing);
                            } else {
                                filled.push({ date: dateStr, scanCount: 0, violationCount: 0, dollarsSaved: 0 });
                            }
                        }
                        setData(filled);
                    } else {
                        setData([]);
                    }
                }
            } catch (e) {
                console.error(e);
            } finally {
                setLoading(false);
            }
        };
        fetchData();
    }, [user]);

    if (loading) {
        return (
            <div className="w-full h-[300px] flex items-center justify-center bg-zinc-900/50 border border-zinc-800 rounded-xl">
                <div className="h-8 w-8 animate-spin rounded-full border-2 border-white border-t-transparent"></div>
            </div>
        );
    }

    if (data.length === 0) {
        return (
            <div className="w-full h-[300px] flex items-center justify-center bg-zinc-900/50 border border-zinc-800 rounded-xl">
                <p className="text-zinc-500">No data available for chart. Run a scan to see trends.</p>
            </div>
        );
    }

    return (
        <div className="w-full bg-zinc-900/50 border border-zinc-800 rounded-xl p-6 shadow-xl backdrop-blur-sm">
            <h3 className="text-lg font-semibold text-white mb-6">Security & Compliance Trends</h3>
            <div className="h-[350px] w-full">
                <ResponsiveContainer width="100%" height="100%">
                    <LineChart 
                        data={data}
                        onClick={(e: any) => {
                            if (e && e.activePayload && e.activePayload.length > 0) {
                                onDataPointClick?.(e.activePayload[0].payload as DailyStat);
                            }
                        }}
                        style={{ cursor: 'pointer' }}
                    >
                        <CartesianGrid strokeDasharray="3 3" stroke="#27272a" vertical={false} />
                        <XAxis 
                            dataKey="date" 
                            stroke="#71717a" 
                            tick={{fill: '#71717a'}}
                            tickLine={false}
                            axisLine={false}
                            tickFormatter={(value) => new Date(value).toLocaleDateString(undefined, {month:'short', day:'numeric'})}
                        >
                            <Label value="Timeline" offset={-5} position="insideBottom" fill="#71717a" style={{ fontSize: '12px' }} />
                        </XAxis>
                        <YAxis 
                            yAxisId="left"
                            stroke="#71717a" 
                            tick={{fill: '#71717a'}}
                            tickLine={false}
                            axisLine={false}
                            label={{ value: 'Scans Performed', angle: -90, position: 'insideLeft', fill: '#71717a', style: { textAnchor: 'middle' } }}
                        />
                        <YAxis 
                            yAxisId="right" 
                            orientation="right" 
                            stroke="#71717a" 
                            tick={{fill: '#71717a'}}
                            tickLine={false}
                            axisLine={false}
                            label={{ value: 'Violations Found', angle: 90, position: 'insideRight', fill: '#71717a', style: { textAnchor: 'middle' } }}
                        />
                        <YAxis 
                            yAxisId="cost" 
                            orientation="right" 
                            hide
                        />
                        <Tooltip 
                            contentStyle={{ backgroundColor: '#18181b', borderColor: '#27272a', color: '#fff' }}
                            itemStyle={{ color: '#fff' }}
                            labelStyle={{ color: '#a1a1aa' }}
                            formatter={(value: any, name: any) => {
                                if (name === 'Cost Saved') return [`$${value.toLocaleString()}`, name];
                                return [value, name];
                            }}
                        />
                        <Legend />
                        <Line 
                            yAxisId="left"
                            type="monotone" 
                            dataKey="scanCount" 
                            name="Scans"
                            stroke="#3b82f6" 
                            strokeWidth={3}
                            dot={{ fill: '#3b82f6', r: 4 }}
                            activeDot={{ r: 6 }}
                        />
                        <Line 
                            yAxisId="right"
                            type="monotone" 
                            dataKey="violationCount" 
                            name="Violations"
                            stroke="#ef4444" 
                            strokeWidth={3}
                            dot={{ fill: '#ef4444', r: 4 }}
                            activeDot={{ r: 6 }}
                        />
                        <Line 
                            yAxisId="cost"
                            type="monotone" 
                            dataKey="dollarsSaved" 
                            name="Cost Saved"
                            stroke="#10b981" 
                            strokeWidth={3}
                            strokeDasharray="5 5"
                            dot={{ fill: '#10b981', r: 4 }}
                            activeDot={{ r: 6 }}
                        />
                    </LineChart>
                </ResponsiveContainer>
            </div>
        </div>
    );
}
