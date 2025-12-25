'use client';

import { useEffect, useState } from 'react';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend } from 'recharts';
import { API_ENDPOINTS, createAuthHeaders } from '@/app/lib/api';
import { useAuth } from '@/app/context/AuthContext';

interface DailyStat {
    date: string;
    scanCount: number;
    violationCount: number;
    dollarsSaved: number;
}

export default function DashboardChart() {
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
                    const json = await res.json();
                    setData(json);
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
                    <LineChart data={data}>
                        <CartesianGrid strokeDasharray="3 3" stroke="#27272a" vertical={false} />
                        <XAxis 
                            dataKey="date" 
                            stroke="#71717a" 
                            tick={{fill: '#71717a'}}
                            tickLine={false}
                            axisLine={false}
                            tickFormatter={(value) => new Date(value).toLocaleDateString(undefined, {month:'short', day:'numeric'})}
                        />
                        <YAxis 
                            yAxisId="left"
                            stroke="#71717a" 
                            tick={{fill: '#71717a'}}
                            tickLine={false}
                            axisLine={false}
                        />
                        <YAxis 
                            yAxisId="right" 
                            orientation="right" 
                            stroke="#71717a" 
                            tick={{fill: '#71717a'}}
                            tickLine={false}
                            axisLine={false}
                            tickFormatter={(val) => `$${val}`}
                        />
                        <Tooltip 
                            contentStyle={{ backgroundColor: '#18181b', borderColor: '#27272a', color: '#fff' }}
                            itemStyle={{ color: '#fff' }}
                            labelStyle={{ color: '#a1a1aa' }}
                            formatter={(value: any, name: any) => {
                                if (name === 'Cost Saved') return [`$${value}`, name];
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
                            strokeWidth={2}
                            dot={{ fill: '#3b82f6', r: 4 }}
                            activeDot={{ r: 6 }}
                        />
                        <Line 
                            yAxisId="left"
                            type="monotone" 
                            dataKey="violationCount" 
                            name="Violations"
                            stroke="#ef4444" 
                            strokeWidth={2}
                            dot={{ fill: '#ef4444', r: 4 }}
                            activeDot={{ r: 6 }}
                        />
                        <Line 
                            yAxisId="right"
                            type="monotone" 
                            dataKey="dollarsSaved" 
                            name="Cost Saved"
                            stroke="#10b981" 
                            strokeWidth={2}
                            dot={{ fill: '#10b981', r: 4 }}
                            activeDot={{ r: 6 }}
                        />
                    </LineChart>
                </ResponsiveContainer>
            </div>
        </div>
    );
}