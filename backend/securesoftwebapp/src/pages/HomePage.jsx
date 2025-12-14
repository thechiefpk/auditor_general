import React from 'react';
import { Link } from 'react-router-dom';
import Card from '../components/ui/Card';
import { Button } from '../components/ui';

export default function HomePage() {
    return (
        <div className="max-w-4xl mx-auto">
            <section className="bg-white p-6 rounded shadow mb-6">
                <h2 className="text-2xl font-bold mb-2">Welcome to SecureSoft</h2>
                <p className="text-gray-600">Quickly scan repositories for compliance and security issues, view detailed reports, and track improvements over time.</p>
            </section>

            <section className="grid grid-cols-3 gap-4 mb-6">
                <Card>
                    <div className="flex flex-col gap-2">
                        <h3 className="font-semibold">Run a Scan</h3>
                        <p className="text-sm text-gray-500">Start a one-time scan of a repository path (JSON or raw text).</p>
                        <div className="mt-2">
                            <Link to="/scan">
                                <Button variant="primary">Start</Button>
                            </Link>
                        </div>
                    </div>
                </Card>

                <Card>
                    <div className="flex flex-col gap-2">
                        <h3 className="font-semibold">Latest Results</h3>
                        <p className="text-sm text-gray-500">View the most recent scan results and violations.</p>
                        <div className="mt-2">
                            <Link to="/results">
                                <Button variant="secondary">View</Button>
                            </Link>
                        </div>
                    </div>
                </Card>

                <Card>
                    <div className="flex flex-col gap-2">
                        <h3 className="font-semibold">Statistics</h3>
                        <p className="text-sm text-gray-500">View compliance statistics and charts (coming soon).</p>
                        <div className="mt-2">
                            <Link to="/history">
                                <Button variant="ghost">History</Button>
                            </Link>
                        </div>
                    </div>
                </Card>
            </section>

            <section className="bg-white rounded shadow p-4">
                <h3 className="font-semibold mb-2">Quick Start</h3>
                <ol className="list-decimal list-inside text-sm text-gray-700">
                    <li>Click "Run a Scan" and submit a path.</li>
                    <li>Review the results and violations.</li>
                    <li>Use the report ID to view saved statistics (if auto-saved).</li>
                </ol>
            </section>
        </div>
    )
}
