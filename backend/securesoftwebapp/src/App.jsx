import React from 'react';
import { Routes, Route, Link } from 'react-router-dom';
import HomePage from './pages/HomePage';
import ScanPage from './pages/ScanPage';
import ResultsPage from './pages/ResultsPage';
import StatsPage from './pages/StatsPage';
import HistoryPage from './pages/HistoryPage';
import ReportDetails from './pages/ReportDetails';
import LoginPage from './pages/LoginPage';
import RegisterPage from './pages/RegisterPage';
import { useAuth } from './components/AuthProvider';
import ProtectedRoute from './components/ProtectedRoute';
import './App.css'

function App() {
    const auth = useAuth();
    return (
        <div className="min-h-screen bg-gray-50">
            <a href="#main" className="sr-only focus:not-sr-only p-2 bg-white">Skip to content</a>
            <header className="bg-white shadow p-4">
                <div className="container mx-auto flex justify-between items-center">
                    <div className="flex items-center gap-4">
                        <h1 className="text-xl font-semibold">SecureSoft</h1>
                        <nav className="space-x-4 text-sm">
                            <Link to="/" className="text-gray-600 hover:text-gray-900">Home</Link>
                            <Link to="/scan" className="text-gray-600 hover:text-gray-900">Scan</Link>
                            <Link to="/results" className="text-gray-600 hover:text-gray-900">Results</Link>
                            <Link to="/history" className="text-gray-600 hover:text-gray-900">History</Link>
                        </nav>
                    </div>
                    <div>
                        {auth?.user ? (
                            <div className="flex items-center gap-4">
                                <span className="text-sm">{auth.user.username}</span>
                                <button onClick={() => auth.logout()} className="text-sm text-indigo-600">Logout</button>
                            </div>
                        ) : (
                            <nav className="space-x-4 text-sm">
                                <Link to="/login" className="text-gray-600 hover:text-gray-900">Login</Link>
                                <Link to="/register" className="text-gray-600 hover:text-gray-900">Register</Link>
                            </nav>
                        )}
                    </div>
                </div>
            </header>
            <main id="main" className="container mx-auto p-4">
                <Routes>
                    <Route path="/" element={<HomePage />} />
                    <Route path="/scan" element={<ProtectedRoute><ScanPage /></ProtectedRoute>} />
                    <Route path="/results" element={<ResultsPage />} />
                    <Route path="/stats/:id" element={<ProtectedRoute><StatsPage /></ProtectedRoute>} />
                    <Route path="/history" element={<ProtectedRoute><HistoryPage /></ProtectedRoute>} />
                    <Route path="/report/:id" element={<ProtectedRoute><ReportDetails /></ProtectedRoute>} />
                    <Route path="/login" element={<LoginPage />} />
                    <Route path="/register" element={<RegisterPage />} />
                </Routes>
            </main>
        </div>
    )
}

export default App
