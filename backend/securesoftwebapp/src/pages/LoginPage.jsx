import React, { useState } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { useAuth } from '../components/AuthProvider';
import { Button, Input } from '../components/ui';

export default function LoginPage() {
    const auth = useAuth();
    const nav = useNavigate();
    const location = useLocation();
    const [username, setUsername] = useState('');
    const [password, setPassword] = useState('');
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState(null);

    // where to redirect after login
    const from = location.state?.from || '/'

    const submit = async (e) => {
        e.preventDefault();
        setError(null); setLoading(true);
        try {
            await auth.login(username, password);
            nav(from, { replace: true });
        } catch (err) { setError(err.message || 'Login failed'); }
        finally { setLoading(false); }
    }

    return (
        <div className="max-w-md mx-auto">
            <h2 className="text-2xl font-semibold mb-4">Login</h2>
            <form onSubmit={submit} className="bg-white p-4 rounded shadow">
                <label className="block mb-2">Username</label>
                <Input value={username} onChange={e => setUsername(e.target.value)} />
                <label className="block mb-2 mt-2">Password</label>
                <Input type="password" value={password} onChange={e => setPassword(e.target.value)} />
                {error && <div className="text-red-600 mt-2">{error}</div>}
                <div className="mt-4">
                    <Button type="submit" variant="primary" disabled={loading}>{loading ? 'Signing in...' : 'Sign in'}</Button>
                </div>
            </form>
        </div>
    )
}
