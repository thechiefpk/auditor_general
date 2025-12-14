import React, { createContext, useContext, useEffect, useState } from 'react';
import api from '../services/api';
import { useToast } from './ToastProvider';
import { useNavigate } from 'react-router-dom';

const AuthContext = createContext(null);

export function useAuth() { return useContext(AuthContext); }

function decodeJwt(token) {
    try {
        const parts = token.split('.');
        if (parts.length < 2) return null;
        const payload = parts[1].replace(/-/g, '+').replace(/_/g, '/');
        const json = decodeURIComponent(atob(payload).split('').map(c => '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2)).join(''));
        return JSON.parse(json);
    } catch { return null; }
}

export default function AuthProvider({ children }) {
    const [user, setUser] = useState(null);
    const [token, setToken] = useState(null);
    const toast = useToast();
    const nav = useNavigate();

    useEffect(() => {
        const t = localStorage.getItem('authToken');
        const r = localStorage.getItem('refreshToken');
        if (t) {
            setToken(t);
            const payload = decodeJwt(t);
            if (payload) setUser({ id: payload.sub || payload.nameid || payload['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier'], username: payload.unique_name || payload.name || payload['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name'] });
        }

        const onLogout = () => {
            localStorage.removeItem('authToken');
            localStorage.removeItem('refreshToken');
            setUser(null);
            toast.push('Session expired, please login again', 'info');
            nav('/login');
        };
        window.addEventListener('logout', onLogout);
        return () => window.removeEventListener('logout', onLogout);
    }, []);

    const saveTokens = (t, r) => {
        if (t) localStorage.setItem('authToken', t); else localStorage.removeItem('authToken');
        if (r) localStorage.setItem('refreshToken', r); else localStorage.removeItem('refreshToken');
        setToken(t);
        if (t) {
            const p = decodeJwt(t);
            if (p) setUser({ id: p.sub || p.nameid, username: p.unique_name || p.name });
        }
    };

    const login = async (username, password) => {
        const res = await api.login(username, password);
        if (res?.token) {
            saveTokens(res.token, res.refresh);
            toast.push('Logged in', 'success');
            return true;
        }
        throw new Error('Login failed');
    };

    const register = async (username, email, password) => {
        const res = await api.register(username, email, password);
        if (res?.id) {
            toast.push('Registration successful', 'success');
            return res.id;
        }
        throw new Error('Register failed');
    };

    const logout = async () => {
        const r = localStorage.getItem('refreshToken');
        if (r) { try { await api.revoke(r); } catch { } }
        saveTokens(null, null);
        setUser(null);
        toast.push('Logged out', 'success');
        nav('/login');
    };

    const refresh = async () => {
        const r = localStorage.getItem('refreshToken');
        if (!r) throw new Error('No refresh token');
        const res = await api.refresh(r);
        if (res?.token) {
            saveTokens(res.token, res.refresh);
            return true;
        }
        throw new Error('Refresh failed');
    };

    return (
        <AuthContext.Provider value={{ user, token, login, register, logout, refresh }}>
            {children}
        </AuthContext.Provider>
    );
}
