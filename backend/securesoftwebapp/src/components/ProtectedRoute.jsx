import React from 'react';
import { Navigate, useLocation } from 'react-router-dom';
import { useAuth } from './AuthProvider';

export default function ProtectedRoute({ children }) {
    const auth = useAuth();
    const loc = useLocation();

    if (!auth?.user) {
        // redirect to login, preserve where we came from
        return <Navigate to="/login" state={{ from: loc.pathname }} replace />;
    }

    return children;
}
