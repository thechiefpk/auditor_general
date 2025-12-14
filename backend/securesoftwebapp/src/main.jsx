import React from 'react';
import { createRoot } from 'react-dom/client';
import { BrowserRouter } from 'react-router-dom';
import App from './App';
import ToastProvider from './components/ToastProvider';
import AuthProvider from './components/AuthProvider';
import './index.css';

const root = createRoot(document.getElementById('root'));
root.render(
    <React.StrictMode>
        <BrowserRouter>
            <ToastProvider>
                <AuthProvider>
                    <App />
                </AuthProvider>
            </ToastProvider>
        </BrowserRouter>
    </React.StrictMode>
);
