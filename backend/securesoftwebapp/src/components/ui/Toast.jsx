import React from 'react';

export default function Toast({ message, type = 'info', onClose }) {
    const bg = type === 'error' ? 'bg-red-600' : type === 'success' ? 'bg-green-600' : 'bg-gray-800';
    return (
        <div className={`text-white px-4 py-2 rounded shadow ${bg}`} role="status" aria-live="polite">
            <div className="flex items-center justify-between gap-4">
                <div>{message}</div>
                <button onClick={onClose} className="text-white opacity-80 hover:opacity-100" aria-label="Close">×</button>
            </div>
        </div>
    );
}
